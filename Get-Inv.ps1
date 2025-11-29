# Usage: - powershell.exe -ExecutionPolicy Bypass -File .\Get-DeviceInventoryJson.ps1 -Interactive

<#
.SYNOPSIS
  Collects device inventory (must-have + nice-to-have) and exports to per-host JSON.
  For fields that cannot be fully automated, prompts the user (technician) interactively.
  Uploads the JSON file to a Discord channel via webhook and logs actions.

.PARAMETER OutputFolder
  Local folder where JSON files and logs will be stored (e.g. C:\AssetInventory).

.PARAMETER Interactive
  If set, script will prompt for manual/ownership/lifecycle fields.
#>
param(
    [string]$OutputFolder = "C:\AssetInventory",
    [switch]$Interactive
)

# ================== DISCORD WEBHOOK CONFIG ==================
$DiscordWebhookUrl = "https://discord.com/api/webhooks/1444009876027215974/_cEF1sp_VFlQTB1L8xV220r70f9ZniV77mKJtED022skWIA3DxbrleV5RvIChSLcdVvb"
$DiscordUsername = "Asset Inventory Bot"
$DiscordAvatarUrl = "https://www.freepik.com/free-ai-image/view-futuristic-music-robot-droid_94124586.htm"
# ============================================================

# -------------------------------------------------------------------
# Helper: interactive override + validation + technician
# -------------------------------------------------------------------
function Ask-Override {
    param(
        [string]$Label,
        [string]$CurrentValue
    )

    if (-not $Interactive) {
        return $CurrentValue
    }

    Write-Host ""
    Write-Host "=== $Label ===" -ForegroundColor Cyan
    if ($CurrentValue) {
        Write-Host "Current value: $CurrentValue"
    }
    else {
        Write-Host "Current value: (empty)"
    }

    $input = Read-Host "Enter new $Label (leave blank to keep current)"
    if ([string]::IsNullOrWhiteSpace($input)) {
        return $CurrentValue
    }
    return $input
}

function Ask-Status {
    param([string]$CurrentValue = "Active")

    $valid = @("Active", "Spare", "Repair", "Retired")

    while ($true) {
        $val = Ask-Override "Device Status (Active/Spare/Repair/Retired)" $CurrentValue
        if ($valid -contains $val) { return $val }
        Write-Host "Invalid status. Valid values: $($valid -join ', ')" -ForegroundColor Yellow
    }
}

function Ask-DateOptional {
    param(
        [string]$Label,
        [string]$CurrentValue
    )

    if (-not $Interactive) {
        return $CurrentValue
    }

    while ($true) {
        $val = Ask-Override $Label $CurrentValue
        if ([string]::IsNullOrWhiteSpace($val)) {
            return $val
        }
        if ($val -match '^\d{4}-\d{2}-\d{2}$') {
            return $val
        }
        Write-Host "Please use format YYYY-MM-DD or leave blank." -ForegroundColor Yellow
    }
}

function Get-Technician {
    if (-not $Interactive) {
        return $env:USERNAME
    }

    Write-Host ""
    Write-Host "=== Technician Info ===" -ForegroundColor Cyan
    $t = Read-Host "Enter your name (technician running this script)"
    if ([string]::IsNullOrWhiteSpace($t)) {
        return $env:USERNAME
    }
    return $t
}

# Ensure output folder exists
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$logFile = Join-Path $OutputFolder "inventory_log.txt"
$technician = Get-Technician

# -------------------------------------------------------------------
# Device identity
# -------------------------------------------------------------------
function Get-DeviceType {
    try {
        $enclosure = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop
        $typeCode = $enclosure.ChassisTypes | Select-Object -First 1

        switch ($typeCode) {
            3 { "Desktop" }
            4 { "Low Profile Desktop" }
            5 { "Pizza Box" }
            6 { "Mini Tower" }
            7 { "Tower" }
            8 { "Portable" }
            9 { "Laptop" }
            10 { "Notebook" }
            11 { "Hand Held" }
            12 { "Docking Station" }
            13 { "All in One" }
            14 { "Sub Notebook" }
            15 { "Space-Saving" }
            16 { "Lunch Box" }
            17 { "Main System Chassis" }
            18 { "Expansion Chassis" }
            21 { "Peripheral Chassis" }
            31 { "Tablet" }
            32 { "Convertible" }
            34 { "Stick PC" }
            Default { "Unknown ($typeCode)" }
        }
    }
    catch {
        "Unknown"
    }
}

function Get-AssetTag {
    try {
        $enclosure = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop
        if ($enclosure.SMBIOSAssetTag -and $enclosure.SMBIOSAssetTag -ne "To Be Filled By O.E.M.") {
            $enclosure.SMBIOSAssetTag
        }
        else {
            "Not Set"
        }
    }
    catch {
        "Unknown"
    }
}

function Get-SerialAndModel {
    $result = @{
        Serial = "Unknown"
        Model  = "Unknown"
    }
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $csProd = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue

        if ($csProd) {
            $result.Serial = $csProd.IdentifyingNumber
            $result.Model = $csProd.Name
        }
        elseif ($bios) {
            $result.Serial = $bios.SerialNumber
        }
        if ($cs -and $cs.Model) {
            $result.Model = $cs.Model
        }
    }
    catch {}

    return $result
}

# -------------------------------------------------------------------
# Ownership / assignment
# -------------------------------------------------------------------
function Get-LoggedOnUser {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.UserName) { return $cs.UserName }
    }
    catch {}
    return $env:USERNAME
}

# -------------------------------------------------------------------
# OS info
# -------------------------------------------------------------------
function Get-OSInfo {
    $obj = @{
        name         = "Unknown"
        version      = "Unknown"
        build        = "Unknown"
        arch         = $env:PROCESSOR_ARCHITECTURE
        install_date = $null
        last_boot    = $null
        uptime_days  = $null
        family       = "Windows"
    }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $obj.name = $os.Caption
        $obj.version = $os.Version
        $obj.build = $os.BuildNumber

        if ($os.InstallDate) {
            $obj.install_date = [Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate).ToString("s")
        }
        if ($os.LastBootUpTime) {
            $boot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
            $obj.last_boot = $boot.ToString("s")
            $obj.uptime_days = [Math]::Round((New-TimeSpan -Start $boot -End (Get-Date)).TotalDays, 1)
        }
    }
    catch {}

    return $obj
}

# -------------------------------------------------------------------
# Licensing
# -------------------------------------------------------------------
function Get-WindowsLicenseInfo {
    $info = @{
        status          = "Unknown"
        detail          = "Unknown"
        detected_expiry = $null
    }

    try {
        $lic = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction Stop |
        Where-Object { $_.Name -like "Windows*Operating System*" -and $_.PartialProductKey } |
        Select-Object -First 1

        if (-not $lic) { return $info }

        $statusText = switch ($lic.LicenseStatus) {
            0 { "Unlicensed" }
            1 { "Licensed" }
            2 { "OOB Grace" }
            3 { "OOT Grace" }
            4 { "Non-genuine Grace" }
            5 { "Notification" }
            6 { "Extended Grace" }
            default { "Unknown ($($_.LicenseStatus))" }
        }

        $info.status = $statusText

        if ($lic.TokenExpirationDate) {
            $info.detected_expiry = $lic.TokenExpirationDate
            $info.detail = "$statusText (Token expires: $($lic.TokenExpirationDate))"
        }
        elseif ($lic.GracePeriodRemaining) {
            $info.detail = "$statusText (Grace remaining: $($lic.GracePeriodRemaining) mins)"
        }
        else {
            $info.detail = $statusText
        }
    }
    catch {}

    return $info
}

# -------------------------------------------------------------------
# Security (AV, BitLocker, Firewall)
# -------------------------------------------------------------------
function Get-AntivirusInfo {
    $info = @{
        products  = @()
        summary   = "Unknown"
        av_expiry = $null
    }

    try {
        $av = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
        if (-not $av) {
            $info.summary = "No AV detected"
            return $info
        }

        $prodList = @()
        foreach ($p in $av) {
            $stateHex = '{0:X8}' -f $p.productState
            $prodList += @{
                name       = $p.displayName
                product_id = $p.instanceGuid
                state_hex  = "0x$stateHex"
            }
        }
        $info.products = $prodList
        $info.summary = ($prodList | ForEach-Object { "$($_.name) ($($_.state_hex))" }) -join "; "
    }
    catch {}

    return $info
}

function Get-BitLockerStatus {
    $result = @{
        system_drive = "Unknown"
        others       = @()
    }

    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        try {
            $vols = Get-BitLockerVolume
            foreach ($v in $vols) {
                $entry = @{
                    mount_point       = $v.MountPoint
                    protection_state  = $v.ProtectionStatus.ToString()
                    volume_status     = $v.VolumeStatus.ToString()
                    encryption_method = $v.EncryptionMethod
                }
                if ($v.MountPoint -eq "C:") {
                    $result.system_drive = $entry
                }
                else {
                    $result.others += $entry
                }
            }
        }
        catch {}
    }
    else {
        try {
            $output = manage-bde -status C: 2>$null
            if ($output) {
                $result.system_drive = ($output -join "`n")
            }
        }
        catch {}
    }

    return $result
}

function Get-FirewallStatus {
    $info = @{
        domain  = "Unknown"
        private = "Unknown"
        public  = "Unknown"
    }

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            $v = if ($p.Enabled) { "Enabled" } else { "Disabled" }
            switch ($p.Name) {
                "Domain" { $info.domain = $v }
                "Private" { $info.private = $v }
                "Public" { $info.public = $v }
            }
        }
    }
    catch {}

    return $info
}

# -------------------------------------------------------------------
# Hardware
# -------------------------------------------------------------------
function Get-CPUInfo {
    $info = @{
        name          = "Unknown"
        cores         = $null
        logical       = $null
        max_clock_mhz = $null
    }
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $info.name = $cpu.Name
        $info.cores = $cpu.NumberOfCores
        $info.logical = $cpu.NumberOfLogicalProcessors
        $info.max_clock_mhz = $cpu.MaxClockSpeed
    }
    catch {}
    return $info
}

function Get-RAMInfo {
    $info = @{
        total_gb       = $null
        modules        = @()
        health_comment = "OK (no detailed diagnostics from OS)"
    }

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $info.total_gb = [Math]::Round($cs.TotalPhysicalMemory / 1GB, 1)

        $dimms = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction SilentlyContinue
        foreach ($d in $dimms) {
            $info.modules += @{
                capacity_gb  = [Math]::Round($d.Capacity / 1GB, 1)
                speed_mhz    = $d.Speed
                manufacturer = $d.Manufacturer
                part_number  = $d.PartNumber
                slot         = $d.DeviceLocator
            }
        }
    }
    catch {}

    return $info
}

function Get-StorageInfo {
    $info = @()

    try {
        $disks = Get-PhysicalDisk -ErrorAction Stop
        foreach ($d in $disks) {
            $sizeGB = if ($d.Size) { [Math]::Round($d.Size / 1GB, 1) } else { $null }
            $info += @{
                friendly_name = $d.FriendlyName
                media_type    = $d.MediaType.ToString()
                size_gb       = $sizeGB
                health        = $d.HealthStatus.ToString()
                can_pool      = $d.CanPool
            }
        }
        if ($info.Count -gt 0) { return $info }
    }
    catch {}

    try {
        $drives = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop
        foreach ($d in $drives) {
            $sizeGB = if ($d.Size) { [Math]::Round($d.Size / 1GB, 1) } else { $null }
            $info += @{
                friendly_name = $d.Model
                media_type    = "Unknown"
                size_gb       = $sizeGB
                health        = "Unknown"
                can_pool      = $null
            }
        }
    }
    catch {}

    return $info
}

function Get-GPUInfo {
    $gpus = @()
    try {
        $vc = Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop
        foreach ($g in $vc) {
            $gpus += @{
                name           = $g.Name
                adapter_ram_mb = if ($g.AdapterRAM) { [Math]::Round($g.AdapterRAM / 1MB, 0) } else { $null }
                driver_version = $g.DriverVersion
            }
        }
    }
    catch {}
    return $gpus
}

function Get-BatteryInfo {
    $info = @{
        present                = $false
        status                 = "No battery detected"
        charge_pct             = $null
        estimated_run_time_min = $null
    }

    try {
        $bat = Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop | Select-Object -First 1
        if ($bat) {
            $info.present = $true
            $info.status = $bat.BatteryStatus
            $info.charge_pct = $bat.EstimatedChargeRemaining
            $info.estimated_run_time_min = $bat.EstimatedRunTime
        }
    }
    catch {}

    return $info
}

function Get-BIOSInfo {
    $info = @{
        manufacturer = "Unknown"
        version      = "Unknown"
        release_date = $null
    }
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $info.manufacturer = $bios.Manufacturer
        $info.version = $bios.SMBIOSBIOSVersion
        if ($bios.ReleaseDate) {
            $info.release_date = [Management.ManagementDateTimeConverter]::ToDateTime($bios.ReleaseDate).ToString("s")
        }
    }
    catch {}
    return $info
}

function Get-TPMInfo {
    $info = @{
        present      = $false
        ready        = $null
        spec         = $null
        manufacturer = $null
    }

    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        try {
            $tpm = Get-Tpm
            if ($tpm) {
                $info.present = $tpm.TpmPresent
                $info.ready = $tpm.TpmReady
                $info.spec = $tpm.SpecVersion
                $info.manufacturer = $tpm.ManufacturerIdTxt
            }
        }
        catch {}
    }

    return $info
}

# -------------------------------------------------------------------
# Network
# -------------------------------------------------------------------
function Get-NetworkInfo {
    $info = @{
        primary_ip    = $null
        adapters      = @()
        wifi_ssid     = $null
        mac_addresses = @()
    }

    try {
        $nics = Get-NetAdapter -Physical -ErrorAction Stop
        foreach ($nic in $nics) {
            $ips = Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "169.254.*" }

            $ipList = $ips.IPAddress
            if (-not $info.primary_ip -and $ipList.Count -gt 0) {
                $info.primary_ip = $ipList[0]
            }

            $info.adapters += @{
                name    = $nic.Name
                status  = $nic.Status
                ifindex = $nic.ifIndex
                mac     = $nic.MacAddress
                ips     = $ipList
                type    = $nic.InterfaceDescription
            }

            if ($nic.MacAddress) {
                $info.mac_addresses += $nic.MacAddress
            }
        }

        try {
            $wlan = netsh wlan show interfaces 2>$null
            if ($wlan) {
                $ssidLine = $wlan | Select-String -Pattern "^\s*SSID\s*:"
                if ($ssidLine) {
                    $ssid = $ssidLine.ToString().Split(":")[1].Trim()
                    if ($ssid -ne "") {
                        $info.wifi_ssid = $ssid
                    }
                }
            }
        }
        catch {}
    }
    catch {}

    return $info
}

# -------------------------------------------------------------------
# Discord upload helper
# -------------------------------------------------------------------
function Upload-DiscordFile {
    param(
        [string]$LocalFile,
        [string]$WebhookUrl,
        [string]$Hostname,
        [string]$Technician,
        [string]$UsernameOverride,
        [string]$AvatarUrl
    )

    if (-not (Test-Path $LocalFile)) {
        Write-Warning "Local file not found: $LocalFile"
        return [pscustomobject]@{ Success = $false; Error = "Local file not found" }
    }

    if (-not $WebhookUrl) {
        Write-Warning "Discord webhook URL not set. Skipping upload."
        return [pscustomobject]@{ Success = $false; Error = "No webhook URL" }
    }

    # Make sure we use modern TLS
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $msg = "Inventory JSON for **$Hostname** collected by **$Technician** at $(Get-Date -Format s)"

    $payload = @{
        content = $msg
    }
    if ($UsernameOverride) { $payload.username = $UsernameOverride }
    if ($AvatarUrl) { $payload.avatar_url = $AvatarUrl }

    $payloadJson = $payload | ConvertTo-Json -Compress

    # Build multipart/form-data using HttpClient
    $httpClient = New-Object System.Net.Http.HttpClient
    $form = New-Object System.Net.Http.MultipartFormDataContent

    try {
        # payload_json part
        $stringContent = New-Object System.Net.Http.StringContent($payloadJson, [System.Text.Encoding]::UTF8, "application/json")
        $stringContent.Headers.ContentDisposition = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue("form-data")
        $stringContent.Headers.ContentDisposition.Name = '"payload_json"'
        $form.Add($stringContent)

        # file1 part
        $fileStream = [System.IO.File]::OpenRead($LocalFile)
        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
        $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/json")
        $fileContent.Headers.ContentDisposition = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue("form-data")
        $fileContent.Headers.ContentDisposition.Name = '"file1"'
        $fileContent.Headers.ContentDisposition.FileName = '"' + [System.IO.Path]::GetFileName($LocalFile) + '"'
        $form.Add($fileContent)

        # Send request
        $response = $httpClient.PostAsync($WebhookUrl, $form).Result

        # Clean up stream
        $fileStream.Dispose()

        if (-not $response.IsSuccessStatusCode) {
            $respBody = $response.Content.ReadAsStringAsync().Result
            $msgErr = "Discord upload failed: HTTP $($response.StatusCode) - $respBody"
            Write-Warning $msgErr
            return [pscustomobject]@{ Success = $false; Error = $msgErr }
        }

        Write-Host "Uploaded inventory JSON to Discord channel via webhook." -ForegroundColor Green
        return [pscustomobject]@{ Success = $true; Error = $null }
    }
    catch {
        $msgErr = "Discord upload failed: $($_.Exception.Message)"
        Write-Warning $msgErr
        return [pscustomobject]@{ Success = $false; Error = $msgErr }
    }
    finally {
        if ($form) { $form.Dispose() }
        if ($httpClient) { $httpClient.Dispose() }
    }
}

# -------------------------------------------------------------------
# Main collection
# -------------------------------------------------------------------
$hostname = $env:COMPUTERNAME
$deviceType = Get-DeviceType
$assetTag = Get-AssetTag
$sm = Get-SerialAndModel
$serial = $sm.Serial
$model = $sm.Model

$loggedUser = Get-LoggedOnUser
$osInfo = Get-OSInfo
$cpuInfo = Get-CPUInfo
$ramInfo = Get-RAMInfo
$storage = Get-StorageInfo
$gpuInfo = Get-GPUInfo
$battery = Get-BatteryInfo
$biosInfo = Get-BIOSInfo
$tpmInfo = Get-TPMInfo
$netInfo = Get-NetworkInfo
$licInfo = Get-WindowsLicenseInfo
$avInfo = Get-AntivirusInfo
$bitlocker = Get-BitLockerStatus
$fwInfo = Get-FirewallStatus

# Ownership / lifecycle defaults
$assignedUser = $loggedUser
$department = ""
$location = $hostname
$status = "Active"          # Active / Spare / Repair / Retired
$purchaseDate = ""
$warrantyExpiry = ""
$vendor = ""

if ($Interactive) {
    $assetTag = Ask-Override "Asset Tag"      $assetTag
    $assignedUser = Ask-Override "Assigned User (e.g. DOMAIN\user)" $assignedUser
    $department = Ask-Override "Department / Business Unit"       $department
    $location = Ask-Override "Location (Building/Floor/Room)"   $location
    $status = Ask-Status $status
    $purchaseDate = Ask-DateOptional "Purchase Date (YYYY-MM-DD)"   $purchaseDate
    $warrantyExpiry = Ask-DateOptional "Warranty Expiry (YYYY-MM-DD)" $warrantyExpiry
    $vendor = Ask-Override "Vendor / Supplier" $vendor

    $avExpiryManual = Ask-DateOptional "Antivirus Expiry (YYYY-MM-DD, if known)" ""
    if ($avExpiryManual) {
        $avInfo.av_expiry = $avExpiryManual
    }

    $licExpiryManual = Ask-DateOptional "Windows License Contract Expiry (YYYY-MM-DD, if known)" ""
    if ($licExpiryManual) {
        $licInfo.detected_expiry = $licExpiryManual
    }

    $ramHealthComment = Ask-Override "RAM Health Comment (e.g. DIMM replaced, errors)" $ramInfo.health_comment
    if ($ramHealthComment) {
        $ramInfo.health_comment = $ramHealthComment
    }
}

# Build final structured object
$inventory = [ordered]@{
    device    = @{
        hostname  = $hostname
        asset_tag = if ($assetTag -like "Unknown*") { $null } else { $assetTag }
        serial    = if ($serial -like "Unknown*") { $null } else { $serial }
        model     = if ($model -like "Unknown*") { $null } else { $model }
        type      = if ($deviceType -like "Unknown*") { $null } else { $deviceType }
        domain    = $env:USERDOMAIN
    }
    owner     = @{
        assigned_user = $assignedUser
        department    = $department
        location      = $location
        status        = $status
    }
    hardware  = @{
        cpu     = $cpuInfo
        ram     = $ramInfo
        storage = $storage
        gpu     = $gpuInfo
        battery = $battery
        bios    = $biosInfo
        tpm     = $tpmInfo
    }
    os        = $osInfo
    security  = @{
        antivirus       = $avInfo
        bitlocker       = $bitlocker
        firewall        = $fwInfo
        windows_license = $licInfo
    }
    network   = $netInfo
    lifecycle = @{
        purchase_date   = $purchaseDate
        warranty_expiry = $warrantyExpiry
        vendor          = $vendor
    }
    metadata  = @{
        schema_version      = "1.1"
        collected_timestamp = (Get-Date).ToString("s")
        collected_by_script = "Get-DeviceInventoryJson.ps1 v1.1"
        technician          = $technician
    }
}

# -------------------------------------------------------------------
# Save JSON locally and upload to Discord + log
# -------------------------------------------------------------------
$json = $inventory | ConvertTo-Json -Depth 8
$localJsonPath = Join-Path $OutputFolder "$hostname.json"

if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$json | Out-File -FilePath $localJsonPath -Encoding UTF8

Write-Host ""
Write-Host "Local inventory JSON saved to: $localJsonPath" -ForegroundColor Cyan

$uploadResult = Upload-DiscordFile -LocalFile $localJsonPath `
    -WebhookUrl $DiscordWebhookUrl `
    -Hostname $hostname `
    -Technician $technician `
    -UsernameOverride $DiscordUsername `
    -AvatarUrl $DiscordAvatarUrl

$uploadStatusText = "NO_WEBHOOK"
if ($uploadResult) {
    if ($uploadResult.Success) {
        $uploadStatusText = "SUCCESS"
    }
    else {
        $uploadStatusText = "FAILED:$($uploadResult.Error)"
    }
}

$logLine = "[{0}] Host={1}; Tech={2}; JSON={3}; Upload={4}" -f `
(Get-Date).ToString("s"), $hostname, $technician, $localJsonPath, $uploadStatusText

$logLine | Out-File -FilePath $logFile -Append -Encoding UTF8
Write-Host "Log entry appended to: $logFile" -ForegroundColor DarkCyan
