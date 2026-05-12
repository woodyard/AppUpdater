<#
.SYNOPSIS
    Collects WingetUpgradeManager diagnostics and sends them to Azure Log Analytics.

.DESCRIPTION
    Gathers system info, registry state (deferrals, failures, skips), and recent
    log file summaries, then posts to a Log Analytics custom log table.

    Designed to run as SYSTEM via Intune or scheduled task.
    Each record includes CustomerTag, hostname, user UPN, and device info
    so data can be filtered per customer/tenant/device in Log Analytics.

.PARAMETER WorkspaceId
    Log Analytics Workspace ID (GUID). Can also be set via env var LAW_WORKSPACE_ID.

.PARAMETER SharedKey
    Log Analytics primary or secondary shared key. Can also be set via env var LAW_SHARED_KEY.

.PARAMETER CustomerTag
    Free-text identifier for the customer/tenant (e.g. "Contoso", "cloudonly.dk").
    Used to distinguish data across multiple tenants sharing one workspace.

.PARAMETER LogType
    Custom log table name in Log Analytics. Defaults to "WingetUpgradeStatus".
    Will appear as "WingetUpgradeStatus_CL" in the workspace.

.EXAMPLE
    .\Send-UpgradeDiagnostics.ps1 -WorkspaceId "abc-123" -SharedKey "base64==" -CustomerTag "Contoso"
#>

param(
    [string]$WorkspaceId  = $env:LAW_WORKSPACE_ID,
    [string]$SharedKey    = $env:LAW_SHARED_KEY,
    [string]$CustomerTag  = $env:LAW_CUSTOMER_TAG,
    [string]$LogType      = "WingetUpgradeStatus"
)

$ErrorActionPreference = "Stop"

# ============================================================
# Validate parameters
# ============================================================
if (-not $WorkspaceId -or -not $SharedKey) {
    # Try loading from config file next to this script
    $configPath = Join-Path $PSScriptRoot "diagnostics-config.json"
    if (Test-Path $configPath) {
        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
        if (-not $WorkspaceId) { $WorkspaceId = $cfg.WorkspaceId }
        if (-not $SharedKey)   { $SharedKey   = $cfg.SharedKey }
    }
}
if (-not $WorkspaceId -or -not $SharedKey) {
    Write-Error "WorkspaceId and SharedKey are required. Provide via parameters, environment variables (LAW_WORKSPACE_ID, LAW_SHARED_KEY), or diagnostics-config.json."
    exit 1
}
if (-not $CustomerTag) {
    # Fall back to Azure AD tenant domain if available
    try {
        $dsregOutput = dsregcmd /status 2>$null
        $tenantLine  = ($dsregOutput | Select-String "TenantName\s*:" | Select-Object -First 1).ToString()
        $CustomerTag = ($tenantLine -split ":\s*", 2)[1].Trim()
    } catch {}
    if (-not $CustomerTag) { $CustomerTag = $env:USERDNSDOMAIN }
    if (-not $CustomerTag) { $CustomerTag = "Unknown" }
}

# ============================================================
# Helper: Send data to Log Analytics HTTP Data Collector API
# ============================================================
function Send-LogAnalyticsData {
    param(
        [string]$WorkspaceId,
        [string]$SharedKey,
        [string]$LogType,
        [string]$Body,
        [string]$TimeStampField = ""
    )

    $method      = "POST"
    $contentType = "application/json"
    $resource    = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLen  = [System.Text.Encoding]::UTF8.GetByteCount($Body)

    $xHeaders    = "x-ms-date:$rfc1123date"
    $stringToHash = "$method`n$contentLen`n$contentType`n$xHeaders`n$resource"
    $bytesToHash  = [System.Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes     = [Convert]::FromBase64String($SharedKey)
    $hmac         = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key     = $keyBytes
    $hash         = $hmac.ComputeHash($bytesToHash)
    $signature    = [Convert]::ToBase64String($hash)
    $authorization = "SharedKey ${WorkspaceId}:${signature}"

    $uri = "https://$WorkspaceId.ods.opinsights.azure.com$resource`?api-version=2016-04-01"

    $headers = @{
        "Authorization"        = $authorization
        "Log-Type"             = $LogType
        "x-ms-date"           = $rfc1123date
        "time-generated-field" = $TimeStampField
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType `
        -Headers $headers -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -UseBasicParsing

    return $response.StatusCode
}

# ============================================================
# Collect: System Information
# ============================================================
function Get-SystemInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem

    # Architecture
    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { "x64" }
        "ARM64" { "ARM64" }
        "x86"   { "x86" }
        default { $env:PROCESSOR_ARCHITECTURE }
    }

    # Windows version (e.g. "10.0.22631") and friendly name
    $buildNumber  = $os.BuildNumber
    $displayVer   = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).DisplayVersion  # e.g. "24H2"
    $productName  = $os.Caption  # e.g. "Microsoft Windows 11 Pro"

    return @{
        Hostname       = $cs.Name
        Domain         = $cs.Domain
        OSVersion      = $os.Version           # 10.0.22631
        OSBuild        = $buildNumber          # 22631
        OSDisplayVer   = $displayVer           # 24H2
        OSProductName  = $productName
        Architecture   = $arch
        TotalMemoryGB  = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        Manufacturer   = $cs.Manufacturer
        Model          = $cs.Model
    }
}

# ============================================================
# Collect: Logged-in User Info
# ============================================================
function Get-UserInfo {
    $info = @{
        Username  = ""
        UPN       = ""
        SID       = ""
        Domain    = ""
    }

    # Get interactive user
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 3
        $fullUser = $cs.UserName  # DOMAIN\user or AzureAD\user
        if ($fullUser) {
            $parts = $fullUser -split "\\"
            $info.Domain   = $parts[0]
            $info.Username = $parts[-1]
        }
    } catch {}

    # Get SID for the user
    if ($info.Username) {
        try {
            $userProfile = Get-CimInstance Win32_UserProfile | Where-Object {
                $_.LocalPath -like "*\$($info.Username)" -and $_.Special -eq $false
            } | Select-Object -First 1
            if ($userProfile) { $info.SID = $userProfile.SID }
        } catch {}
    }

    # Azure AD UPN from identity cache
    if ($info.SID) {
        try {
            $idCachePath = "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($info.SID)\IdentityCache\$($info.SID)"
            $upn = (Get-ItemProperty -Path $idCachePath -Name UserName -ErrorAction SilentlyContinue).UserName
            if ($upn) { $info.UPN = $upn }
        } catch {}
    }

    # Fallback: dsregcmd for UPN
    if (-not $info.UPN) {
        try {
            $dsreg = dsregcmd /status 2>$null
            $upnLine = ($dsreg | Select-String "UserEmail\s*:" | Select-Object -First 1).ToString()
            $info.UPN = ($upnLine -split ":\s*", 2)[1].Trim()
        } catch {}
    }

    return $info
}

# ============================================================
# Collect: Tenant Info (Azure AD / Entra ID)
# ============================================================
function Get-TenantInfo {
    $info = @{
        TenantId   = ""
        TenantName = ""
        JoinType   = ""
    }
    try {
        $dsreg = dsregcmd /status 2>$null
        foreach ($line in $dsreg) {
            if ($line -match "TenantId\s*:\s*(.+)")   { $info.TenantId   = $Matches[1].Trim() }
            if ($line -match "TenantName\s*:\s*(.+)")  { $info.TenantName = $Matches[1].Trim() }
            if ($line -match "AzureAdJoined\s*:\s*YES") { $info.JoinType  = "AzureAD" }
            if ($line -match "DomainJoined\s*:\s*YES" -and $info.JoinType -eq "AzureAD") {
                $info.JoinType = "Hybrid"
            } elseif ($line -match "DomainJoined\s*:\s*YES" -and -not $info.JoinType) {
                $info.JoinType = "OnPrem"
            }
        }
    } catch {}
    return $info
}

# ============================================================
# Collect: Registry - Deferral Data
# ============================================================
function Get-DeferralData {
    $deferrals = @()
    $basePath  = "HKLM:\SOFTWARE\WingetUpgradeManager\Deferrals"

    if (-not (Test-Path $basePath)) { return $deferrals }

    foreach ($app in Get-ChildItem $basePath -ErrorAction SilentlyContinue) {
        $props = Get-ItemProperty -Path $app.PSPath -ErrorAction SilentlyContinue
        $deferrals += @{
            AppID            = $app.PSChildName
            DeferralsUsed    = $props.DeferralsUsed
            LastDeferralDate = $props.LastDeferralDate
            UserDeadline     = $props.UserDeadline
            FirstDetected    = $props.FirstDetected
        }
    }
    return $deferrals
}

# ============================================================
# Collect: Registry - Failure Data
# ============================================================
function Get-FailureData {
    $failures = @()
    $basePath = "HKLM:\SOFTWARE\WingetUpgradeManager\Failures"

    if (-not (Test-Path $basePath)) { return $failures }

    foreach ($app in Get-ChildItem $basePath -ErrorAction SilentlyContinue) {
        $props = Get-ItemProperty -Path $app.PSPath -ErrorAction SilentlyContinue
        $failures += @{
            AppID        = $app.PSChildName
            FailedVersion = $props.FailedVersion
            FailureCount = $props.FailureCount
            Skipped      = $props.Skipped
            SkippedAt    = $props.SkippedAt
            LastFailure  = $props.LastFailure
        }
    }
    return $failures
}

# ============================================================
# Collect: Recent Log Summaries
# ============================================================
function Get-RecentLogSummary {
    $logDir = Join-Path $env:ProgramData "Microsoft\IntuneManagementExtension\Logs"
    $results = @()

    if (-not (Test-Path $logDir)) { return $results }

    # Find most recent detection and remediation logs
    $logFiles = Get-ChildItem $logDir -Filter "*.log" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "DetectAvailableUpgrades|RemediateAvailableUpgrades|availableUpgrades" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 6

    foreach ($logFile in $logFiles) {
        $content = Get-Content $logFile.FullName -Tail 50 -ErrorAction SilentlyContinue

        # Extract key events from log tail
        $upgrades   = @($content | Where-Object { $_ -match "upgrade.*found|available.*upgrade|upgrading|winget upgrade" })
        $successes  = @($content | Where-Object { $_ -match "success|completed|upgraded" })
        $errors     = @($content | Where-Object { $_ -match "fail|error|exception" })
        $deferrals  = @($content | Where-Object { $_ -match "defer" })
        $skips      = @($content | Where-Object { $_ -match "skip" })

        $results += @{
            FileName        = $logFile.Name
            LastWriteTime   = $logFile.LastWriteTime.ToString("o")
            SizeKB          = [math]::Round($logFile.Length / 1KB, 1)
            UpgradeLines    = $upgrades.Count
            SuccessLines    = $successes.Count
            ErrorLines      = $errors.Count
            DeferralLines   = $deferrals.Count
            SkipLines       = $skips.Count
            LastLines       = ($content | Select-Object -Last 5) -join "`n"
        }
    }
    return $results
}

# ============================================================
# Collect: Currently Available Upgrades (winget)
# ============================================================
function Get-AvailableUpgrades {
    $upgrades = @()
    try {
        # Find winget
        $wingetPath = Get-Command winget -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        if (-not $wingetPath) {
            $wingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_*__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue |
                Sort-Object Path -Descending | Select-Object -First 1 -ExpandProperty Path
        }
        if (-not $wingetPath) { return $upgrades }

        $output = & $wingetPath upgrade --accept-source-agreements 2>$null
        if (-not $output) { return $upgrades }

        # Find header line with "Id" and "Version" and "Available"
        $headerIdx = -1
        for ($i = 0; $i -lt $output.Count; $i++) {
            if ($output[$i] -match "\bId\b" -and $output[$i] -match "\bVersion\b" -and $output[$i] -match "\bAvailable\b") {
                $headerIdx = $i
                break
            }
        }
        if ($headerIdx -lt 0) { return $upgrades }

        $header = $output[$headerIdx]
        $idStart   = $header.IndexOf("Id")
        $verStart  = $header.IndexOf("Version")
        $availStart = $header.IndexOf("Available")

        # Skip separator line (dashes)
        $dataStart = $headerIdx + 2

        for ($i = $dataStart; $i -lt $output.Count; $i++) {
            $line = $output[$i]
            if ($line -match "^\d+ upgrades? available" -or [string]::IsNullOrWhiteSpace($line)) { break }
            if ($line.Length -lt $availStart + 2) { continue }

            $appId   = $line.Substring($idStart, $verStart - $idStart).Trim()
            $version = $line.Substring($verStart, $availStart - $verStart).Trim()
            $avail   = $line.Substring($availStart).Trim() -replace "\s+.*$", ""

            if ($appId -and $version -and $avail) {
                $upgrades += @{
                    AppID            = $appId
                    InstalledVersion = $version
                    AvailableVersion = $avail
                }
            }
        }
    } catch {
        # Silently continue - winget may not be available in SYSTEM context without tricks
    }
    return $upgrades
}

# ============================================================
# Collect: Whitelist Status
# ============================================================
function Get-WhitelistInfo {
    $info = @{ Apps = @(); Source = "none" }

    # Check for local whitelist
    $localPath = Join-Path $PSScriptRoot "app-whitelist.json"
    if (Test-Path $localPath) {
        try {
            $wl = Get-Content $localPath -Raw | ConvertFrom-Json
            $info.Source = "local"
            foreach ($app in $wl) {
                $info.Apps += @{
                    AppID           = $app.AppID
                    Disabled        = [bool]$app.Disabled
                    DeferralEnabled = [bool]$app.DeferralEnabled
                    FriendlyName    = $app.FriendlyName
                }
            }
        } catch {}
    }

    return $info
}

# ============================================================
# MAIN: Collect all data and send
# ============================================================
Write-Host "Collecting WingetUpgradeManager diagnostics..." -ForegroundColor Cyan

$timestamp  = Get-Date -Format "o"
$sysInfo    = Get-SystemInfo
$userInfo   = Get-UserInfo
$tenantInfo = Get-TenantInfo
$deferrals  = Get-DeferralData
$failures   = Get-FailureData
$logSummary = Get-RecentLogSummary
$upgrades   = Get-AvailableUpgrades
$whitelist  = Get-WhitelistInfo

# Build per-app records for granular analysis
$records = @()

# One record per available upgrade (most useful for dashboards)
foreach ($upg in $upgrades) {
    $appDeferral = $deferrals | Where-Object { $_.AppID -eq $upg.AppID }
    $appFailure  = $failures  | Where-Object { $_.AppID -eq $upg.AppID }

    $records += @{
        # Identity
        TimeGenerated    = $timestamp
        CustomerTag      = $CustomerTag
        TenantId         = $tenantInfo.TenantId
        TenantName       = $tenantInfo.TenantName
        Hostname         = $sysInfo.Hostname
        UserUPN          = $userInfo.UPN
        Username         = $userInfo.Username
        UserSID          = $userInfo.SID

        # System
        OSVersion        = $sysInfo.OSVersion
        OSBuild          = $sysInfo.OSBuild
        OSDisplayVersion = $sysInfo.OSDisplayVer
        OSProductName    = $sysInfo.OSProductName
        Architecture     = $sysInfo.Architecture
        Manufacturer     = $sysInfo.Manufacturer
        Model            = $sysInfo.Model

        # App Update
        RecordType       = "AvailableUpgrade"
        AppID            = $upg.AppID
        InstalledVersion = $upg.InstalledVersion
        AvailableVersion = $upg.AvailableVersion

        # Deferral state
        DeferralsUsed    = if ($appDeferral) { $appDeferral.DeferralsUsed } else { 0 }
        LastDeferralDate = if ($appDeferral) { $appDeferral.LastDeferralDate } else { $null }
        UserDeadline     = if ($appDeferral) { $appDeferral.UserDeadline } else { $null }
        FirstDetected    = if ($appDeferral) { $appDeferral.FirstDetected } else { $null }

        # Failure state
        FailedVersion    = if ($appFailure) { $appFailure.FailedVersion } else { $null }
        FailureCount     = if ($appFailure) { $appFailure.FailureCount } else { 0 }
        Skipped          = if ($appFailure) { $appFailure.Skipped } else { "false" }
        SkippedAt        = if ($appFailure) { $appFailure.SkippedAt } else { $null }
        LastFailure      = if ($appFailure) { $appFailure.LastFailure } else { $null }
    }
}

# Add records for apps with failures/deferrals that are NOT currently showing as available
# (e.g. successfully upgraded but had prior issues, or skipped versions)
$reportedAppIds = $records | ForEach-Object { $_.AppID }

foreach ($fail in $failures) {
    if ($fail.AppID -in $reportedAppIds) { continue }
    $appDeferral = $deferrals | Where-Object { $_.AppID -eq $fail.AppID }

    $records += @{
        TimeGenerated    = $timestamp
        CustomerTag      = $CustomerTag
        TenantId         = $tenantInfo.TenantId
        TenantName       = $tenantInfo.TenantName
        Hostname         = $sysInfo.Hostname
        UserUPN          = $userInfo.UPN
        Username         = $userInfo.Username
        UserSID          = $userInfo.SID
        OSVersion        = $sysInfo.OSVersion
        OSBuild          = $sysInfo.OSBuild
        OSDisplayVersion = $sysInfo.OSDisplayVer
        OSProductName    = $sysInfo.OSProductName
        Architecture     = $sysInfo.Architecture
        Manufacturer     = $sysInfo.Manufacturer
        Model            = $sysInfo.Model
        RecordType       = "FailureRecord"
        AppID            = $fail.AppID
        InstalledVersion = $null
        AvailableVersion = $null
        DeferralsUsed    = if ($appDeferral) { $appDeferral.DeferralsUsed } else { 0 }
        LastDeferralDate = if ($appDeferral) { $appDeferral.LastDeferralDate } else { $null }
        UserDeadline     = if ($appDeferral) { $appDeferral.UserDeadline } else { $null }
        FirstDetected    = if ($appDeferral) { $appDeferral.FirstDetected } else { $null }
        FailedVersion    = $fail.FailedVersion
        FailureCount     = $fail.FailureCount
        Skipped          = $fail.Skipped
        SkippedAt        = $fail.SkippedAt
        LastFailure      = $fail.LastFailure
    }
}

foreach ($def in $deferrals) {
    if ($def.AppID -in $reportedAppIds) { continue }
    if ($def.AppID -in ($failures | ForEach-Object { $_.AppID })) { continue }  # Already covered above

    $records += @{
        TimeGenerated    = $timestamp
        CustomerTag      = $CustomerTag
        TenantId         = $tenantInfo.TenantId
        TenantName       = $tenantInfo.TenantName
        Hostname         = $sysInfo.Hostname
        UserUPN          = $userInfo.UPN
        Username         = $userInfo.Username
        UserSID          = $userInfo.SID
        OSVersion        = $sysInfo.OSVersion
        OSBuild          = $sysInfo.OSBuild
        OSDisplayVersion = $sysInfo.OSDisplayVer
        OSProductName    = $sysInfo.OSProductName
        Architecture     = $sysInfo.Architecture
        Manufacturer     = $sysInfo.Manufacturer
        Model            = $sysInfo.Model
        RecordType       = "DeferralOnly"
        AppID            = $def.AppID
        InstalledVersion = $null
        AvailableVersion = $null
        DeferralsUsed    = $def.DeferralsUsed
        LastDeferralDate = $def.LastDeferralDate
        UserDeadline     = $def.UserDeadline
        FirstDetected    = $def.FirstDetected
        FailedVersion    = $null
        FailureCount     = 0
        Skipped          = "false"
        SkippedAt        = $null
        LastFailure      = $null
    }
}

# If no per-app records, send a heartbeat with system info only
if ($records.Count -eq 0) {
    $records += @{
        TimeGenerated    = $timestamp
        CustomerTag      = $CustomerTag
        TenantId         = $tenantInfo.TenantId
        TenantName       = $tenantInfo.TenantName
        Hostname         = $sysInfo.Hostname
        UserUPN          = $userInfo.UPN
        Username         = $userInfo.Username
        UserSID          = $userInfo.SID
        OSVersion        = $sysInfo.OSVersion
        OSBuild          = $sysInfo.OSBuild
        OSDisplayVersion = $sysInfo.OSDisplayVer
        OSProductName    = $sysInfo.OSProductName
        Architecture     = $sysInfo.Architecture
        Manufacturer     = $sysInfo.Manufacturer
        Model            = $sysInfo.Model
        RecordType       = "Heartbeat"
        AppID            = $null
        InstalledVersion = $null
        AvailableVersion = $null
        DeferralsUsed    = 0
        LastDeferralDate = $null
        UserDeadline     = $null
        FirstDetected    = $null
        FailedVersion    = $null
        FailureCount     = 0
        Skipped          = "false"
        SkippedAt        = $null
        LastFailure      = $null
    }
}

# Also send log summary records separately
foreach ($log in $logSummary) {
    $records += @{
        TimeGenerated    = $timestamp
        CustomerTag      = $CustomerTag
        TenantId         = $tenantInfo.TenantId
        TenantName       = $tenantInfo.TenantName
        Hostname         = $sysInfo.Hostname
        UserUPN          = $userInfo.UPN
        Username         = $userInfo.Username
        UserSID          = $userInfo.SID
        OSVersion        = $sysInfo.OSVersion
        OSBuild          = $sysInfo.OSBuild
        OSDisplayVersion = $sysInfo.OSDisplayVer
        OSProductName    = $sysInfo.OSProductName
        Architecture     = $sysInfo.Architecture
        Manufacturer     = $sysInfo.Manufacturer
        Model            = $sysInfo.Model
        RecordType       = "LogSummary"
        AppID            = $null
        InstalledVersion = $null
        AvailableVersion = $null
        DeferralsUsed    = 0
        LastDeferralDate = $null
        UserDeadline     = $null
        FirstDetected    = $null
        FailedVersion    = $null
        FailureCount     = 0
        Skipped          = "false"
        SkippedAt        = $null
        LastFailure      = $null
        LogFileName      = $log.FileName
        LogLastWrite     = $log.LastWriteTime
        LogSizeKB        = $log.SizeKB
        LogUpgradeLines  = $log.UpgradeLines
        LogSuccessLines  = $log.SuccessLines
        LogErrorLines    = $log.ErrorLines
        LogDeferralLines = $log.DeferralLines
        LogSkipLines     = $log.SkipLines
        LogLastLines     = $log.LastLines
    }
}

# Send to Log Analytics
$json = $records | ConvertTo-Json -Depth 5
if ($records.Count -eq 1) { $json = "[$json]" }  # API expects array

Write-Host "Sending $($records.Count) records to Log Analytics ($LogType)..." -ForegroundColor Cyan
Write-Host "  Customer : $CustomerTag"
Write-Host "  Hostname : $($sysInfo.Hostname)"
Write-Host "  User     : $($userInfo.UPN)"
Write-Host "  OS       : $($sysInfo.OSProductName) $($sysInfo.OSDisplayVer) ($($sysInfo.Architecture))"

try {
    $statusCode = Send-LogAnalyticsData -WorkspaceId $WorkspaceId -SharedKey $SharedKey `
        -LogType $LogType -Body $json -TimeStampField "TimeGenerated"

    if ($statusCode -eq 200) {
        Write-Host "  Sent successfully (HTTP $statusCode)." -ForegroundColor Green
    } else {
        Write-Host "  Unexpected response: HTTP $statusCode" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Failed to send: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`nData will appear in table '$($LogType)_CL' within a few minutes." -ForegroundColor Cyan
Write-Host "Sample KQL:" -ForegroundColor Gray
Write-Host "  $($LogType)_CL | where RecordType_s == 'AvailableUpgrade' | summarize count() by AppID_s, CustomerTag_s" -ForegroundColor Gray
