<#
.SYNOPSIS
    Runs winget upgrade for the apps that have been failing silently in the
    Intune Remediation script (2-second exits with no output and no exit code),
    captures the full unfiltered output to a log file in C:\ProgramData\Temp
    or %TEMP%.

.DESCRIPTION
    The remediation script's output filter drops lines that don't match a
    specific set of anchor phrases ("Found ", "Successfully", etc.), so when
    winget produces an error message that doesn't start with one of those
    anchors the actual reason for failure is lost. This helper runs the same
    winget invocations with no filtering so the real winget output is preserved.

    Apps listed are the ones observed silently failing in the remediation log -
    Git.Git is in Program Files but still fails from SYSTEM context; the
    others are per-user installs that fail from SYSTEM and sometimes also
    from the non-elevated user-context handoff.

.NOTES
    Where to run from:

      A. As Administrator (admin-user). Best for a quick "what does winget
         actually say". Often succeeds because admin-user has both machine
         and user views. Does NOT reproduce the SYSTEM context Intune uses.

      B. As SYSTEM via PsExec (recommended to reproduce the Intune behaviour).
         From an elevated cmd.exe (not PowerShell - quoting is simpler):

             C:\temp\PsExec64.exe -s -accepteula -nobanner ^
                 powershell.exe -NoProfile -ExecutionPolicy Bypass ^
                 -File "<path-to-this-script>"

         The -s flag makes PsExec start the child as NT AUTHORITY\SYSTEM,
         which is the same identity Intune Remediations use. The log file
         path ends up in C:\Windows\Temp because SYSTEM's %TEMP% resolves
         there (we override this script's default below to write into
         C:\ProgramData\Temp instead so the location is predictable).
#>

$apps = @(
    'Git.Git',
    'Microsoft.Bicep',
    'Microsoft.VisualStudioCode',
    'Anthropic.Claude',
    'Mozilla.Firefox.MSIX',
    'JanDeDobbeleer.OhMyPosh'
)

# Use a predictable path so a SYSTEM-context run lands in a known place that
# the admin user can copy off afterward (SYSTEM's $env:TEMP is normally
# C:\Windows\Temp which is fine, but C:\ProgramData\Temp is even easier to find).
$logDir = "C:\ProgramData\Temp"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
$logPath = Join-Path $logDir "Diagnose-StuckUpgrades_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Write-Host "Writing to: $logPath" -ForegroundColor Cyan

$identity   = [Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem   = $identity.IsSystem
$principal  = New-Object Security.Principal.WindowsPrincipal($identity)
$isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# winget ships as an MSIX (Microsoft.DesktopAppInstaller) installed per-user, so SYSTEM has
# no `winget` on PATH. Mirror what the main remediation script does (~ line 7561): resolve
# the installed App Installer folder under C:\Program Files\WindowsApps\ and invoke
# winget.exe directly from there. From admin-user this isn't strictly necessary because
# winget IS on PATH, but using the explicit path makes both contexts behave identically.
$wingetExe = $null
$resolvePattern = "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_*64__8wekyb3d8bbwe"
$resolved = Resolve-Path $resolvePattern -ErrorAction SilentlyContinue
if ($resolved) {
    $candidate = Join-Path $resolved[-1].Path "winget.exe"
    if (Test-Path $candidate) { $wingetExe = $candidate }
}
if (-not $wingetExe) {
    # Fallback to PATH (works for admin-user, fails for SYSTEM if MSIX not provisioned)
    $wingetExe = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
}

$header = @(
    "=== Diagnose-StuckUpgrades $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
    "Run as:     $($identity.Name)"
    "IsSystem:   $isSystem"
    "Elevated:   $isElevated"
    "SessionId:  $((Get-Process -Id $PID).SessionId)"
    "PID:        $PID"
    "Computer:   $env:COMPUTERNAME"
    "Winget exe: $wingetExe"
    "Winget version:"
)
$header | Out-File $logPath -Encoding UTF8
if ($wingetExe) {
    & $wingetExe --version 2>&1 | Out-File $logPath -Append -Encoding UTF8
} else {
    "ERROR: winget.exe not found on this machine - cannot continue." | Out-File $logPath -Append -Encoding UTF8
    Write-Host "winget.exe not found" -ForegroundColor Red
    return
}

# winget needs to run from its own install directory (some sub-binaries are loaded by relative
# path). Match the remediation script: Push-Location into the WindowsApps dir while calling.
$wingetDir = Split-Path $wingetExe -Parent

foreach ($app in $apps) {
    "" | Out-File $logPath -Append -Encoding UTF8
    "===== $app =====" | Out-File $logPath -Append -Encoding UTF8
    "" | Out-File $logPath -Append -Encoding UTF8

    $start = Get-Date
    Push-Location $wingetDir
    try {
        $output = & $wingetExe upgrade --silent --disable-interactivity --accept-source-agreements --accept-package-agreements --source winget --id $app 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    $duration = ((Get-Date) - $start).TotalSeconds

    $output | Out-File $logPath -Append -Encoding UTF8
    "" | Out-File $logPath -Append -Encoding UTF8
    "Exit code:  $exitCode" | Out-File $logPath -Append -Encoding UTF8
    "Duration:   $($duration.ToString('F2')) s" | Out-File $logPath -Append -Encoding UTF8

    Write-Host "$app -> exit $exitCode in $($duration.ToString('F2')) s" -ForegroundColor Yellow
}

"" | Out-File $logPath -Append -Encoding UTF8
"=== Done ===" | Out-File $logPath -Append -Encoding UTF8

Write-Host ""
Write-Host "Log file: $logPath" -ForegroundColor Green
