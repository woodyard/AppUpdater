<#
.SYNOPSIS
    Runs winget upgrade for the three apps currently failing in the AppUpdater
    remediation cycle (Bicep, VSCode, Claude), captures the full output, and
    writes everything to a single log file in %TEMP%.

.DESCRIPTION
    The remediation script's output filter drops lines that don't match a
    specific set of anchor phrases ("Found ", "Successfully", etc.), so when
    winget produces an error message that doesn't start with one of those
    anchors the actual reason for failure is lost. This helper runs the same
    three winget invocations as the remediation script with no filtering,
    so the real winget output is preserved.

.NOTES
    Run as Administrator to match the SYSTEM-context invocation used by the
    Intune Remediation script.
#>

$apps = @(
    'Microsoft.Bicep',
    'Microsoft.VisualStudioCode',
    'Anthropic.Claude'
)

$logPath = Join-Path $env:TEMP "Diagnose-StuckUpgrades_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Write-Host "Writing to: $logPath" -ForegroundColor Cyan

$header = @(
    "=== Diagnose-StuckUpgrades $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
    "Run as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    "Elevated: $((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    "Winget version:"
)
$header | Out-File $logPath -Encoding UTF8
& winget --version 2>&1 | Out-File $logPath -Append -Encoding UTF8

foreach ($app in $apps) {
    "" | Out-File $logPath -Append -Encoding UTF8
    "===== $app =====" | Out-File $logPath -Append -Encoding UTF8
    "" | Out-File $logPath -Append -Encoding UTF8

    $output = & winget upgrade --silent --disable-interactivity --accept-source-agreements --accept-package-agreements --source winget --id $app 2>&1
    $exitCode = $LASTEXITCODE

    $output | Out-File $logPath -Append -Encoding UTF8
    "" | Out-File $logPath -Append -Encoding UTF8
    "Exit code: $exitCode" | Out-File $logPath -Append -Encoding UTF8

    Write-Host "$app -> exit $exitCode" -ForegroundColor Yellow
}

"" | Out-File $logPath -Append -Encoding UTF8
"=== Done ===" | Out-File $logPath -Append -Encoding UTF8

Write-Host ""
Write-Host "Log file: $logPath" -ForegroundColor Green
