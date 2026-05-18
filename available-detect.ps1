$ErrorActionPreference = 'Stop'
$global:whitelistUrl = "https://raw.githubusercontent.com/woodyard/AppUpdater/main/app-whitelist.json"
$tmp = "$env:TEMP\availableUpgrades-detect_$(Get-Random).ps1"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri "https://raw.githubusercontent.com/woodyard/AppUpdater/main/availableUpgrades-detect.ps1" -OutFile $tmp
    if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -eq 0) {
        throw "downloaded detect script is missing or empty at $tmp"
    }
    & $tmp
    exit $LASTEXITCODE
} catch {
    Write-Error "Bootstrapper (detect) failed: $($_.Exception.Message)"
    exit 1
} finally {
    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}
