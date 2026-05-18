$ErrorActionPreference = 'Stop'
$tmp = "$env:TEMP\availableUpgrades-remediate_$(Get-Random).ps1"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri "https://raw.githubusercontent.com/woodyard/AppUpdater/main/availableUpgrades-remediate.ps1" -OutFile $tmp
    if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -eq 0) {
        throw "downloaded remediate script is missing or empty at $tmp"
    }
    & $tmp -WhitelistUrl "https://raw.githubusercontent.com/woodyard/AppUpdater/main/app-whitelist.json"
    exit $LASTEXITCODE
} catch {
    Write-Error "Bootstrapper (remediate) failed: $($_.Exception.Message)"
    exit 1
} finally {
    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}
