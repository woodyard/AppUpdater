$tmp = "$env:TEMP\availableUpgrades-remediate_$(Get-Random).ps1"
irm "https://raw.githubusercontent.com/woodyard/AppUpdater/main/availableUpgrades-remediate.ps1" -OutFile $tmp
& $tmp -WhitelistUrl "https://raw.githubusercontent.com/woodyard/AppUpdater/main/app-whitelist.json"
$exitCode = $LASTEXITCODE
Remove-Item $tmp -Force -ErrorAction SilentlyContinue
exit $exitCode
