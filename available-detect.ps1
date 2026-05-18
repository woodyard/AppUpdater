# Intune detect for AppUpdater. Sub-second on the happy path so it always
# fits inside IME's ~32 s ODPR runner-queue budget.
#
# Architecture:
#   This script does NOT do the heavy detection itself anymore. It just reads
#   availableUpgrades-tasks.json (written by a local "maintainer" scheduled
#   task that runs hourly) and decides 0/1 based on what's in there.
#
#   First run on a device (or any run where the maintainer task is missing):
#     - install the maintainer scheduled task
#     - fire it immediately so the task file lands ASAP
#     - exit 0 (no task file yet)
#
#   Subsequent runs:
#     - read the task file
#     - exit 1 if it has tasks AND was written within the last 48 h
#     - exit 0 otherwise (no file, stale, empty, or parse error)
#
# Exit codes follow Intune Remediations convention:
#   0 = compliant / nothing to do
#   1 = non-compliant / run remediation script
#
# Why this works: the heavy detection (winget upgrade, user-context handoff,
# per-app scope walk - 30-60 s of work) runs from a Task Scheduler trigger
# on the device, NOT inside the Intune Remediation timeout window. IME's
# detect launch budget is irrelevant to that task. This script only ever
# does a file read + small JSON parse.

$ErrorActionPreference = 'Stop'

$taskFile            = 'C:\ProgramData\Temp\availableUpgrades-tasks.json'
$maintainerTaskName  = 'AppUpdater-Maintainer'
$maintainerDir       = 'C:\ProgramData\AppUpdater'
$maintainerLauncher  = Join-Path $maintainerDir 'maintainer-launcher.ps1'
$detectScriptUrl     = 'https://raw.githubusercontent.com/woodyard/AppUpdater/main/availableUpgrades-detect.ps1'
$taskFileMaxAgeHours = 48

function Install-MaintainerTask {
    # 1. Write the local launcher script. Same hardened-bootstrapper pattern as the
    #    previous Intune wrapper - downloads availableUpgrades-detect.ps1 fresh each
    #    run so the maintainer always uses the latest detection logic from GitHub.
    if (-not (Test-Path $maintainerDir)) {
        New-Item -Path $maintainerDir -ItemType Directory -Force | Out-Null
    }
    $launcherContent = @'
$ErrorActionPreference = 'Stop'
$tmp = "$env:TEMP\availableUpgrades-detect_$(Get-Random).ps1"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri '__URL__' -OutFile $tmp
    if (-not (Test-Path $tmp) -or (Get-Item $tmp).Length -eq 0) {
        throw 'downloaded detect script is missing or empty'
    }
    & $tmp
    exit $LASTEXITCODE
} catch {
    Write-Error "Maintainer launcher failed: $($_.Exception.Message)"
    exit 1
} finally {
    if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}
'@.Replace('__URL__', $detectScriptUrl)
    $launcherContent | Out-File -FilePath $maintainerLauncher -Encoding UTF8 -Force

    # 2. Register the scheduled task via XML. XML route picked over the cmdlet path
    #    because the PS 5.1 New-ScheduledTaskTrigger / RepetitionInterval /
    #    RepetitionDuration combination is parameter-set-fussy and varies across
    #    OS builds. Raw XML works the same everywhere.
    #
    #    Trigger: TimeTrigger at "now+1m" with 1-hour repetition, no end. Without
    #    StopAtDurationEnd, Task Scheduler interprets a missing <Duration> as
    #    indefinite repetition - exactly what we want for hourly forever.
    $startBoundary = (Get-Date).AddMinutes(1).ToString('s')
    $launcherEscaped = $maintainerLauncher.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
    $taskXml = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>AppUpdater hourly detection refresh - writes C:\ProgramData\Temp\availableUpgrades-tasks.json</Description>
    <Author>AppUpdater</Author>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>__START__</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "__LAUNCHER__"</Arguments>
    </Exec>
  </Actions>
</Task>
'@.Replace('__START__', $startBoundary).Replace('__LAUNCHER__', $launcherEscaped)

    Register-ScheduledTask -TaskName $maintainerTaskName -Xml $taskXml -Force | Out-Null

    # 3. Fire it immediately. The trigger's StartBoundary is 1 minute in the future,
    #    but Start-ScheduledTask runs it right now regardless. First task file write
    #    typically lands ~1 minute after this returns.
    Start-ScheduledTask -TaskName $maintainerTaskName
}

try {
    # Step 1: ensure the maintainer scheduled task is installed. Recreate it if it
    # got deleted between Intune detect runs.
    $existing = Get-ScheduledTask -TaskName $maintainerTaskName -ErrorAction SilentlyContinue
    if (-not $existing) {
        Install-MaintainerTask
        Write-Output "[AppUpdater] Maintainer scheduled task installed and fired - task file pending"
        exit 0
    }

    # Step 2: read the task file. Treat missing / stale / empty / unparseable as compliant.
    if (-not (Test-Path $taskFile)) {
        Write-Output "[AppUpdater] No task file present yet (maintainer may still be running its first cycle)"
        exit 0
    }

    $age = (Get-Date) - (Get-Item $taskFile).LastWriteTime
    if ($age.TotalHours -gt $taskFileMaxAgeHours) {
        Write-Output "[AppUpdater] Task file is stale ($([int]$age.TotalHours) h, threshold $taskFileMaxAgeHours h) - ignoring"
        exit 0
    }

    $data = Get-Content $taskFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $tasks = @($data.Tasks)
    if ($tasks.Count -eq 0) {
        Write-Output "[AppUpdater] No upgrades pending"
        exit 0
    }

    $appIds = ($tasks | ForEach-Object { $_.AppID }) -join ', '
    Write-Output "[AppUpdater] $($tasks.Count) upgrade(s) pending: $appIds"
    exit 1

} catch {
    # Detect errors fall through as "compliant" so we don't spam remediation runs on
    # transient parse / I/O issues. The maintainer is independent and will keep
    # refreshing the task file regardless.
    Write-Output "[AppUpdater] Detect error (treated as compliant): $($_.Exception.Message)"
    exit 0
}
