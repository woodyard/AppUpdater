@echo off
REM Runs Diagnose-StuckUpgrades.ps1 as NT AUTHORITY\SYSTEM via PsExec64.
REM
REM Prerequisites:
REM   - C:\temp\PsExec64.exe present
REM   - C:\temp\Diagnose-StuckUpgrades.ps1 present
REM   - This .cmd file run from an *elevated* cmd.exe (Run as Administrator).
REM
REM On first run PsExec asks you to accept its EULA - the -accepteula flag
REM does that non-interactively.
REM
REM Output log lands at C:\ProgramData\Temp\Diagnose-StuckUpgrades_<timestamp>.log
REM The script's header will read:
REM   Run as:     NT AUTHORITY\SYSTEM
REM   IsSystem:   True
REM   SessionId:  0
REM confirming you reproduced the Intune context.

setlocal

set "PSEXEC=C:\temp\PsExec64.exe"
set "SCRIPT=C:\temp\Diagnose-StuckUpgrades.ps1"

if not exist "%PSEXEC%" (
    echo ERROR: %PSEXEC% not found.
    exit /b 1
)
if not exist "%SCRIPT%" (
    echo ERROR: %SCRIPT% not found.
    exit /b 1
)

echo Launching diagnostic as SYSTEM via PsExec...
echo.

"%PSEXEC%" -s -accepteula -nobanner powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"

echo.
echo Done. Log file is in C:\ProgramData\Temp\Diagnose-StuckUpgrades_*.log
echo.
pause

endlocal
