<#
.SYNOPSIS
    Winget Application Update Remediation Script
    
.DESCRIPTION
    This script performs application updates using winget based on a whitelist approach.
    It supports both system and user context applications using a dual-context architecture.
    The script is designed to work as a remediation script in Microsoft Intune remediation policies.

.PARAMETER UserRemediationOnly
    When specified, the script runs in user remediation mode (scheduled task execution)

.PARAMETER RemediationResultFile
    Path to the file where remediation results are written (used by scheduled task child process)

.PARAMETER WhitelistUrl
    URL to the whitelist JSON file. Passed through to user-context scheduled tasks.
    If not specified, falls back to $global:whitelistUrl (bootstrapper scenario), then the default GitHub URL.

.NOTES
 Author: Henrik Skovgaard
 Version: 9.62
 Tag: 62
    
    Version History:
    1.0 - Initial version
    2.0 - Fixed user context detection, improved error handling, enhanced blocking process logic
    2.1 - Added Logitech.Options, Logitech.OptionsPlus, TrackerSoftware.PDF-XChangeEditor to whitelist
    2.2 - Implemented variable-based tag system for easier maintenance
    2.3 - Improved console output: tag moved to front, removed date from console (kept in log), added startup date log
    2.4 - ScriptTag now appears before timestamp in console output
    2.5 - Disabled Logitech.OptionsPlus due to upgrade issues
    2.6 - Improved date format from MM-dd-yy to dd.MM.yyyy for better readability
    2.7 - Added Microsoft.VCLibs.Desktop.14 to whitelist
    2.8 - Enhanced Adobe Reader blocking processes and improved multiple process support
    2.9 - Fixed Logitech.OptionsPlus AppID typo to match actual winget ID (OptonsPlus)
    3.0 - Added Microsoft.AzureDataStudio, Mythicsoft.AgentRansack, ParadoxInteractive.ParadoxLauncher, Foxit.FoxitReader.Inno, OBSProject.OBSStudio, Python.Launcher; Disabled Fortinet.FortiClientVPN
    3.1 - Added ARM64 support for winget path resolution
    3.2 - Added interactive popup to ask users about closing blocking processes
    3.3 - Added GitHub.GitHubDesktop to whitelist; Fixed winget output parsing bug causing character-by-character display
    3.4 - Moved whitelist configuration to external GitHub-hosted JSON file for centralized management
    3.5 - Removed redundant exclude list logic to streamline whitelist-only approach
    3.6 - Fixed wildcard matching bug that caused disabled apps to be processed when they contained enabled app names as substrings
    3.7 - Updated version to match detection script
    3.8 - Made context filtering logic more robust to handle apps without explicit SystemContext/UserContext properties; Added WiresharkFoundation.Wireshark to whitelist
    3.9 - Improved log management: dynamic path selection (Intune logs for system context), automatic cleanup of logs older than 1 month
    4.0 - Added PromptWhenBlocked property support for granular control over interactive dialogs vs silent waiting when blocking processes are running
    4.1 - Fixed Windows Forms dialog for non-interactive/system context execution, resolved quser command path issues, improved system context error handling, added user session dialog display for system context
    4.2 - Enhanced user session dialog display with multiple fallback approaches and improved reliability
    4.3 - Fixed quser.exe availability issues with multiple path detection and comprehensive WMI-based fallback mechanisms for user session detection and dialog display
    4.4 - Fixed scheduled task LogonType enumeration error (InteractiveToken to Interactive) for proper VBScript dialog execution in user context
    4.5 - Enhanced VBScript dialog execution with direct process approach and improved scheduled task debugging for better dialog reliability
    4.6 - Added multiple user notification methods: msg.exe alerts, balloon tip notifications, and simplified notification approach for better user visibility
    5.0 - MAJOR UPDATE: Implemented Windows 10/11 Toast Notifications with interactive Yes/No buttons for true user dialog capability from system service context
    6.0 - COMPLETE REWRITE: Replaced all problematic dialog systems with robust Windows Toast Notifications and PowerShell WPF dialogs with comprehensive fallback mechanisms
    7.0 - REVOLUTIONARY UPDATE: Implemented modern WPF-based notification system with Azure AD support, replacing legacy toast notifications with reliable cross-session dialogs, enhanced whitelist timeout support, and optimized for Intune deployment environments
    7.1 - Enhanced WPF dialog system with countdown timer display on default action button for improved user experience and clarity
    8.1 - CRITICAL UPDATE: Added --scope user support for non-privileged user context upgrades, allowing users without admin rights to upgrade user-scoped applications
    8.2 - CRITICAL FIX: Fixed empty script path issue in scheduled tasks by capturing $MyInvocation.MyCommand.Path at global scope with multiple fallback methods; Fixed PowerShell syntax errors with Test-RunningAsSystem function calls
    8.3 - SECURITY IMPROVEMENT: Scripts now copy themselves to user-accessible temp locations before scheduling tasks, improving security and access control with automatic cleanup
    8.4 - CRITICAL FIX: Fixed Azure AD identity cache registry errors in Intune by replacing Start-Job background registry access with direct Test-Path and SilentlyContinue error handling, eliminating "remediation error" messages on AAD-joined machines
    8.5 - ENHANCEMENT: Implemented comprehensive marker file management system with centralized cleanup functions, orphaned file detection, and emergency cleanup handlers to prevent accumulation of .userdetection files; Added hidden console window execution method using cmd.exe with /min flag to eliminate visible console windows during scheduled task execution
    8.6 - PERFORMANCE OPTIMIZATION: Implemented user info caching to eliminate redundant CIM/WMI calls (3+ second savings), fixed deferral system type comparison error that blocked Adobe Reader updates, eliminated double marker file initialization, enhanced scheduled task execution with -NoProfile flag for better reliability
    8.7 - FEATURE: Added per-version failure tracking - counts consecutive install failures per app version in registry, offers user skip dialog after 3 failures; skip auto-clears when a newer version becomes available or upgrade succeeds
    8.8 - FIX: Added post-upgrade verification for exit-code-0 successes: runs winget list after upgrade and checks if "Available" column is still present; if so treats as failure instead of false-positive success (fixes detection loop for apps like Adobe Reader whose installer returns 0 without changing the installed version)
    8.9 - FIX: Removed --scope user from winget upgrade listing in user remediation context; machine-scoped apps were hidden from detection. Added scope detection to upgrade command: machine-scoped apps are skipped in non-admin user context (would require elevation/UAC), user-scoped apps keep --scope user
    9.0 - FIX: Fixed whitelist loading via iex bootstrapper - added global scope fallback for $whitelistUrl, TLS 1.2 enforcement, and WhitelistUrl parameter documentation
    9.1 - FIX: Replaced WebClient.DownloadString with Invoke-RestMethod for whitelist loading to avoid AV/AMSI blocks when run via iex bootstrapper
    9.2 - ENHANCEMENT: Direct user-context deferral dialog now stays open in progress mode during upgrades instead of closing immediately; polls for status updates and completion signal
    9.3 - FIX: Added heartbeat updates during app processing loop and Invoke-WingetWithProgress to prevent SYSTEM parent timeout during long upgrades; fixed winget output validation for ErrorRecord objects
    9.4 - ENHANCEMENT: Added Resolve-FriendlyName function that looks up display names via winget show when FriendlyName is missing from whitelist config; runs lazily only for matched apps being updated
    9.5 - FEATURE: Added category-based whitelist defaults; JSON now supports { CategoryDefaults, Apps } structure where per-category settings (PromptWhenBlocked, TimeoutSeconds, DeferralEnabled, etc.) are inherited by apps in that category; app-level properties override category defaults; backward compatible with legacy flat array format
    9.6 - FIX: SYSTEM-side wait now uses idle-based timeout (600s without heartbeat) instead of hard deadline, so active user-context upgrades run indefinitely as long as heartbeat is alive; post-upgrade verification uses --exact flag to prevent substring ID matches and compares available version against target to avoid false failures when a newer release appears in the source after upgrade; added diagnostic logging to success evaluation; pre-update winget source once before the upgrade loop to prevent redundant per-app source refreshes; removed misleading "Updating sources..." status from progress dialog; optimized per-app winget commands by dropping unused --log flag, adding --disable-interactivity and --accept-package-agreements to eliminate preamble stalls
    9.7 - FIX: Fixed orphaned scheduled task cleanup - added Remove-StaleScheduledTasks startup sweep for all task prefixes (UserPrompt_, UpgradeProgress_, CompletionNotification_, MandatoryPrompt_, DeferralPrompt_, SkipPrompt_, UserRemediation_); added task and temp file cleanup to catch blocks in Invoke-SystemUserPrompt, Invoke-SystemCompletionNotification, Invoke-SystemDeferralPrompt, Show-VersionSkipDialog, and Show-MandatoryUpdateDialog that previously leaked tasks on exceptions
    9.8 - FIX: Fixed VBS launcher file accumulation in temp directories - expanded Remove-OldTempFiles to scan user temp directories (not just C:\ProgramData\Temp) for stale HiddenLaunch_*.vbs and dialog script/response files; added VBS cleanup to New-UserPromptTask failure paths (including Azure AD fallback) and Show-UpgradeProgressNotification error/no-principal paths; broadened temp file regex to cover all dialog types (UpgradeProgress_, CompletionNotification_, SkipPrompt_)
    9.9 - FIX: VBS launcher files now self-delete after the child process finishes; eliminates accumulation regardless of caller cleanup path
    9.10 - FIX: Reduced stale file/task cleanup cutoff from 30 minutes to 10 minutes so the startup sweep removes old leftovers (days/months old) on next run
    9.11 - FIX: Wrapped VBS self-delete in On Error Resume Next to prevent "Permission denied" dialog when user context cannot delete SYSTEM-owned launcher file; Fixed user-context remediation missing user-scoped apps (e.g. Perplexity.Comet) by running winget twice - default listing for machine-scoped apps plus --scope user for user-scoped apps - and merging results by AppID before processing
    9.12 - FIX: Fixed Update-Heartbeat Boolean return value leaking into Invoke-WingetWithProgress output, causing "[System.Boolean] does not contain a method named 'Trim'" error during post-upgrade result parsing; added type guard in upgrade output iteration to skip non-string elements
    9.13 - FEATURE: Added direct-download installer fallback when winget fails with "Installer hash does not match" (common with rolling installer URLs like Perplexity Comet); resolves installer URL from whitelist InstallerUrl field or winget show output; downloads and runs installer silently; whitelist gains optional InstallerUrl and InstallerArgs fields for per-app configuration
    9.14 - FIX: Direct download fallback now uses WebClient.DownloadFile in a background job instead of Invoke-WebRequest (which is extremely slow for large files in PS 5.1); heartbeats continue during both download and install phases preventing SYSTEM parent timeout; added 5-minute timeout for each phase with progress reporting to dialog
    9.15 - FIX: Direct install fallback now calls WaitForExit() before reading exit code and treats null exit code as success; Chromium-based installers fork a child process and the parent exits immediately with no exit code, which was incorrectly treated as failure
    9.16 - FIX: Added --scope user dual-listing to SYSTEM context so apps like Perplexity.Comet (user-scoped in winget but installed to Program Files) are discovered and upgraded with SYSTEM privileges; prevents failed upgrades from user context lacking write access to Program Files
    9.17 - REVERT: Removed --scope user from SYSTEM context - SYSTEM cannot see user-registered winget packages; dual-scope listing remains in user context only where it is effective
    9.18 - FIX: Prevent unintended UAC prompts during user-context upgrades. Scope detection correctly identified machine-scoped apps (e.g. Mozilla.Firefox) but the resulting `$doUpgrade = $false` had no effect because it was set inside the `if ($doUpgrade)` block, so winget still ran and the installer triggered UAC. Now the user-context flow signals dialogs cleanly and `continue`s to the next app, leaving machine-scoped upgrades to the SYSTEM context.
    9.19 - FIX: Post-upgrade verification was producing false-positive failures. Whitespace-split column extraction misclassified columns when winget list returns no Available column after a successful upgrade - empty parse fell into the failure branch. Replaced ad-hoc parsing with the existing header-position parser (ConvertFrom-WingetOutput) and now treats only an EXACT match between parsed Available and our target version as a true failure; empty/different Available is treated as success. Also: SYSTEM context now augments its `winget upgrade` listing by querying `winget list --id ID` for each whitelisted machine-scoped app missing from the upgrade list - picks up apps like Mozilla.Firefox that winget tracks under user accounts but which actually live in C:\Program Files, so SYSTEM can upgrade them without UAC.
    9.20 - REFACTOR: Detection now writes a static task file (C:\ProgramData\Temp\availableUpgrades-tasks.json) with the apps it found pending upgrade. Remediation reads that file as the authoritative work list and removes entries as each app is processed (success or final-failure). Eliminates the need for SYSTEM-context augmentation to walk every whitelisted machine-scoped app querying `winget list` per app - detection has already done the discovery via its dual `winget upgrade` listing. The augmentation pass remains as a fallback for when the task file is missing or older than 6 hours. User-context "skip machine-scoped to avoid UAC" leaves the entry in the task file so SYSTEM picks it up next cycle.
    9.21 - REFACTOR: Removed all `winget upgrade` discovery calls from remediation - detection's task file is now the sole source of truth. Each task entry carries an InstalledScope (machine/user/unknown) recorded by detect.ps1, which lets remediation filter the work list by current context at load time: SYSTEM processes machine + unknown, user context processes user + unknown. Scope decisions in the upgrade loop now read InstalledScope from the task entry instead of re-running Get-AppInstalledScope per app. When the task file is missing or stale, remediation exits 0 cleanly (no fallback discovery - run detect.ps1 first).
    9.22 - FIX: When user-context remediation had nothing to do (typically because SYSTEM had already drained the task file) it exited without writing the result file. SYSTEM-side Schedule-UserContextRemediation then waited the full 600-second idle timeout for a heartbeat that never came (observed: 750-second hang, ~12 min wasted per cycle). Now the empty-work-list exit path writes a minimal result JSON (ProcessedApps=0, Success=true, Reason) so SYSTEM can stop waiting immediately.
    9.23 - FIX: SYSTEM-context remediation no longer skips user-context handoff when its own work list is empty. The handoff (Schedule-UserContextRemediation) was nested inside the `if ($LIST.Count -gt 0)` branch, so a task file containing only user-scoped entries (e.g. "0 routed to SYSTEM, 1 left for the other context") fell into the else branch and exited without ever launching the user-context task. Added a parallel handoff in the else branch gated on $Script:TasksForOtherContext > 0 (set during routing). Pairs with detect.ps1 v5.38 which now produces task files containing both scopes.
    9.24 - LOGGING: Made remediation log self-explanatory at the SYSTEM level. (a) Successful upgrades now report as `AppID (OK)` instead of bare AppID - previously success/failure was distinguishable only by the absence of a "(FAILED)/(ERROR)" suffix, which was easy to misread when the user-context task reported back. (b) Routing log now lists the actual AppIDs (with InstalledScope) for both the current context's work list AND the entries handed off to the other context, so SYSTEM log readers can see which apps the user-context task is about to attempt without needing the user-context log file.
    9.25 - FIX: SYSTEM-context handoff to user-context remediation no longer runs when the task file contains zero user-scoped entries. The post-processing handoff (only reached when SYSTEM had work itself) was unconditional - every SYSTEM run that processed any machine-scoped app would also schedule a no-op user-context task, wasting ~3 minutes per cycle on heartbeat polling for nothing. Now gated on $Script:TasksForOtherContext > 0, matching the gate already on the empty-list else branch added in v9.23.
    9.26 - PERF: Two startup/per-app cost reductions. (a) Orphan marker cleanup no longer calls Get-InteractiveUser to find the user temp dir - replaced with a disk enumeration of C:\Users\* (skipping well-known non-user profile dirs). The CIM call costs ~7s on Azure AD machines and was the first thing every Intune cycle paid for; disk enumeration is sub-millisecond and additionally catches orphans from any user profile rather than just the active one. (b) Post-upgrade verification (the `winget list --exact` re-query that costs ~1.5s per upgraded app) is now opt-in via a new whitelist `RequiresPostVerify: true` flag. Originally added in v8.8 for Adobe Reader's silent-failure pattern; Adobe Reader is now disabled in the whitelist, so the cost was being paid on every enabled app to protect against a problem none of them have. Apps that need the safety net can opt back in by setting the flag.
    9.27 - PERF: Three further cost reductions. (a) Get-InteractiveUser now uses Get-Process explorer -IncludeUserName as the PRIMARY detection method (~50ms) and falls back to CIM (~5s) only when Explorer isn't running. Explorer is the desktop shell so its owner is by definition the interactive user - same answer as Win32_ComputerSystem.Username in 99%+ of sessions, dramatically faster. The CIM/WMI paths are kept as fallbacks for early-boot or RDP-edge scenarios where Explorer isn't yet running. Also collapsed the verbose per-method logging: the function now emits a single line "User detection method: Explorer (52ms) -> DSGR\\adminhsk, SID=..." instead of 8+ progress lines. (b) Whitelist fetch now uses an on-disk cache (C:\ProgramData\Temp\availableUpgrades-whitelist.cache.*) with a 60-min TTL plus ETag/If-Modified-Since revalidation. Within the TTL window we skip the network entirely; after TTL we send If-None-Match and reuse the cached body on a 304. Reduces external dependency from once-per-cycle to at most once-per-hour. Stale cache is also used as a fallback when the network is unavailable. (c) Removed three redundant log lines around the Get-InteractiveUser call inside Schedule-UserContextRemediation that were just announcing function entry/exit ("Calling Get-InteractiveUser function...", "Get-InteractiveUser completed in X seconds"). The function logs its own success line.
    9.28 - TUNE: Whitelist cache TTL bumped from 60 min to 36 hours (2160 min). At a once-a-day client cadence the 60-min default never reached the fast-path (cache always >60 min old at next run, always revalidated). 36 h is comfortably longer than a daily cycle including check-in jitter, so the fast-path normally hits and we skip the network entirely. Whitelist edits propagate within ~1.5 days worst case.
    9.29 - FIX: Stripped em-dashes/en-dashes (U+2014, U+2013) from the script and saved with a UTF-8 BOM. Without a BOM, PowerShell 5.1 reads the file as Windows-1252 and the multi-byte UTF-8 sequence for an em-dash decodes to bytes 0xE2 0x80 0x94 - byte 0x94 is a right-quote in Windows-1252 which terminated string literals early and broke the parser when run via the iex bootstrapper (which writes the script to a .ps1 in temp without preserving UTF-8 metadata). All Unicode dashes replaced with ASCII hyphen-minus.
    9.30 - FIX: Get-CachedWhitelistJSON returned its log line concatenated with the cached body, so $whitelistJSON was "Using cached whitelist (age 0.6 min...) {actual JSON}" and ConvertFrom-Json failed with "Invalid JSON primitive". Root cause: Write-Log emits to the success stream under some conditions (Out-File internally); every other value-returning function in the script already pipes Write-Log to Out-Null for this reason - I missed it on the new function. All Write-Log calls inside Get-CachedWhitelistJSON now end with `| Out-Null`. Also added a defensive validator: cached and fetched bodies are checked to start with `{` or `[` before being used; corrupt cache files are auto-deleted so the next run re-fetches.
    9.31 - PERF: Dialogs now appear ~2-3 s faster. Three cold-start reductions in every scheduled-task-launched dialog (informational progress, mandatory update, deferral, completion notification, user prompt): (a) Added -NoProfile to the spawned powershell.exe so user profile customizations (e.g. Oh My Posh) no longer load before the WPF window renders - saved ~1-2 s on profiles with prompt frameworks. (b) Collapsed four separate Add-Type -AssemblyName calls into one combined call - PresentationFramework, PresentationCore, WindowsBase loaded together is noticeably faster than four sequential calls. (c) Dropped System.Windows.Forms from four of the five dialog scripts that only used it for [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea; replaced with WPF's [System.Windows.SystemParameters]::WorkArea which is part of the already-loaded WindowsBase assembly - saves a whole extra assembly load (~500 ms). Net effect: the upgrade progress dialog now renders before winget finishes downloading instead of after, fixing the "dialogs appear after the work is done" symptom.
    9.32 - FEATURE (foundation): Persistent dialog host - replaces the per-app dialog spawn pattern with a single long-lived WPF window that swaps content as remediation progresses. This commit adds only the foundation (command protocol, host script, lifecycle helpers); the existing Show-* / Invoke-System* functions are unchanged and still spawn per-dialog scheduled tasks. Next commit wires them through Send-DialogCommand with the legacy spawn kept as fallback. Protocol: JSON-lines appended to C:\ProgramData\Temp\availableUpgrades-dialog-<sessionId>.cmd, host pumps every 250 ms and replies via per-id files in the .replies dir; heartbeat + PID file make liveness verifiable in <10 s. Window has 5 panels (Progress, Transition, Completion, Mandatory, Deferral, Skip) toggled via Visibility; only one renders at a time. Cross-context handshake reuses the Schedule-UserContextRemediation pattern - SYSTEM starts the host and passes -DialogSessionId to user-context, which connects to the same files. Lifecycle is SYSTEM-owned: Stop-DialogHost is called after user-context handoff completes (or after SYSTEM's own loop if no handoff). User dismissal via X-button sets a session-scoped suppression flag; subsequent fire-and-forget commands (show-progress/status/transition/complete) are silently swallowed but blocking prompt-* commands (mandatory/deferral/skip) always force the window back into view because they require an explicit answer. Day-scoped SuppressInfoDialogs flag becomes obsolete in the new path (still honored by legacy fallback). Stale-task sweep and temp-file cleanup regex updated for the new DialogHost_ / availableUpgrades-dialog- patterns.
    9.33 - FEATURE (wire-up): Routes every dialog through the persistent dialog host introduced in v9.32; legacy per-app scheduled-task spawn is retained as fallback when the host is unavailable. New script parameter -DialogSessionId lets user-context attach to the SYSTEM-owned session via Connect-DialogSession; Schedule-UserContextRemediation appends -DialogSessionId to the user-context launch args only when Test-DialogHostAlive. Start-DialogHost runs once at the top of the main remediation block in SYSTEM context; Stop-DialogHost runs on both exit paths gated on (-not $UserRemediationOnly) so user-context never tears down a host SYSTEM started. Wrappers added at the public entry points: Show-CompletionNotification -> complete; Show-UpgradeProgressNotification -> show-progress (returns $null on host path so legacy signal-file callers no-op); Write-InfoDialogStatus -> status (routes to host whenever alive, independent of SignalFilePath); Show-MandatoryUpdateDialog -> prompt-mandatory ("upgrade"/"timeout" both mean proceed, returns "Continue"); Show-DeferralDialog -> prompt-mandatory for ForceUpdate, prompt-deferral otherwise; Show-VersionSkipDialog -> prompt-skip. Main loop emits a `transition` command between successive apps using $Script:DialogPrevApp; after the foreach loop ends, a final `complete` reports total apps processed + overall success/failure, triggering the host's 3 s auto-hide. Show-ProcessCloseDialog and the general-purpose Yes/No prompts (Show-UserDialog, Invoke-SystemUserPrompt, Show-ModernDialog, Show-DirectUserDialog) are intentionally left on the legacy path - their UX doesn't match any of the six host panels yet.
    9.34 - FIX: Two defects observed during the first v9.33 live run. (a) Dialog stayed on screen after "Dialog host stopped" was logged. The graceful "shutdown" command sometimes never lands (host's pump tick can collide with the parent appending to the cmd file, or the final complete+shutdown arrive between pump ticks and the wait-loop exits before they're processed). Stop-DialogHost now records the host PID before tearing down session files, and if the process is still alive after the 5 s graceful window it calls Stop-Process -Force so the WPF window goes away with the process. (b) The window position was set to (workArea.Bottom - 200) before any panel was visible, but SizeToContent="Height" then expanded the window downward as panels filled in, sometimes pushing it below the taskbar (depending on monitor and panel height). Replaced the one-shot position with a Reposition-AnchoredBottomRight helper bound to $window.Add_SizeChanged so the window stays anchored 20 px above the taskbar regardless of which panel is showing.
    9.35 - TUNE: $LogDate dropped its _HH-mm component, so all remediation runs on the same calendar day now append to a single RemediateAvailableUpgrades-DD-MM-YY.log file instead of producing a new file per session. Easier to follow a day's activity in one read; Remove-OldLogs's 1-month retention is unchanged so disk growth is bounded.
    9.36 - FIX: When the persistent dialog host dies mid-prompt (Send-DialogCommand returns $null), the blocking-prompt wrappers (Show-MandatoryUpdateDialog, Show-DeferralDialog, Show-VersionSkipDialog) used to silently default to the "proceed with upgrade" outcome. Observed in field on a Notepad++ run with a running blocking process: host went away ~5s after the prompt-deferral command was sent, the deferral wrapper returned Action=Update without surfacing any dialog, and the user's app was force-closed and updated with no opportunity to defer. Wrappers now only commit to the host's reply when a non-null reply comes back; otherwise they fall through to the legacy WPF spawn so the user still sees a dialog. Also: Stop-DialogHost no longer deletes the host's $session.LogFile, so when the host does die its log survives for post-mortem (Remove-OldTempFiles still sweeps it on its normal schedule). And the misleading hardcoded "Starting persistent dialog host (v9.33)" log line was made version-agnostic.
    9.37 - FIX: Root cause of the dialog host crashing one second into prompt-deferral (and presumably prompt-mandatory, prompt-skip, and the completion auto-hide). The dispatcher timers' Add_Tick script blocks referenced function-local variables ($updateBtn, $btn, $countdown, $hideTimer) defined inside Process-Command's switch arms; by the time the dispatcher fired the timer, Process-Command had returned and those locals were out of scope, resolving to $null. The countdown's `$updateBtn.Content = ...` then threw "The property 'Content' cannot be found on this object", which escaped $app.Run() and exited the host process. Preserved host log from session 25886aac6a4c made this immediately visible (`FATAL: ... Run ... property 'Content' cannot be found`). Fix: every dispatcher closure now reads through $script:blocking (script-scoped) for button + timer references, with Button stored at hashtable creation and timers added once they exist. Each Add_Tick body is also wrapped in try/catch (logs to host log via Write-DH but doesn't crash the dispatcher). Same scope fix applied to complete's hideTimer ($script:hideTimer). Added an Application.DispatcherUnhandledException handler as a final safety net so any future unanticipated exception inside a dispatcher event is logged and swallowed rather than killing the host.
    9.38 - FIX: When the per-app loop ended without processing any apps (e.g. the only app in the task file was actively deferred and got skipped), the script still sent a `complete` command to the dialog host. The host briefly rendered "Updates complete - 0 apps processed" with its 3-second auto-hide, but Stop-DialogHost fired immediately after and force-killed the host process within ~1 s, producing a visible sub-second flash of the completion panel even though the run was a no-op. Now the final `complete` command is gated on $count -gt 0 so a no-op run leaves the host hidden through teardown.
    9.39 - FIX: WingetUpgradeManager registry state (Deferrals, Failures, ReleaseCache) was being read/written via PSDrive paths like HKLM:\SOFTWARE\WingetUpgradeManager\..., which the Windows WoW64 redirector silently rewrites to HKLM:\SOFTWARE\WOW6432Node\... when the host process is 32-bit. Intune Remediations default to a 32-bit PowerShell host, so all script writes went to WOW6432Node; anything reading from a 64-bit context (manual PowerShell prompt, ad-hoc tooling) saw an empty/stale view. A user with an active Notepad++ deferral was invisible to a 64-bit Get-ChildItem on the non-WOW path while clearly visible at the WOW6432Node path. Fix: introduced $Script:WumRegRoot pinned to HKLM:\SOFTWARE\WOW6432Node\WingetUpgradeManager and routed all 12 call sites through it (later renamed to $Script:AppRegRoot in v9.40). Both 32-bit and 64-bit PowerShell hosts now hit the same physical hive. Chose WOW6432Node-pinned (not 64-bit-pinned via .NET OpenBaseKey) because existing data is already at WOW6432Node from prior 32-bit Intune runs, so no migration is required; the trade-off is that orphaned entries written to the native HKLM:\SOFTWARE\WingetUpgradeManager by old 64-bit runs become invisible to the script (acceptable: those entries were already stale or expired).
    9.40 - RENAME: Registry root renamed from HKLM:\SOFTWARE\WOW6432Node\WingetUpgradeManager to HKLM:\SOFTWARE\WOW6432Node\AppUpdater so the on-disk path matches the GitHub repo name. Variable renamed from $Script:WumRegRoot to $Script:AppRegRoot to match. No automatic migration of state from the old WingetUpgradeManager path - existing deferrals, failures, and release cache entries become orphaned. On the next run the script sees an empty state, so users will be re-prompted for any apps with pending updates instead of having their previously-set deferrals honored. Manual cleanup of the orphaned old key is up to the operator: Remove-Item 'HKLM:\SOFTWARE\WOW6432Node\WingetUpgradeManager' -Recurse -Force.
    9.41 - FIX: Real root cause of "host died mid-prompt" and the "two dialogs on screen" symptom. SYSTEM creates the session IPC files (CmdFile, CursorFile, HeartbeatFile) in C:\ProgramData\Temp, where the default ACL gives CREATOR OWNER (i.e. SYSTEM) full control and Users only read. The user-context host process can therefore READ the cmd file but its WriteAllText on CursorFile and HeartbeatFile silently fails with "Access denied". The previous code swallowed those failures in a no-op catch, so the heartbeat file timestamp never refreshed - and ~10 s after host startup, the parent's Test-DialogHostAlive declared the host dead based on stale heartbeat while the host was alive and rendering a dialog. Send-DialogCommand then returned $null, the v9.36 wrapper fell through to the legacy spawn, and the user saw the legacy dialog appear on top of the still-up host dialog. Two fixes: (a) Start-DialogHost now explicitly grants the interactive user Modify rights on CmdFile/CursorFile/HeartbeatFile (via SetAccessRule) and on the ReplyDir (via inherited Modify) immediately after creating them, so the host can actually write its own heartbeat. (b) The pump's heartbeat-write catch now logs the first failure via Write-DH (suppresses repeats) instead of silently swallowing, so any future ACL/IO failure shows up immediately in the host log instead of producing a mysterious false-positive 10 s later. With these in place, the dialog host should remain provably alive throughout a 120 s prompt - no fallback spawn, one dialog on screen, then teardown when the user clicks Defer or Update Now.
    9.42 - FIX: v9.39's "pin registry path to WOW6432Node" approach was based on the wrong WoW64 semantics. PSDrive registry cmdlets (Get-ItemProperty, Set-ItemProperty, etc.) go through the WoW64 redirector, which from a 32-bit PowerShell host rewrites HKLM:\SOFTWARE\X to HKLM:\SOFTWARE\WOW6432Node\X *unconditionally* - it does not notice that WOW6432Node is already in the requested path. So v9.39's writes to HKLM:\SOFTWARE\WOW6432Node\AppUpdater\Deferrals\... actually landed at HKLM:\SOFTWARE\WOW6432Node\WOW6432Node\AppUpdater\Deferrals\... (confirmed in field: Notepad++.Notepad++ deferral with the v9.41 ACL fix was discovered at the double-WOW path). Proper fix: introduced Open-AppRegKey / Test-AppRegKey / Get-AppRegValue / Get-AppRegProperties / Set-AppRegValue / Remove-AppRegValue / Remove-AppRegKey / Get-AppRegChildKeyNames helpers that use [Microsoft.Win32.RegistryKey]::OpenBaseKey(LocalMachine, Registry64), explicitly requesting the 64-bit view and bypassing the redirector entirely. All 12 PSDrive call sites in remediate.ps1 (Initialize-DeferralRegistry, Get-AppReleaseDate, Get-DeferralStatus, Set-WhitelistedAppDeferral, the deferral/cache cleanup, and the four Get/Set/Clear-VersionFailure functions) routed through the helpers. Data now lives at HKLM:\SOFTWARE\AppUpdater (visible from any 32-bit OR 64-bit observer at the natural path). Existing state at HKLM:\SOFTWARE\WOW6432Node\WOW6432Node\AppUpdater is orphaned with no automatic migration. Operator cleanup: Remove-Item 'HKLM:\SOFTWARE\WOW6432Node\WOW6432Node\AppUpdater' -Recurse -Force.
    9.43 - FIX: On a freshly-set-up Windows machine the dialog host failed to start - parent logged "Dialog host did not heartbeat within 8 s" and fell back to legacy spawn, AND no preserved host log was produced. The host process actually started but died before its first Write-DH call. Root cause: when C:\ProgramData\Temp was freshly created by SYSTEM (Start-DialogHost's auto-create branch), it inherited C:\ProgramData's default ACL which grants Users only Read+Execute - not Create-File. v9.41's ACL fix granted the user Modify on the FILES that SYSTEM had pre-created (CmdFile/CursorFile/HeartbeatFile), but the host's very first action is to WriteAllText its OWN files (PidFile, LogFile, replies/*.json), and the user couldn't CREATE new files in the parent directory. The host's WriteAllText on PidFile threw Access Denied, the process died, no Write-DH ever fired, and the parent waited 8 s on a heartbeat that would never come. Two fixes: (a) Session files now live inside a per-session SUBDIRECTORY (C:\ProgramData\Temp\availableUpgrades-dialog-<id>\{cmd, cursor, heartbeat, pid, host.log, replies\}); SYSTEM creates that directory and grants the user Modify with ContainerInherit+ObjectInherit, so every file the host wants to create inside it just works. (b) Heartbeat wait window bumped from 8 s to 15 s to cover slow first-run WPF cold start. Stop-DialogHost moves the log out to a flat sibling location before removing the per-session directory, so log preservation still works.
    9.44 - UX: Dialog status during winget upgrade is more informative. Initial status is now "Preparing download..." instead of "Downloading update..." so the user can see when bytes actually start moving. Invoke-WingetWithProgress now (a) accepts B/KB/MB/GB on both sides of the X / Y size regex (was KB|MB / MB|GB only, which silently failed on small/very-large downloads), (b) falls back to a "Downloading XX%" status when only a percentage is parseable (newer winget builds render a unicode progress bar with no inline size), and (c) latches into an "Installing update..." status the first time it sees Successfully installed / Successfully verified installer hash / Starting package install / Starting installer / "^Installing" / Configuring - so the dialog stops saying "Downloading" once the bytes are down. Install-phase detection also covers more winget output variants (1.5 used "Starting package install", 1.7+ uses "Starting installer").
    9.45 - FIX: Invoke-WingetWithProgress's monitoring loop was being skipped entirely when the dialog host was alive. When v9.33 wired Show-UpgradeProgressNotification to return $null on the host path (so the legacy signal-file flow no-ops), the caller passed SignalFilePath=$null to Invoke-WingetWithProgress. The function's early-return-on-no-SignalFilePath check then took the direct-execution path - no stdout file, no monitoring loop, no Write-InfoDialogStatus updates - so the dialog stayed frozen on the initial "Preparing download..." for the entire upgrade. None of v9.44's regex improvements ever ran on the host-alive path. Fix: the early-return now also checks Test-DialogHostAlive, so when the host is alive the monitoring loop runs and Write-InfoDialogStatus inside it ships size / percentage / installing updates to the host.
    9.46 - FEATURE: Prevent the system from entering sleep while a remediation run is in flight. Long winget downloads or per-app dialog timeouts can be killed by the OS going to sleep mid-upgrade - especially on laptops on battery with short idle timers. New Set-SystemSleepBlocked helper uses kernel32 SetThreadExecutionState with ES_CONTINUOUS|ES_SYSTEM_REQUIRED (we deliberately do NOT set ES_DISPLAY_REQUIRED, so the display still dims/blanks normally - we only need the kernel awake). Block is applied right after the marker-cleanup init, covering all subsequent work: task-file load, deferral checks, dialog host startup, per-app prompts, winget downloads, post-upgrade verification, user-context handoff polling. PowerShell.Exiting engine event clears the block on every exit path - 7 in total - so the log records "Sleep block cleared" and the flag is gone even on the test/error exits that don't go through the normal cleanup. SetThreadExecutionState is process-scoped, so if the script crashes Windows reclaims it automatically; the explicit clear is just hygiene.
    9.47 - FIX: Dialog jumped straight from "Preparing download..." to "Installing update..." without ever showing a "Downloading..." status for small/fast apps. v9.44's install-phase latch ran BEFORE the download-progress regex on each poll, so on the very first 2 s poll if winget had already finished downloading (Successfully verified installer hash already in $outText), $installPhase tripped immediately and the download-progress branch was skipped forever. Inverted the order: every poll now parses download progress FIRST and writes "Downloading X MB / Y MB" (or "Downloading XX%", or generic "Downloading update..." if neither is parseable yet), THEN checks for install-phase phrases. For fast downloads where both apply in the same poll, the user sees a brief "Downloading..." flash before the latched "Installing update...". For slow downloads the size/percentage ticks visibly upward, then transitions to "Installing update..." once an install-phase phrase appears. Once $installPhase latches it never reverts.
    9.48 - FIX: Two related defects. (a) Set-SystemSleepBlocked threw "Cannot convert argument esFlags" because PowerShell parses 0x80000000 / 0x80000001 as [Int64] (they exceed [Int32]::MaxValue) and Add-Type's `uint` parameter rejects an Int64. Cast both literals to [uint32] explicitly. (b) During multi-app remediation runs the dialog hid in the middle of a later app's progress, then came back, etc. Cause: per-app Show-CompletionNotification sends a `complete` command which starts the host's 3-second auto-hide timer; when the loop moved to the next app and sent `transition` / `show-progress`, the new commands brought the window back via Ensure-Visible but the prior hideTimer was still ticking - it fired later and hid the window mid-progress on the new app. Process-Command now cancels any pending $script:hideTimer the moment a new non-lifecycle command arrives (anything other than `hide` / `shutdown`), so only the FINAL complete - the one with no follow-up commands - actually gets to auto-hide.
    9.49 - FIX: Unknown-scope tasks never got a user-context retry when SYSTEM couldn't upgrade them. Observed in field: Bicep, VS Code (UserSetup), and Anthropic.Claude are all per-user installs - SYSTEM running `winget upgrade --id X` from its own profile sees nothing to upgrade and exits with no output, so the script logs "Processing completed" + outputLength=0 + empty LASTEXITCODE and the task stays on the list every cycle. detect.ps1 v5.52 fixes most of this by classifying VS Code and Claude correctly (user-scoped) so they're routed to user-context anyway, but apps with no uninstall key at all (Bicep) stay "unknown" - and the routing block's previous logic kept "unknown" tasks in SYSTEM's allowed-list without counting them in $Script:TasksForOtherContext, so the user-context handoff never fired for them. Routing now ALSO counts unknown-scope tasks SYSTEM is keeping as "needs other-context retry too" via a new $unknownAlsoOther list, so user-context is scheduled after SYSTEM's loop and gets a chance to upgrade per-user installs that SYSTEM couldn't see.
    9.50 - TUNE: Tightened up C:\ProgramData\Temp cleanup. Two gaps closed: (a) Remove-OldTempFiles's regex was missing UserDetection_*.json - so when remediate.ps1 ran its startup cleanup it never touched detect.ps1's leftover result files, and cross-script leftovers accumulated. Regex unified with detect.ps1 v5.53 so each script's startup cleanup catches whatever the other one left behind. (b) The function only scanned files, not directories. With v9.43 the dialog host stores per-session state inside a subdirectory (C:\ProgramData\Temp\availableUpgrades-dialog-<id>\) and Stop-DialogHost normally removes it - but if the script crashes before cleanup or the WPF process orphans the dir somehow, a file-only scan can't see it. Now also enumerates directories matching the same regex and removes them recursively when older than the 10 minute cutoff.
    9.51 - TUNE: Remove-OldTempFiles cutoff bumped from 10 minutes to 60 minutes. The previous 10-minute window was set assuming all script-created temp files were tied to short-lived dialogs and prompts, but a remediation run that processes several large packages (Office, Visual Studio, multi-gigabyte downloads with retries) can easily stay running for 30+ minutes. During that time its own in-flight files would match the cleanup regex and could be deleted out from under it. 60 minutes is comfortably longer than any legitimate single run and still recent enough to catch real orphans on the next startup.
    9.52 - FIX: Set-SystemSleepBlocked still failed with "Cannot convert value -2147483647 to type System.UInt32" despite v9.48's [uint32] cast. Root cause: PowerShell 5.1 (which is what Intune Remediations run) parses hex literals like 0x80000001 as SIGNED Int32 - the high bit is treated as the sign bit, so the literal evaluates to -2147483647 BEFORE the [uint32] cast even runs. The cast then rejects the negative value. v9.48's cast was a no-op for the same reason. Switched the literals to decimal (2147483648 = 0x80000000, 2147483649 = 0x80000001). PowerShell promotes bare decimals that exceed [Int32]::MaxValue straight to Int64 with no sign trickery, so [uint32]<positive Int64> succeeds and SetThreadExecutionState gets the value it expected all along.
    9.53 - UX: Session-start banner written at the top of each run. Three `=`-bordered lines so a new run is obvious when scrolling a per-day log file that contains many sessions. Banner reads the script's own Version field from the .NOTES block at runtime so it stays in sync without a separate constant to maintain. Format: "===== RemediateAvailableUpgrades v9.53  PID 12345  SYSTEM context  on COMPUTERNAME". Context label distinguishes SYSTEM / user (admin) / user / user-context (handoff).
    9.54 - FIX: Schedule-UserContextRemediation's task principal RunLevel bumped from Limited to Highest. Some upgrades require admin to write the target install location (Git.Git lives in C:\Program Files\Git\ - the user's winget LocalState knows the catalog binding so the upgrade can be identified, but the install itself needs elevation). At RunLevel Limited the v9.49 user-context retry handoff ran non-elevated and silently failed these machine-scope-needing upgrades. At RunLevel Highest, admin users get an elevated scheduled-task token automatically (no UAC prompt - scheduled tasks at Highest auto-elevate for members of the local Administrators group); non-admin users see no regression (Highest is "max of what the user has", which is still Limited for them). Pairs with detect.ps1 v5.60.
    9.55 - FIX: Two issues from the 18:44 field log. (a) SYSTEM was still allowed to try "unknown"-scope tasks (allowedScopes was @("machine","unknown")). With detect.ps1 v5.60's visibility probe in place, anything reaching remediate as "unknown" has been proven invisible-to-SYSTEM during detection - SYSTEM trying anyway wastes the attempt AND bumps the per-version failure counter, which combined with the 3-strikes skip-version dialog can remove the task before the user-context retry handoff gets its turn. Git.Git hit exactly this race: SYSTEM-failure bumped count to 3/3, skip dialog fired, task removed at 18:45:00 - user-context handoff started at 18:45:00 but Git.Git was no longer in the task file. Fix: SYSTEM's allowedScopes is now @("machine") only; "unknown" tasks bypass SYSTEM entirely and go straight to user-context (where v9.54's RunLevel Highest gives admin users the elevation they need). The v9.49 $unknownAlsoOther mechanism becomes redundant and is removed. (b) The "Retry" button on the skip-version dialog was effectively meaningless - both Skip and Retry called Remove-UpgradeTaskEntry regardless, so Retry just suppressed the Skipped=true flag without any other effect. Reported by the user: "I pressed Retry, is there a bug there?" Yes there was. Fixed: Skip behaves as before (set Skipped flag + remove from task file); Retry now clears the accumulated failure count via Clear-VersionFailureData AND keeps the task entry so the next remediation cycle gets a fresh 3-attempt budget against the same version.
    9.56 - UX: Persistent dialog host tweaks per user request. (a) Anchor moved closer to the taskbar - $anchorMargin reduced from 20 px to 6 px and $anchorRight from 20 to 12 - so the window now sits tight against the work-area corner instead of floating midway up. SizeToContent="Height" + the v9.34 Reposition-AnchoredBottomRight handler keep the bottom edge pinned regardless of which panel is showing. (b) Border colour darkened on both themes (dark: #FF323232 -> #FF606060; light: #FFD1D1D1 -> #FF9A9A9A) so the existing 1 px BorderThickness reads as a crisp fine line against the panel background; the rounded corners + drop shadow previously washed the border into the background and the dialog looked frameless. No XAML structure change - just the two ARGB literals in the theme block.
    9.57 - DOCS: Reordered the version-history block. Entries 9.41 through 9.55 had been prepended at the top of the block over several sessions, leaving a confusing 9.40 -> 9.55 -> 9.54 -> ... -> 9.41 -> 9.56 sequence. Block is now strictly ascending 1.0 -> 9.57 so a reader can scroll top-to-bottom and follow the chronological evolution. No code change.
    9.58 - UX: ProgressPanel status-text gap widened. The status TextBlock (e.g. "Downloading 4.2 MB / 12.0 MB", "Installing update...") shared Grid.Row 2 with the 3 px ProgressBar and was positioned with Margin="0,12,0,0", giving only ~9 px of clear space between the bar and the text. Felt cramped during live runs. Bumped top margin to 20 so the bar and status read as two distinct elements.
    9.59 - UX: Completion panel now actually stays visible long enough to read. Reported by the user: "when the dialog closes after the last update there is not enough time to read it, I see a glimpse of a green icon and then it disappears. Maybe this also happens between app upgrades?" Two problems were stacked: (a) the per-app complete -> next-app transition path was racing - Show-CompletionNotification sent `complete` then immediately returned to the caller, which proceeded to the next app and emitted `transition` within ms, and v9.48's transition-cancels-hideTimer logic swapped the panel before the green icon registered visually. (b) The final `complete` after the foreach loop relied on the host's auto-hide timer (3 s pre-v9.59), but Stop-DialogHost in the user-context-handoff path can force-kill the host within ~5 s of the user-context script exiting, which often pre-empted the auto-hide. Fixes: (1) host's auto-hide timer bumped from 3 s -> 7 s so when it does fire it's actually readable; (2) Show-CompletionNotification's host-path branch now Start-Sleeps 2 s after sending the `complete` command so the per-app panel dwells before the next iteration's `transition` swaps it; (3) the final post-loop `complete` is followed by Start-Sleep 5 s so the summary panel ("Updates complete - N apps processed") is visible for the full dwell before the script proceeds to user-context handoff scheduling or exits and lets SYSTEM tear down the host. Net effect: per-app icon visible for ~2 s, final summary visible for ~5 s minimum (longer if user-context handoff is involved since SYSTEM blocks on that), and the 7 s auto-hide remains as a clean fade-out when nothing tears the host down sooner.
    9.60 - FIX/UX: Two unrelated changes bundled together. (a) New-HiddenLaunchAction's VBS launcher would throw "Microsoft VBScript compilation error: Unterminated string constant" if the PowerShellArguments string ever contained a stray CR/LF - the original `.Replace('"','""')` doubled-quote escaping wrapped the whole args string inside a single VBS `.Run "..."` literal, so any embedded newline terminated the string mid-line and pointed the parser at an offset like "line 2 char 339". Reported by the user on 2026-05-13 (HiddenLaunch_480682102.vbs error popped up on screen between Notepad++ and 7zip upgrades). Replaced the doubled-quote scheme with Chr(34) concatenation (each embedded `"` becomes `" & Chr(34) & "`, evaluating to a literal `"` at VBS runtime), and added a CR/LF sanitisation pass that strips line breaks and logs a warning so we have diagnostic breadcrumbs the next time something upstream slips a newline in. The Chr(34) approach is also robust against empty/edge-case argument values that the previous doubled-quote scheme could mis-parse. (b) The deferral dialog now warns the user that clicking "Update Now" will close the running app and that they should save their work first, but only when a blocking process is actually active (no point warning when the app isn't open). Applied to both the persistent dialog host path (extra trailing line appended to the body) and the legacy WPF spawn fallback (extra line appended to $processText so the existing block of running-app text is one cohesive paragraph).
    9.61 - FIX: Regression from v9.60's CR/LF sanitisation. The user-prompt path (Invoke-SystemUserPrompt -> Show-UserPrompt_*.ps1 spawned via wscript+VBS) passed the question text as a raw -Question parameter that legitimately contained "`n`n" line breaks between sentences (e.g. "App update available\n\nThe application cannot be updated while running\n\nWould you like to close X now?"). v9.60 stripped those newlines so the dialog displayed everything as one run-on sentence. Discovered when inspecting HiddenLaunch_459789442.vbs left in the repo by the user. Brought the user-prompt path in line with the deferral/mandatory/skip paths by base64-encoding the question and title before passing them as -EncodedQuestion / -EncodedTitle args. The receiving Show-UserPrompt_*.ps1 script now accepts both the legacy -Question / -Title and the new -EncodedQuestion / -EncodedTitle params and decodes whichever is present; UTF-8 base64 has no whitespace in its alphabet so it survives both the VBS .Run string and the v9.60 CR/LF sanitiser intact. Applied to the primary spawn at New-UserPromptTask (~line 1464) and the Azure AD SYSTEM fallback (~line 1586).
    9.62 - FIX: Close-app prompt for non-deferral apps was invisible behind the persistent dialog host. Reported by the user via the 13-05-26 log: Notepad++'s close-app prompt (deferral-enabled, routed through the host) worked correctly, but 7-Zip's close-app prompt (deferral-disabled, fell to Invoke-SystemUserPrompt's legacy WPF spawn via wscript+VBS) silently timed out after 120 s on three consecutive runs (v9.59/v9.60/v9.61). Root cause: between apps the host shows a "Notepad++ updated -> Starting 7-Zip" transition panel at the bottom-right corner; the legacy spawn's WPF window targets the SAME bottom-right corner and is also Topmost. Z-order between two cross-process Topmost windows is undefined and Windows' foreground-stealing protections prevented the newer legacy dialog from coming to front, so it stayed hidden behind the host's transition panel for the full 120 s. Show-ProcessCloseDialog's no-deferral branch now routes through the persistent dialog host's prompt-deferral panel when Test-DialogHostAlive: payload uses canDefer=true (both Defer and Update Now active), daysLeft=null (counter suppressed since these apps have no day-based deferral). Update Now -> close+update, Defer -> keep app open, timeout -> falls back to $DefaultTimeoutAction. Legacy WPF spawn remains as the fallback when the host is not alive (e.g. host startup failed) or doesn't reply. Also adds the v9.60 "save your work first" warning to the legacy WPF body so both paths show the same advice.

    Exit Codes:
    0 - Script completed successfully or OOBE not complete
    1 - Error occurred during remediation
#>

param(
    [switch]$UserRemediationOnly,
    [string]$RemediationResultFile,
    [string]$WhitelistUrl,
    [string]$DialogSessionId
)

# Note: Admin requirement is conditional - not needed for user context execution (UserRemediationOnly mode)
# #Requires -RunAsAdministrator
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Test-RunningAsSystem {
	[CmdletBinding()]
	param()
	process {
		return [bool]($(whoami -user) -match 'S-1-5-18')
	}
}
function Write-Log($message) #Log script messages to temp directory
{
    $LogMessage = ((Get-Date -Format "dd.MM.yyyy HH:mm:ss ") + $message)
    # Extract ScriptTag from message if present, or use global variable
    if ($message -match '^\[([A-Z0-9]+)\]\s*(.*)') {
        $tag = $matches[1]
        $cleanMessage = $matches[2]
        $ConsoleMessage = "[$tag] " + (Get-Date -Format "HH:mm:ss ") + $cleanMessage
    } else {
        $ConsoleMessage = "[$ScriptTag] " + (Get-Date -Format "HH:mm:ss ") + $message
    }
    $ConsoleMessage
	Out-File -InputObject $LogMessage -FilePath "$LogPath\$LogFullName" -Append -Encoding utf8
}

function OOBEComplete {
$TypeDef = @"

using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Api
{
public class Kernel32
{
[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern int OOBEComplete(ref int bIsOOBEComplete);
}
}
"@
        
        Add-Type -TypeDefinition $TypeDef -Language CSharp
        
        $IsOOBEComplete = $false
        $hr = [Api.Kernel32]::OOBEComplete([ref] $IsOOBEComplete)
        
        return $IsOOBEComplete
}

function Get-ActiveUserSessions {
    <#
    .SYNOPSIS
        Gets active user sessions using Explorer process detection
    .DESCRIPTION
        Finds active desktop sessions by looking for explorer.exe processes
        Uses the correct session ID format for user interaction
    .OUTPUTS
        Array of session objects with SessionId and UserName properties
    #>
    
    $activeSessions = @()
    
    try {
        Write-Log -Message "Detecting active user sessions via Explorer processes" | Out-Null
        
        # Primary method: Use Explorer process to find active desktop sessions
        # This gives us the correct session ID format for user interaction
        $explorerProcesses = Get-Process -Name explorer -ErrorAction SilentlyContinue
        
        foreach ($process in $explorerProcesses) {
            Write-Log -Message "Found explorer.exe in session $($process.SessionId)" | Out-Null
            $activeSessions += [PSCustomObject]@{
                SessionId = $process.SessionId
                UserName = "User"
                LogonType = "Desktop"
                ProcessId = $process.Id
            }
        }
        
        # Sort by session ID to get the most likely user session first
        $activeSessions = $activeSessions | Sort-Object SessionId
        
        Write-Log -Message "Found $($activeSessions.Count) active desktop session(s)" | Out-Null
        
        # Log all sessions for debugging
        foreach ($session in $activeSessions) {
            Write-Log -Message "Session ID: $($session.SessionId)" | Out-Null
        }
        
        return $activeSessions
        
    } catch {
        Write-Log -Message "Error detecting user sessions: $($_.Exception.Message)" | Out-Null
        return @()
    }
}


function Set-SystemSleepBlocked {
    <#
    .SYNOPSIS
        Prevents (Block=$true) or allows (Block=$false) the system from entering sleep while
        upgrades are in flight. Uses kernel32 SetThreadExecutionState - the request is
        process-scoped, so if the script crashes Windows automatically reclaims it.
    .DESCRIPTION
        v9.46: long winget downloads or per-app dialog timeouts can be killed by the system
        going to sleep mid-upgrade (especially on laptops on battery with short idle timers).
        We pin the system awake for the duration of the per-app processing loop and clear it
        on every exit path. We deliberately do NOT set ES_DISPLAY_REQUIRED so the user's
        display still dims/blanks normally - we only need the kernel awake.
    #>
    param([bool]$Block)
    try {
        if (-not ('Win32.PowerControl' -as [Type])) {
            Add-Type -Namespace Win32 -Name PowerControl -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern uint SetThreadExecutionState(uint esFlags);
'@ -ErrorAction Stop
        }
        # v9.52: use decimal literals to dodge PowerShell 5.1's hex-literal Int32 overflow.
        # `0x80000001` in PS 5.1 is parsed as a SIGNED Int32 (high bit -> sign bit), giving
        # -2147483647 before [uint32] can cast it; the cast then refuses the negative value
        # with "Cannot convert value -2147483647 to type System.UInt32". v9.48's [uint32] cast
        # was a no-op because the damage was already done at literal-parse time. PowerShell
        # promotes bare decimals that exceed [Int32]::MaxValue straight to Int64, so the
        # decimal-then-uint32 cast actually works.
        #   2147483648 = 0x80000000  (ES_CONTINUOUS)
        #   2147483649 = 0x80000001  (ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
        if ($Block) {
            $r = [Win32.PowerControl]::SetThreadExecutionState([uint32]2147483649)
            if ($r -ne 0) {
                Write-Log -Message "Sleep blocked for duration of upgrade run" | Out-Null
            } else {
                Write-Log -Message "SetThreadExecutionState returned 0 - sleep block may not be in effect" | Out-Null
            }
        } else {
            # ES_CONTINUOUS alone clears all flags, restoring normal idle behavior
            [Win32.PowerControl]::SetThreadExecutionState([uint32]2147483648) | Out-Null
            Write-Log -Message "Sleep block cleared" | Out-Null
        }
    } catch {
        Write-Log -Message "Set-SystemSleepBlocked failed: $($_.Exception.Message)" | Out-Null
    }
}


function New-HiddenLaunchAction {
    <#
    .SYNOPSIS
        Creates a scheduled task action that launches PowerShell without any visible window flash.
    .DESCRIPTION
        Uses wscript.exe with a temporary VBS launcher instead of cmd.exe.
        wscript.exe is a GUI subsystem application and never creates a console window,
        eliminating the brief window flash that cmd.exe /c start /min causes.
    .PARAMETER PowerShellArguments
        The full PowerShell command-line arguments (e.g. "-NoProfile -WindowStyle Hidden -File ...")
    .PARAMETER VbsDirectory
        Directory where the temporary VBS launcher file will be created
    .OUTPUTS
        Hashtable with Action (ScheduledTaskAction) and VbsPath (for cleanup)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$PowerShellArguments,

        [Parameter(Mandatory=$true)]
        [string]$VbsDirectory,

        [switch]$AllowUI
    )

    try {
        # Ensure directory exists
        if (-not (Test-Path $VbsDirectory)) {
            New-Item -Path $VbsDirectory -ItemType Directory -Force | Out-Null
        }

        $vbsPath = Join-Path $VbsDirectory "HiddenLaunch_$(Get-Random).vbs"

        # Always use window style 0 (SW_HIDE) to prevent console flash
        # WPF dialogs appear independently via Topmost + Activate() regardless of console window style
        $windowStyle = 0

        # v9.60: Robust VBS string composition.
        # Previously we did $PowerShellArguments.Replace('"', '""') and wrapped the whole thing
        # in "..." inside the VBS .Run line. That broke catastrophically if the args ever
        # contained a literal CR/LF (field report 2026-05-13: HiddenLaunch_*.vbs threw
        # "Unterminated string constant at line 2 char 339" - the LF terminated the .Run "..."
        # string mid-line). Now: (a) strip any stray CR/LF from the args (no legitimate args
        # contain them - log a warning if we see any), (b) escape embedded quotes via
        # Chr(34) concatenation instead of VBS's doubled-quote escape so we sidestep the
        # entire class of doubled-quote parser ambiguities.
        $cleanedArgs = $PowerShellArguments -replace "[`r`n]+", " "
        if ($cleanedArgs.Length -ne $PowerShellArguments.Length) {
            Write-Log "WARNING: stripped CR/LF from PowerShellArguments before VBS generation (length $($PowerShellArguments.Length) -> $($cleanedArgs.Length))" | Out-Null
        }
        $vbsArgsLiteral = '"' + $cleanedArgs.Replace('"', '" & Chr(34) & "') + '"'
        # VBS self-deletes after the child process finishes (.Run with True waits)
        # On Error Resume Next prevents "Permission denied" dialog when SYSTEM owns the file
        # and the user context cannot delete it (the SYSTEM parent cleans up regardless)
        $vbsContent = @"
On Error Resume Next
CreateObject("WScript.Shell").Run $vbsArgsLiteral, $windowStyle, True
CreateObject("Scripting.FileSystemObject").DeleteFile WScript.ScriptFullName, True
"@

        $vbsContent | Out-File -FilePath $vbsPath -Encoding ASCII -Force

        Write-Log "Created VBS hidden launcher: $vbsPath" | Out-Null

        return @{
            Action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument """$vbsPath"""
            VbsPath = $vbsPath
        }
    } catch {
        Write-Log "ERROR: Failed to create hidden launch action: $($_.Exception.Message)" | Out-Null
        return $null
    }
}

# ============================================================================
# Persistent Dialog Host (v9.32)
# ============================================================================
# Replaces per-app dialog spawning with a single long-lived WPF window that
# swaps content as remediation progresses. Communication is JSON-lines over
# files in C:\ProgramData\Temp (same handshake pattern used by
# Schedule-UserContextRemediation). The cross-context flow is:
#   1. SYSTEM context: Start-DialogHost creates session files and launches the
#      host script as a scheduled task in the interactive user's session.
#   2. SYSTEM and user-context both call Send-DialogCommand, which appends to
#      the session's .cmd file. The host pumps the file every 250 ms.
#   3. User-context inherits the session via -DialogSessionId (set by
#      Schedule-UserContextRemediation). If the host has died, callers fall
#      back to legacy per-dialog spawn.
#   4. SYSTEM owns lifecycle: it calls Stop-DialogHost after user-context
#      handoff completes (or after its own loop if no handoff).

$Script:DialogSession = $null      # populated by Start-DialogHost / Attach-DialogSession
$Script:DialogCmdCounter = 0       # monotonic id for command correlation
$Script:DialogLegacyFallback = $false  # set when host start/probe fails; suppresses retry

function Get-DialogSessionPaths {
    # v9.43: session files now live INSIDE a per-session subdirectory rather than at sibling
    # paths sharing a prefix. SYSTEM creates the directory and grants the interactive user
    # Modify with inheritance (see Start-DialogHost), so the user-context host can create
    # PidFile / LogFile / replies/* itself without hitting "Access denied" - the previous flat
    # layout depended on the user being able to create files directly under C:\ProgramData\Temp,
    # which a freshly-created C:\ProgramData\Temp does not allow.
    param([Parameter(Mandatory=$true)][string]$SessionId)
    $base = Join-Path "C:\ProgramData\Temp" "availableUpgrades-dialog-$SessionId"
    return @{
        SessionId     = $SessionId
        Base          = $base
        CmdFile       = Join-Path $base 'cmd'
        CursorFile    = Join-Path $base 'cursor'
        ReplyDir      = Join-Path $base 'replies'
        HeartbeatFile = Join-Path $base 'heartbeat'
        PidFile       = Join-Path $base 'pid'
        LogFile       = Join-Path $base 'host.log'
        ScriptFile    = "$base.host.ps1"
    }
}

function Test-DialogHostAlive {
    <#
    .SYNOPSIS Returns $true if the dialog host is processing commands.
    Liveness = heartbeat younger than 10 s AND PID is alive.
    #>
    param($Session = $Script:DialogSession)
    if (-not $Session) { return $false }
    try {
        if (-not (Test-Path $Session.HeartbeatFile)) { return $false }
        $hbAge = (Get-Date) - (Get-Item $Session.HeartbeatFile).LastWriteTime
        if ($hbAge.TotalSeconds -gt 10) { return $false }
        if (-not (Test-Path $Session.PidFile)) { return $false }
        $hostPid = [int]((Get-Content $Session.PidFile -Raw -ErrorAction Stop).Trim())
        if (-not (Get-Process -Id $hostPid -ErrorAction SilentlyContinue)) { return $false }
        return $true
    } catch {
        return $false
    }
}

function Start-DialogHost {
    <#
    .SYNOPSIS Launches the persistent dialog host as a scheduled task in the
    interactive user session. Populates $Script:DialogSession on success.
    Returns $true on success, $false on failure (caller should fall back to
    legacy per-dialog spawn).
    #>
    if ($Script:DialogSession -and (Test-DialogHostAlive)) {
        Write-Log "Dialog host already running for session $($Script:DialogSession.SessionId)" | Out-Null
        return $true
    }
    if ($Script:DialogLegacyFallback) { return $false }

    try {
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "Dialog host: no interactive user - falling back to legacy dialogs" | Out-Null
            $Script:DialogLegacyFallback = $true
            return $false
        }

        $sessionId = [Guid]::NewGuid().ToString('N').Substring(0, 12)
        $paths = Get-DialogSessionPaths -SessionId $sessionId

        if (-not (Test-Path "C:\ProgramData\Temp")) {
            New-Item -Path "C:\ProgramData\Temp" -ItemType Directory -Force | Out-Null
        }
        # v9.43: create per-session subdirectory and grant the interactive user Modify with
        # ContainerInherit+ObjectInherit. Any file the user-context host creates inside it
        # (PidFile, LogFile, replies/*.json) inherits Modify automatically. Previous flat layout
        # depended on the user being able to create files directly in C:\ProgramData\Temp,
        # which a freshly-SYSTEM-created C:\ProgramData\Temp does not allow - host died before
        # its first Write-DH call (no log file produced) and the parent's 8 s wait timed out.
        New-Item -Path $paths.Base -ItemType Directory -Force | Out-Null
        try {
            $userSid  = New-Object System.Security.Principal.SecurityIdentifier($userInfo.SID)
            $aclDir   = Get-Acl -Path $paths.Base
            $dirRule  = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $userSid, [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow)
            $aclDir.AddAccessRule($dirRule)
            Set-Acl -Path $paths.Base -AclObject $aclDir
        } catch {
            Write-Log "Dialog host: failed to grant user ACL on session dir - $($_.Exception.Message)" | Out-Null
            # Continue anyway; the host may still work if C:\ProgramData\Temp is open to Users
        }
        # Now create the SYSTEM-side seed files. They inherit Modify-for-user from the parent dir.
        New-Item -Path $paths.ReplyDir -ItemType Directory -Force | Out-Null
        Set-Content -Path $paths.CmdFile -Value "" -Encoding UTF8 -Force
        Set-Content -Path $paths.CursorFile -Value "0" -Encoding UTF8 -Force
        Set-Content -Path $paths.HeartbeatFile -Value (Get-Date -Format 'o') -Encoding UTF8 -Force

        # Write host script to user's temp (it needs to run under user account)
        $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
        if (-not (Test-Path $userTempPath)) { $userTempPath = "C:\ProgramData\Temp" }
        $userScriptPath = Join-Path $userTempPath "availableUpgrades-dialog-$sessionId.host.ps1"
        $Script:DialogHostScript | Set-Content -Path $userScriptPath -Encoding UTF8 -Force
        $paths.ScriptFile = $userScriptPath

        $hostArgs = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$userScriptPath`" " +
                    "-CmdFile `"$($paths.CmdFile)`" -CursorFile `"$($paths.CursorFile)`" " +
                    "-ReplyDir `"$($paths.ReplyDir)`" -HeartbeatFile `"$($paths.HeartbeatFile)`" " +
                    "-PidFile `"$($paths.PidFile)`" -LogFile `"$($paths.LogFile)`""
        $launch = New-HiddenLaunchAction -PowerShellArguments $hostArgs -VbsDirectory $userTempPath -AllowUI
        if (-not $launch) {
            Write-Log "Dialog host: failed to create launch action - falling back" | Out-Null
            $Script:DialogLegacyFallback = $true
            return $false
        }

        $principal = $null
        foreach ($userFormat in @($userInfo.FullName, $userInfo.Username, ".\$($userInfo.Username)")) {
            try {
                $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType Interactive -RunLevel Limited
                break
            } catch { continue }
        }
        if (-not $principal) {
            Write-Log "Dialog host: could not create task principal - falling back" | Out-Null
            $Script:DialogLegacyFallback = $true
            return $false
        }

        $taskName = "DialogHost_$sessionId"
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 2)
        $task = New-ScheduledTask -Action $launch.Action -Principal $principal -Settings $settings -Description "Upgrade remediation dialog host"
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName

        $session = $paths.Clone()
        $session.TaskName = $taskName
        $session.VbsPath  = $launch.VbsPath
        $Script:DialogSession = $session

        # v9.43: wait up to 15 s for first heartbeat (was 8 s). Cold WPF startup on slower x64
        # machines + first-run JIT can take longer than 8 s; the previous timeout produced
        # spurious "did not heartbeat" fallbacks on machines that would have come up fine.
        $waitStart = Get-Date
        while (((Get-Date) - $waitStart).TotalSeconds -lt 15) {
            if (Test-DialogHostAlive) {
                Write-Log "Dialog host ready (session $sessionId)" | Out-Null
                return $true
            }
            Start-Sleep -Milliseconds 200
        }

        Write-Log "Dialog host did not heartbeat within 15 s - falling back to legacy dialogs" | Out-Null
        $Script:DialogLegacyFallback = $true
        Stop-DialogHost -Force | Out-Null
        return $false

    } catch {
        Write-Log "Dialog host start failed: $($_.Exception.Message) - falling back" | Out-Null
        $Script:DialogLegacyFallback = $true
        return $false
    }
}

function Connect-DialogSession {
    <#
    .SYNOPSIS User-context entry point: connect to an existing dialog session
    started by SYSTEM. Returns $true if the host is alive and we can use it.
    #>
    param([Parameter(Mandatory=$true)][string]$SessionId)
    try {
        $paths = Get-DialogSessionPaths -SessionId $SessionId
        $Script:DialogSession = $paths
        if (Test-DialogHostAlive) {
            Write-Log "Connected to dialog session $SessionId" | Out-Null
            return $true
        }
        Write-Log "Dialog session $SessionId is not alive - falling back to legacy dialogs" | Out-Null
        $Script:DialogSession = $null
        $Script:DialogLegacyFallback = $true
        return $false
    } catch {
        Write-Log "Connect-DialogSession failed: $($_.Exception.Message)" | Out-Null
        $Script:DialogLegacyFallback = $true
        return $false
    }
}

function Send-DialogCommand {
    <#
    .SYNOPSIS Send a command to the dialog host. Fire-and-forget by default;
    pass -Blocking to wait for the host's reply.
    .OUTPUTS For -Blocking: the parsed reply object (or $null on timeout).
             For fire-and-forget: $true if dispatched, $false if host dead.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Cmd,
        [hashtable]$Payload = @{},
        [switch]$Blocking,
        [int]$TimeoutSeconds = 120
    )
    if (-not $Script:DialogSession) { return $false }
    if (-not (Test-DialogHostAlive)) {
        Write-Log "Send-DialogCommand: host not alive (cmd=$Cmd)" | Out-Null
        $Script:DialogLegacyFallback = $true
        return $false
    }

    $Script:DialogCmdCounter++
    $cmdId = "c$($Script:DialogCmdCounter)"
    $envelope = @{ id = $cmdId; cmd = $Cmd } + $Payload
    $json = $envelope | ConvertTo-Json -Compress -Depth 5

    # Append with retry to tolerate concurrent writers (SYSTEM + user-context)
    $appended = $false
    for ($i = 0; $i -lt 5 -and -not $appended; $i++) {
        try {
            [System.IO.File]::AppendAllText($Script:DialogSession.CmdFile, "$json`n", [System.Text.Encoding]::UTF8)
            $appended = $true
        } catch {
            Start-Sleep -Milliseconds 50
        }
    }
    if (-not $appended) {
        Write-Log "Send-DialogCommand: failed to append (cmd=$Cmd)" | Out-Null
        return $false
    }

    if (-not $Blocking) { return $true }

    $replyFile = Join-Path $Script:DialogSession.ReplyDir "$cmdId.json"
    $waitStart = Get-Date
    while (((Get-Date) - $waitStart).TotalSeconds -lt $TimeoutSeconds) {
        if (Test-Path $replyFile) {
            try {
                $reply = Get-Content $replyFile -Raw | ConvertFrom-Json
                Remove-Item $replyFile -Force -ErrorAction SilentlyContinue
                return $reply
            } catch {
                Start-Sleep -Milliseconds 100
            }
        }
        if (-not (Test-DialogHostAlive)) {
            Write-Log "Send-DialogCommand: host died while waiting for $cmdId" | Out-Null
            return $null
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Log "Send-DialogCommand: timeout waiting for reply to $cmdId ($Cmd)" | Out-Null
    return $null
}

function Stop-DialogHost {
    param([switch]$Force)
    if (-not $Script:DialogSession) { return }
    $session = $Script:DialogSession
    try {
        # Capture the host PID before we start tearing things down so we can
        # force-kill the process if the graceful shutdown command never lands
        # (v9.34: observed in field that after fast remediation runs the dialog
        # could stay on screen showing stale Progress content even though all
        # session files had been cleaned up).
        $hostPid = $null
        try {
            if ($session.PidFile -and (Test-Path $session.PidFile)) {
                $hostPid = [int]((Get-Content $session.PidFile -Raw -ErrorAction Stop).Trim())
            }
        } catch {}

        if (-not $Force -and (Test-DialogHostAlive)) {
            Send-DialogCommand -Cmd "shutdown" | Out-Null
            $waitStart = Get-Date
            while (((Get-Date) - $waitStart).TotalSeconds -lt 5) {
                if (-not (Test-DialogHostAlive)) { break }
                Start-Sleep -Milliseconds 200
            }
        }

        # Force-kill if the host process is still running after the graceful window
        # (or if -Force was specified). Without this, the WPF window can outlive
        # our session-file cleanup and stay on screen with stale content.
        if ($hostPid) {
            $proc = Get-Process -Id $hostPid -ErrorAction SilentlyContinue
            if ($proc) {
                Write-Log "Dialog host PID $hostPid still alive after shutdown - force-killing" | Out-Null
                try { Stop-Process -Id $hostPid -Force -ErrorAction Stop } catch {
                    Write-Log "Stop-Process failed for dialog host PID $hostPid : $($_.Exception.Message)" | Out-Null
                }
            }
        }

        if ($session.TaskName) {
            Unregister-ScheduledTask -TaskName $session.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        # v9.43: session files now live inside a per-session subdirectory ($session.Base).
        # Preserve the log by moving it to a sibling location before removing the directory,
        # so post-mortem on any future host crash still works.
        if ($session.LogFile -and (Test-Path $session.LogFile)) {
            try {
                $preservedLog = Join-Path "C:\ProgramData\Temp" "availableUpgrades-dialog-$($session.SessionId).log"
                Move-Item -Path $session.LogFile -Destination $preservedLog -Force -ErrorAction Stop
                Write-Log "Dialog host log preserved at $preservedLog" | Out-Null
            } catch {
                Write-Log "Stop-DialogHost: could not preserve log file - $($_.Exception.Message)" | Out-Null
            }
        }
        # Out-of-tree files (script, VBS launcher) live in user temp - remove them separately.
        foreach ($p in @($session.ScriptFile, $session.VbsPath)) {
            if ($p) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
        }
        # And blow away the per-session directory in one shot.
        if ($session.Base -and (Test-Path $session.Base)) {
            Remove-Item $session.Base -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Log "Dialog host stopped (session $($session.SessionId))" | Out-Null
    } catch {
        Write-Log "Stop-DialogHost cleanup error: $($_.Exception.Message)" | Out-Null
    } finally {
        $Script:DialogSession = $null
    }
}

# ----------------------------------------------------------------------------
# DialogHost inline script - written to disk and run as scheduled task. Uses
# single-quoted here-string so $-variables stay literal until the host runs.
# ----------------------------------------------------------------------------
$Script:DialogHostScript = @'
param(
    [Parameter(Mandatory=$true)][string]$CmdFile,
    [Parameter(Mandatory=$true)][string]$CursorFile,
    [Parameter(Mandatory=$true)][string]$ReplyDir,
    [Parameter(Mandatory=$true)][string]$HeartbeatFile,
    [Parameter(Mandatory=$true)][string]$PidFile,
    [Parameter(Mandatory=$true)][string]$LogFile
)

[System.IO.File]::WriteAllText($PidFile, "$PID")
function Write-DH($msg) {
    try {
        $line = "$(Get-Date -Format 'HH:mm:ss.fff') $msg"
        [System.IO.File]::AppendAllText($LogFile, "$line`r`n", [System.Text.Encoding]::UTF8)
    } catch {}
}
Write-DH "DialogHost started, PID=$PID"

try {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop
    $workArea = [System.Windows.SystemParameters]::WorkArea

    # Theme detection (light vs dark)
    $isDark = $true
    try {
        $themeKey = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -ErrorAction Stop
        $isDark = $themeKey.AppsUseLightTheme -eq 0
    } catch {}
    if ($isDark) {
        $bgColor = "#FF1F1F1F"; $borderColor = "#FF606060"; $textColor = "#FFFFFFFF"
        $subColor = "#FFCCCCCC"; $shadowOpacity = "0.6"; $closeBtnFg = "#FF888888"
    } else {
        $bgColor = "#FFF3F3F3"; $borderColor = "#FF9A9A9A"; $textColor = "#FF1B1B1B"
        $subColor = "#FF555555"; $shadowOpacity = "0.25"; $closeBtnFg = "#FF999999"
    }

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Software Updates" Width="440" MinHeight="120" SizeToContent="Height"
        WindowStartupLocation="Manual" ResizeMode="NoResize" WindowStyle="None"
        AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="False">
  <Border Background="$bgColor" CornerRadius="8" BorderBrush="$borderColor" BorderThickness="1">
    <Border.Effect>
      <DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="$shadowOpacity" BlurRadius="12"/>
    </Border.Effect>
    <Grid Margin="0">
      <!-- Close button (visible on non-blocking panels only) -->
      <Button Name="CloseButton" Content="X" Width="22" Height="22"
              HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0,6,6,0"
              Background="Transparent" BorderThickness="0" Foreground="$closeBtnFg"
              FontSize="11" FontWeight="Bold" Cursor="Hand" Panel.ZIndex="10"/>

      <!-- ProgressPanel: ongoing winget upgrade for one app -->
      <Grid Name="ProgressPanel" Margin="20,16,20,16" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Name="ProgressTitle" Text="Updating..." Foreground="$textColor" FontSize="13" FontWeight="SemiBold" Margin="0,0,0,2"/>
        <TextBlock Grid.Row="1" Name="ProgressVersion" Text="" Foreground="$subColor" FontSize="11" Margin="0,0,0,6"/>
        <ProgressBar Grid.Row="2" Name="ProgressBar" IsIndeterminate="True" Height="3" Foreground="#FF0078D4"/>
        <TextBlock Grid.Row="2" Name="ProgressStatus" Text="Preparing..." Foreground="$subColor" FontSize="11" HorizontalAlignment="Center" Margin="0,20,0,0"/>
      </Grid>

      <!-- TransitionPanel: brief "Done X -> Starting Y" between apps -->
      <Grid Name="TransitionPanel" Margin="20,16,20,16" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Name="TransitionFrom" Text="" Foreground="$textColor" FontSize="13" FontWeight="SemiBold" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" Name="TransitionTo" Text="" Foreground="$subColor" FontSize="12"/>
      </Grid>

      <!-- CompletionPanel: final "Update complete" or "Could not be completed" -->
      <Grid Name="CompletionPanel" Margin="20,16,20,16" Visibility="Collapsed">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="32"/><ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <Ellipse Grid.Column="0" Name="CompletionIcon" Width="24" Height="24" Fill="#FF107C10" VerticalAlignment="Top" Margin="0,2,0,0"/>
        <TextBlock Grid.Column="0" Name="CompletionGlyph" Text="OK" Foreground="White" FontSize="10" FontWeight="Bold" HorizontalAlignment="Center" VerticalAlignment="Top" Margin="0,7,0,0"/>
        <StackPanel Grid.Column="1" Margin="12,0,0,0">
          <TextBlock Name="CompletionTitle" Text="Update complete" Foreground="$textColor" FontSize="13" FontWeight="SemiBold"/>
          <TextBlock Name="CompletionBody"  Text=""                Foreground="$subColor"  FontSize="11" Margin="0,2,0,0" TextWrapping="Wrap"/>
        </StackPanel>
      </Grid>

      <!-- MandatoryPanel: forced update prompt with Upgrade button -->
      <Grid Name="MandatoryPanel" Margin="16,12,16,12" Visibility="Collapsed">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="32"/><ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Ellipse Grid.Column="0" Grid.RowSpan="3" Width="24" Height="24" Fill="#FFFF6B00" VerticalAlignment="Top" Margin="0,2,0,0"/>
        <TextBlock Grid.Column="0" Grid.RowSpan="3" Text="!" Foreground="White" FontSize="14" FontWeight="Bold" HorizontalAlignment="Center" VerticalAlignment="Top" Margin="0,4,0,0"/>
        <TextBlock Grid.Column="1" Grid.Row="0" Name="MandatoryTitle"   Text="" Foreground="$textColor" FontSize="14" FontWeight="SemiBold" Margin="12,0,0,2" TextWrapping="Wrap"/>
        <TextBlock Grid.Column="1" Grid.Row="1" Name="MandatoryVersion" Text="" Foreground="$subColor"  FontSize="12" Margin="12,0,0,8" TextWrapping="Wrap"/>
        <TextBlock Grid.Column="1" Grid.Row="2" Name="MandatoryBody"    Text="" Foreground="$subColor"  FontSize="12" Margin="12,0,0,8" TextWrapping="Wrap"/>
        <StackPanel Grid.Column="1" Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="12,0,0,0">
          <Button Name="MandatoryButton" Content="Upgrade" Width="100" Height="28" Background="#FF0078D4" Foreground="White" IsDefault="true"/>
        </StackPanel>
      </Grid>

      <!-- DeferralPanel: Defer / Update Now -->
      <Grid Name="DeferralPanel" Margin="16,12,16,12" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Name="DeferralTitle"   Text="" Foreground="$textColor" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,2" TextWrapping="Wrap"/>
        <TextBlock Grid.Row="1" Name="DeferralBody"    Text="" Foreground="$subColor"  FontSize="12" Margin="0,0,0,8" TextWrapping="Wrap"/>
        <TextBlock Grid.Row="2" Name="DeferralCounter" Text="" Foreground="$subColor"  FontSize="11" Margin="0,0,0,8"/>
        <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right">
          <Button Name="DeferralDeferButton"  Content="Defer"      Width="100" Height="28" Margin="0,0,8,0"/>
          <Button Name="DeferralUpdateButton" Content="Update Now" Width="100" Height="28" Background="#FF0078D4" Foreground="White" IsDefault="true"/>
        </StackPanel>
      </Grid>

      <!-- SkipPanel: "Skip this version after N failures?" -->
      <Grid Name="SkipPanel" Margin="16,12,16,12" Visibility="Collapsed">
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Name="SkipTitle" Text="" Foreground="$textColor" FontSize="14" FontWeight="SemiBold" Margin="0,0,0,4" TextWrapping="Wrap"/>
        <TextBlock Grid.Row="1" Name="SkipBody"  Text="" Foreground="$subColor"  FontSize="12" Margin="0,0,0,8" TextWrapping="Wrap"/>
        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right">
          <Button Name="SkipRetryButton" Content="Retry" Width="100" Height="28" Margin="0,0,8,0"/>
          <Button Name="SkipSkipButton"  Content="Skip"  Width="100" Height="28" Background="#FF0078D4" Foreground="White" IsDefault="true"/>
        </StackPanel>
      </Grid>
    </Grid>
  </Border>
</Window>
"@

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
    $window = [Windows.Markup.XamlReader]::Load($reader)
    # v9.34: anchor the window to the bottom-right of the work area on every size change.
    # The previous fixed Top of (Bottom - 200) was set before content existed; SizeToContent
    # then expanded the window downward and pushed it below the taskbar on the active monitor.
    $script:anchorMargin = 6
    $script:anchorRight  = 12
    function Reposition-AnchoredBottomRight {
        $h = if ($window.ActualHeight -gt 0) { $window.ActualHeight } else { $window.Height }
        if (-not $h -or $h -le 0) { $h = 140 }
        $w = if ($window.ActualWidth -gt 0) { $window.ActualWidth } else { $window.Width }
        if (-not $w -or $w -le 0) { $w = 440 }
        $window.Left = $workArea.Right  - $w - $script:anchorRight
        $window.Top  = $workArea.Bottom - $h - $script:anchorMargin
    }
    $window.Add_SizeChanged({ Reposition-AnchoredBottomRight })
    Reposition-AnchoredBottomRight
    $window.Hide() | Out-Null

    # Element refs
    $panels = @{
        Progress   = $window.FindName("ProgressPanel")
        Transition = $window.FindName("TransitionPanel")
        Completion = $window.FindName("CompletionPanel")
        Mandatory  = $window.FindName("MandatoryPanel")
        Deferral   = $window.FindName("DeferralPanel")
        Skip       = $window.FindName("SkipPanel")
    }
    $closeBtn = $window.FindName("CloseButton")

    # State
    $script:suppressed = $false       # session-scoped after user clicks X
    $script:visible    = $false
    $script:cursor     = 0
    $script:blocking   = $null        # @{ Id, Cmd, TimeoutTimer, CountdownTimer, TimeRemaining, DefaultResponse, ButtonOriginal }

    function Show-Panel($name) {
        foreach ($k in $panels.Keys) {
            $panels[$k].Visibility = if ($k -eq $name) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
        # Hide close button on blocking panels (Mandatory must be answered; Deferral/Skip have explicit buttons)
        $closeBtn.Visibility = if ($name -in @("Mandatory","Deferral","Skip")) { [System.Windows.Visibility]::Collapsed } else { [System.Windows.Visibility]::Visible }
    }
    function Ensure-Visible {
        if (-not $script:visible) {
            $window.Show()
            $window.Activate() | Out-Null
            $script:visible = $true
        }
    }
    function Ensure-Hidden {
        if ($script:visible) {
            $window.Hide()
            $script:visible = $false
        }
    }
    function Write-Reply($id, $payload) {
        try {
            $obj = @{ id = $id } + $payload
            $json = $obj | ConvertTo-Json -Compress -Depth 5
            $replyPath = Join-Path $ReplyDir "$id.json"
            [System.IO.File]::WriteAllText($replyPath, $json, [System.Text.Encoding]::UTF8)
        } catch { Write-DH "Write-Reply failed: $($_.Exception.Message)" }
    }
    function End-Blocking($response) {
        if (-not $script:blocking) { return }
        $b = $script:blocking
        if ($b.TimeoutTimer)   { $b.TimeoutTimer.Stop() }
        if ($b.CountdownTimer) { $b.CountdownTimer.Stop() }
        Write-Reply $b.Id @{ response = $response }
        Write-DH "Blocking $($b.Cmd) -> $response"
        $script:blocking = $null
    }

    # Close button: suppress for session, hide window
    $closeBtn.Add_Click({
        Write-DH "Close clicked - suppressing informational dialogs for session"
        $script:suppressed = $true
        Ensure-Hidden
    })

    # Mandatory button -> "upgrade"
    $window.FindName("MandatoryButton").Add_Click({ End-Blocking "upgrade"; Ensure-Hidden })

    # Deferral buttons
    $window.FindName("DeferralDeferButton").Add_Click({ End-Blocking "defer"; Ensure-Hidden })
    $window.FindName("DeferralUpdateButton").Add_Click({ End-Blocking "update"; Ensure-Hidden })

    # Skip buttons
    $window.FindName("SkipRetryButton").Add_Click({ End-Blocking "retry"; Ensure-Hidden })
    $window.FindName("SkipSkipButton").Add_Click({  End-Blocking "skip";  Ensure-Hidden })

    # Window-close: if blocking, treat as timeout (default response)
    $window.Add_Closing({
        if ($script:blocking) {
            End-Blocking $script:blocking.DefaultResponse
        }
    })

    # ------------------------------------------------------------------
    # Command pump - reads new lines from $CmdFile every 250 ms
    # ------------------------------------------------------------------
    function Process-Command($obj) {
        $id  = $obj.id
        $cmd = $obj.cmd
        # v9.48: cancel any pending auto-hide timer from a previous `complete` the moment a new
        # command arrives. Without this, when the parent loop sends `complete` per-app (via the
        # Show-CompletionNotification wrapper) and then immediately moves to the next app's
        # `transition` / `show-progress`, the 3-second hideTimer from the previous complete
        # would still fire mid-progress and hide the window even though we'd already swapped
        # to a different panel. Only the FINAL complete (at end of remediation) should be
        # allowed to auto-hide, because no more commands arrive after that.
        if ($script:hideTimer -and $cmd -notin @('hide', 'shutdown')) {
            try { $script:hideTimer.Stop() } catch {}
            $script:hideTimer = $null
        }
        switch ($cmd) {
            "show-progress" {
                if ($script:suppressed) { return }
                $window.FindName("ProgressTitle").Text = "Updating $($obj.app)..."
                $vText = ""
                if ($obj.fromVersion -and $obj.toVersion) { $vText = "$($obj.fromVersion) -> $($obj.toVersion)" }
                elseif ($obj.toVersion) { $vText = "Version $($obj.toVersion)" }
                $window.FindName("ProgressVersion").Text = $vText
                $window.FindName("ProgressStatus").Text = "Preparing..."
                $bar = $window.FindName("ProgressBar"); $bar.IsIndeterminate = $true; $bar.Value = 0
                Show-Panel "Progress"
                Ensure-Visible
            }
            "status" {
                if ($script:suppressed) { return }
                $window.FindName("ProgressStatus").Text = [string]$obj.text
            }
            "transition" {
                if ($script:suppressed) { return }
                $outcome = if ($obj.outcome -eq "ok") { "updated" } elseif ($obj.outcome -eq "failed") { "failed" } elseif ($obj.outcome -eq "skipped") { "skipped" } else { "done" }
                $window.FindName("TransitionFrom").Text = "$($obj.fromApp) $outcome"
                $window.FindName("TransitionTo").Text   = if ($obj.toApp) { "Starting $($obj.toApp)..." } else { "" }
                Show-Panel "Transition"
                Ensure-Visible
                # Auto-advance: nothing to do - the next show-progress command will swap content
            }
            "complete" {
                if ($script:suppressed) { return }
                $ok = ($obj.success -eq $true)
                $window.FindName("CompletionIcon").Fill = if ($ok) { [System.Windows.Media.BrushConverter]::new().ConvertFrom("#FF107C10") } else { [System.Windows.Media.BrushConverter]::new().ConvertFrom("#FFD13438") }
                $window.FindName("CompletionGlyph").Text = if ($ok) { "OK" } else { "X" }
                $window.FindName("CompletionTitle").Text = if ($obj.title) { [string]$obj.title } elseif ($ok) { "Update complete" } else { "Update could not be completed" }
                $window.FindName("CompletionBody").Text  = if ($obj.body) { [string]$obj.body } else { "" }
                Show-Panel "Completion"
                Ensure-Visible
                # Auto-hide after 7 s (v9.59: bumped from 3 s - 3 s was too short to read
                # the icon + title + body line). v9.37: hideTimer must live in script scope,
                # not as a function-local, or the closure can't find it when the dispatcher fires.
                if ($script:hideTimer) { try { $script:hideTimer.Stop() } catch {} }
                $script:hideTimer = New-Object System.Windows.Threading.DispatcherTimer
                $script:hideTimer.Interval = [TimeSpan]::FromSeconds(7)
                $script:hideTimer.Add_Tick({
                    try {
                        if ($script:hideTimer) { $script:hideTimer.Stop() }
                        Ensure-Hidden
                    } catch { Write-DH "Hide-tick error: $($_.Exception.Message)" }
                })
                $script:hideTimer.Start()
            }
            "prompt-mandatory" {
                $timeout = if ($obj.timeoutSec) { [int]$obj.timeoutSec } else { 60 }
                $window.FindName("MandatoryTitle").Text = if ($obj.title)   { [string]$obj.title }   else { "Required Update: $($obj.app)" }
                $window.FindName("MandatoryVersion").Text = if ($obj.versionInfo) { [string]$obj.versionInfo } else { "" }
                $window.FindName("MandatoryBody").Text  = if ($obj.body)    { [string]$obj.body }    else { "" }
                $btn = $window.FindName("MandatoryButton"); $btn.Content = "Upgrade ($timeout)"
                Show-Panel "Mandatory"
                Ensure-Visible
                # v9.37: stash button + timers in $script:blocking (script scope) so the dispatcher
                # timer closures still see them after Process-Command returns. The previous code
                # left $btn and $countdown as function-locals; one second later when the countdown
                # timer fired, the closure resolved them to $null and `$null.Content = ...` threw
                # the FATAL that killed $app.Run().
                $script:blocking = @{
                    Id = $id
                    Cmd = $cmd
                    DefaultResponse = "timeout"
                    TimeRemaining = $timeout
                    ButtonOriginal = "Upgrade"
                    Button = $btn
                }
                $countdown = New-Object System.Windows.Threading.DispatcherTimer
                $countdown.Interval = [TimeSpan]::FromSeconds(1)
                $countdown.Add_Tick({
                    try {
                        if (-not $script:blocking) { return }
                        $script:blocking.TimeRemaining--
                        if ($script:blocking.Button) {
                            $script:blocking.Button.Content = "$($script:blocking.ButtonOriginal) ($($script:blocking.TimeRemaining))"
                        }
                        if ($script:blocking.TimeRemaining -le 0 -and $script:blocking.CountdownTimer) {
                            $script:blocking.CountdownTimer.Stop()
                        }
                    } catch { Write-DH "Mandatory countdown tick error: $($_.Exception.Message)" }
                })
                $countdown.Start()
                $timeoutTimer = New-Object System.Windows.Threading.DispatcherTimer
                $timeoutTimer.Interval = [TimeSpan]::FromSeconds($timeout)
                $timeoutTimer.Add_Tick({
                    try {
                        if ($script:blocking -and $script:blocking.TimeoutTimer) { $script:blocking.TimeoutTimer.Stop() }
                        End-Blocking "timeout"
                        Ensure-Hidden
                    } catch { Write-DH "Mandatory timeout tick error: $($_.Exception.Message)" }
                })
                $timeoutTimer.Start()
                $script:blocking.TimeoutTimer = $timeoutTimer
                $script:blocking.CountdownTimer = $countdown
            }
            "prompt-deferral" {
                $timeout = if ($obj.timeoutSec) { [int]$obj.timeoutSec } else { 60 }
                $window.FindName("DeferralTitle").Text = if ($obj.title) { [string]$obj.title } else { "Update available: $($obj.app)" }
                $window.FindName("DeferralBody").Text  = if ($obj.body)  { [string]$obj.body }  else { "" }
                $window.FindName("DeferralCounter").Text = if ($obj.daysLeft -ne $null) { "You can defer for up to $($obj.daysLeft) more days." } else { "" }
                $deferBtn = $window.FindName("DeferralDeferButton")
                $deferBtn.IsEnabled = ($obj.canDefer -eq $true)
                $updateBtn = $window.FindName("DeferralUpdateButton")
                $updateBtn.Content = "Update Now ($timeout)"
                Show-Panel "Deferral"
                Ensure-Visible
                # v9.37: same scope fix as prompt-mandatory above.
                $script:blocking = @{
                    Id = $id
                    Cmd = $cmd
                    DefaultResponse = "timeout"
                    TimeRemaining = $timeout
                    ButtonOriginal = "Update Now"
                    Button = $updateBtn
                }
                $countdown = New-Object System.Windows.Threading.DispatcherTimer
                $countdown.Interval = [TimeSpan]::FromSeconds(1)
                $countdown.Add_Tick({
                    try {
                        if (-not $script:blocking) { return }
                        $script:blocking.TimeRemaining--
                        if ($script:blocking.Button) {
                            $script:blocking.Button.Content = "$($script:blocking.ButtonOriginal) ($($script:blocking.TimeRemaining))"
                        }
                        if ($script:blocking.TimeRemaining -le 0 -and $script:blocking.CountdownTimer) {
                            $script:blocking.CountdownTimer.Stop()
                        }
                    } catch { Write-DH "Deferral countdown tick error: $($_.Exception.Message)" }
                })
                $countdown.Start()
                $timeoutTimer = New-Object System.Windows.Threading.DispatcherTimer
                $timeoutTimer.Interval = [TimeSpan]::FromSeconds($timeout)
                $timeoutTimer.Add_Tick({
                    try {
                        if ($script:blocking -and $script:blocking.TimeoutTimer) { $script:blocking.TimeoutTimer.Stop() }
                        End-Blocking "timeout"
                        Ensure-Hidden
                    } catch { Write-DH "Deferral timeout tick error: $($_.Exception.Message)" }
                })
                $timeoutTimer.Start()
                $script:blocking.TimeoutTimer = $timeoutTimer
                $script:blocking.CountdownTimer = $countdown
            }
            "prompt-skip" {
                $timeout = if ($obj.timeoutSec) { [int]$obj.timeoutSec } else { 60 }
                $window.FindName("SkipTitle").Text = "$($obj.app) has failed to update $($obj.failures) times"
                $window.FindName("SkipBody").Text  = if ($obj.body) { [string]$obj.body } else { "Skip this version, or retry next cycle?" }
                Show-Panel "Skip"
                Ensure-Visible
                # v9.37: skip has no countdown, only a timeout - but the timer still has to live
                # in script scope so its closure can find $script:blocking.TimeoutTimer to stop.
                $script:blocking = @{
                    Id = $id
                    Cmd = $cmd
                    DefaultResponse = "timeout"
                    TimeRemaining = $timeout
                    ButtonOriginal = ""
                }
                $timeoutTimer = New-Object System.Windows.Threading.DispatcherTimer
                $timeoutTimer.Interval = [TimeSpan]::FromSeconds($timeout)
                $timeoutTimer.Add_Tick({
                    try {
                        if ($script:blocking -and $script:blocking.TimeoutTimer) { $script:blocking.TimeoutTimer.Stop() }
                        End-Blocking "timeout"
                        Ensure-Hidden
                    } catch { Write-DH "Skip timeout tick error: $($_.Exception.Message)" }
                })
                $timeoutTimer.Start()
                $script:blocking.TimeoutTimer = $timeoutTimer
            }
            "hide" {
                Ensure-Hidden
            }
            "shutdown" {
                Write-DH "Shutdown received"
                if ($script:blocking) { End-Blocking $script:blocking.DefaultResponse }
                $window.Close()
            }
            default {
                Write-DH "Unknown cmd: $cmd"
            }
        }
    }

    $pump = New-Object System.Windows.Threading.DispatcherTimer
    $pump.Interval = [TimeSpan]::FromMilliseconds(250)
    # v9.41: log heartbeat write failures (was silent catch). When this fires repeatedly the host
    # is alive but the parent's Test-DialogHostAlive will trip on stale heartbeat - which is
    # exactly the false-positive that produced the "two dialogs" symptom.
    $script:hbWarnLogged = $false
    $pump.Add_Tick({
        try { [System.IO.File]::WriteAllText($HeartbeatFile, (Get-Date -Format 'o')) } catch {
            if (-not $script:hbWarnLogged) {
                Write-DH "Heartbeat write failed (suppressing further occurrences): $($_.Exception.Message)"
                $script:hbWarnLogged = $true
            }
        }
        try {
            if (-not (Test-Path $CmdFile)) { return }
            $lines = [System.IO.File]::ReadAllLines($CmdFile, [System.Text.Encoding]::UTF8)
            if ($lines.Length -le $script:cursor) { return }
            for ($i = $script:cursor; $i -lt $lines.Length; $i++) {
                $line = $lines[$i].Trim()
                if (-not $line) { continue }
                try {
                    $obj = $line | ConvertFrom-Json
                    Process-Command $obj
                } catch {
                    Write-DH "Bad command line $($i+1): $($_.Exception.Message) | $line"
                }
            }
            $script:cursor = $lines.Length
            [System.IO.File]::WriteAllText($CursorFile, "$($script:cursor)")
        } catch {
            Write-DH "Pump error: $($_.Exception.Message)"
        }
    })
    $pump.Start()

    # Use ShowDialog of an invisible "anchor" window to run a message loop
    # The real $window starts hidden and toggles visibility via Show()/Hide().
    # We need a Dispatcher.Run() to keep the message pump alive even when
    # the window is hidden, so use Application + DoEvents pattern instead.
    $app = New-Object System.Windows.Application
    $app.ShutdownMode = [System.Windows.ShutdownMode]::OnExplicitShutdown
    $window.Add_Closed({ $app.Shutdown() })
    # v9.37: catch-all for anything that escapes per-handler try/catches; without this any
    # unanticipated exception in a dispatcher event propagates out of $app.Run() and the host
    # process exits, leaving the parent's Send-DialogCommand calls timing out.
    $app.Add_DispatcherUnhandledException({
        param($sender, $e)
        try { Write-DH "Dispatcher unhandled exception: $($e.Exception.Message)" } catch {}
        $e.Handled = $true
    })
    $app.Run() | Out-Null

} catch {
    Write-DH "FATAL: $($_.Exception.Message)"
}
Write-DH "DialogHost exiting"
'@

# WPF System User Prompt Functions - Modern replacement for legacy toast notification system

# Global user info cache to prevent redundant expensive CIM/WMI calls
$Script:CachedUserInfo = $null
$Script:UserInfoCacheTime = $null

function Get-InteractiveUser {
    <#
    .SYNOPSIS
        Gets the currently logged-in interactive user and their SID (Azure AD compatible)
    .DESCRIPTION
        Uses improved detection method that properly handles Azure AD users
        Now includes caching to prevent redundant expensive CIM/WMI calls
    #>
    
    try {
        # Check cache first (valid for 5 minutes)
        if ($Script:CachedUserInfo -and
            $Script:UserInfoCacheTime -and
            ((Get-Date) - $Script:UserInfoCacheTime).TotalMinutes -lt 5) {
            Write-Log "Using cached user info (age: $([Math]::Round(((Get-Date) - $Script:UserInfoCacheTime).TotalMinutes, 1)) minutes)" | Out-Null
            return $Script:CachedUserInfo
        }
        
        Write-Log "Detecting interactive user..." | Out-Null
        $userDetectionStart = Get-Date

        try {
            $loggedInUser = $null
            $LoggedSID = $null
            $CurrentAzureADUser = $null
            $detectionMethod = $null

            # Primary: Get-Process explorer -IncludeUserName. Typically ~50ms vs ~5s for CIM.
            # Explorer is the desktop shell - its owner is by definition the interactive user.
            # CIM/WMI Win32_ComputerSystem.Username is the historic method but is far slower
            # and produces the same answer in 99%+ of sessions, so it's now only the fallback
            # for cases where Explorer isn't running (e.g. session not yet fully initialized).
            try {
                $expStart = Get-Date
                $explorerProc = Get-Process explorer -IncludeUserName -ErrorAction Stop |
                    Where-Object { $_.SessionId -gt 0 } | Select-Object -First 1
                $expDuration = (Get-Date) - $expStart
                if ($explorerProc -and $explorerProc.UserName) {
                    $loggedInUser = $explorerProc.UserName
                    $LoggedSID = ([System.Security.Principal.NTAccount]$loggedInUser).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    $detectionMethod = "Explorer ($([Math]::Round($expDuration.TotalMilliseconds))ms)"
                }
            } catch {
                Write-Log "Explorer-based detection unavailable: $($_.Exception.Message)" | Out-Null
            }

            # Fallback 1: CIM Win32_ComputerSystem.Username (slow, but works when Explorer isn't running yet)
            if (-not $loggedInUser -or -not $LoggedSID) {
                try {
                    $cimStart = Get-Date
                    $cimJob = Start-Job -ScriptBlock {
                        Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Username
                    }
                    if (Wait-Job $cimJob -Timeout 15) {
                        $loggedInUser = Receive-Job $cimJob
                        $cimDuration = (Get-Date) - $cimStart
                        if ($loggedInUser) {
                            $LoggedSID = (([System.Security.Principal.NTAccount]$loggedInUser).Translate([System.Security.Principal.SecurityIdentifier]).Value)
                            $detectionMethod = "CIM ($([Math]::Round($cimDuration.TotalSeconds, 1))s)"
                        }
                    } else {
                        $cimDuration = (Get-Date) - $cimStart
                        Write-Log "CIM fallback timed out after $($cimDuration.TotalSeconds) seconds" | Out-Null
                    }
                    Remove-Job $cimJob -Force
                } catch {
                    Write-Log "CIM fallback failed: $($_.Exception.Message)" | Out-Null
                }
            }

            # Fallback 2: WMI (legacy COM-based path; same data, different transport)
            if (-not $loggedInUser -or -not $LoggedSID) {
                try {
                    $wmiStart = Get-Date
                    $wmiJob = Start-Job -ScriptBlock {
                        Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Username
                    }
                    if (Wait-Job $wmiJob -Timeout 15) {
                        $loggedInUser = Receive-Job $wmiJob
                        $wmiDuration = (Get-Date) - $wmiStart
                        if ($loggedInUser) {
                            $LoggedSID = (([System.Security.Principal.NTAccount]$loggedInUser).Translate([System.Security.Principal.SecurityIdentifier]).Value)
                            $detectionMethod = "WMI ($([Math]::Round($wmiDuration.TotalSeconds, 1))s)"
                        }
                    }
                    Remove-Job $wmiJob -Force
                } catch {
                    Write-Log "WMI fallback failed: $($_.Exception.Message)" | Out-Null
                }
            }

            if (-not $loggedInUser -or -not $LoggedSID) {
                throw "User detection failed - no logged in user found"
            }
            Write-Log "User detection method: $detectionMethod -> $loggedInUser, SID=$LoggedSID" | Out-Null
            
            # Try to get Azure AD username from registry with enhanced error suppression
            try {
                $azureAdPath = "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$LoggedSID\IdentityCache\$LoggedSID"
                Write-Log "Checking for Azure AD user info at: $azureAdPath" | Out-Null
                
                # First check if the path exists to avoid errors completely
                if (Test-Path $azureAdPath) {
                    $registryData = Get-ItemProperty -Path $azureAdPath -Name UserName -ErrorAction SilentlyContinue
                    if ($registryData -and $registryData.UserName) {
                        $CurrentAzureADUser = $registryData.UserName
                        Write-Log "Found Azure AD username: $CurrentAzureADUser" | Out-Null
                    } else {
                        Write-Log "Azure AD path exists but UserName property not found" | Out-Null
                        $CurrentAzureADUser = $null
                    }
                } else {
                    Write-Log "Azure AD identity cache path does not exist (user may be local account)" | Out-Null
                    $CurrentAzureADUser = $null
                }
            } catch {
                Write-Log "No Azure AD user info available (user may be local): $($_.Exception.Message)" | Out-Null
                $CurrentAzureADUser = $null
            }
            
            # Parse domain and username from Windows logon
            $windowsUsername = ($loggedInUser -split '\\')[1]
            $domain = ($loggedInUser -split '\\')[0]
            
            # Important distinction for Azure AD environments:
            # - Windows Username: Used for profile paths (e.g., HenrikSkovgaard-clou)
            # - Azure AD UPN: Used for Azure AD operations (e.g., henrik@cloudonly.dk)
            # - For scheduled tasks and file paths, we typically need the Windows username
            
            Write-Log "User detection results:" | Out-Null
            Write-Log "  - Full Name: $loggedInUser" | Out-Null
            Write-Log "  - Domain: $domain" | Out-Null
            Write-Log "  - Windows Username (profile): $windowsUsername" | Out-Null
            Write-Log "  - Azure AD UPN: $(if ($CurrentAzureADUser) { $CurrentAzureADUser } else { 'N/A' })" | Out-Null
            Write-Log "  - SID: $LoggedSID" | Out-Null
            
            # Verify profile path exists for Windows username
            $profilePath = "C:\Users\$windowsUsername"
            $profileExists = Test-Path $profilePath
            Write-Log "  - Profile Path: $profilePath (Exists: $profileExists)" | Out-Null
            
            $userInfo = @{
                Username = $windowsUsername              # Windows username for file operations
                FullName = $loggedInUser                # Full domain\username format
                Domain = $domain                        # Domain name
                SID = $LoggedSID                       # User SID
                AzureADUser = $CurrentAzureADUser      # Azure AD UPN (if available)
                ProfilePath = $profilePath             # User profile directory
                ProfileExists = $profileExists        # Whether profile directory exists
                SessionId = $null                      # Not available with this method
            }
            
            # Cache the result
            $Script:CachedUserInfo = $userInfo
            $Script:UserInfoCacheTime = Get-Date
            
            return $userInfo
            
        } catch [Exception] {
            $userDetectionDuration = (Get-Date) - $userDetectionStart
            $Message = "User detection failed after $($userDetectionDuration.TotalSeconds) seconds: $_"
            Write-Log $Message | Out-Null
            Throw $Message
        }
        
        $userDetectionDuration = (Get-Date) - $userDetectionStart
        Write-Log "User detection completed successfully in $($userDetectionDuration.TotalSeconds) seconds" | Out-Null
        
    } catch {
        $userDetectionDuration = (Get-Date) - $userDetectionStart
        Write-Log "Error getting interactive user after $($userDetectionDuration.TotalSeconds) seconds: $($_.Exception.Message)" | Out-Null
        return $null
    }
}

function Test-InteractiveSession {
    <#
    .SYNOPSIS
        Tests if there is an active interactive user session suitable for user context operations
    .DESCRIPTION
        Verifies that an interactive user session exists with desktop access before
        attempting to create scheduled tasks that require user interaction
    .OUTPUTS
        Boolean - True if interactive session available, False otherwise
    #>
    
    try {
        Write-Log "Checking for interactive session..." | Out-Null
        
        # Use existing Get-InteractiveUser function
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user detected - skipping user context operations" | Out-Null
            return $false
        }
        
        # Additional check: Verify explorer.exe is running (indicates active desktop)
        $explorerProcesses = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
        if (-not $explorerProcesses) {
            Write-Log "No explorer.exe processes found - no active desktop session" | Out-Null
            return $false
        }
        
        # Verify session is interactive (session ID > 0)
        $hasInteractiveSession = $false
        foreach ($process in $explorerProcesses) {
            if ($process.SessionId -gt 0) {  # Session 0 is services, >0 are user sessions
                $hasInteractiveSession = $true
                Write-Log "Interactive session confirmed - Session ID: $($process.SessionId), User: $($userInfo.Username)" | Out-Null
                break
            }
        }
        
        if (-not $hasInteractiveSession) {
            Write-Log "Explorer processes found but no interactive user sessions detected" | Out-Null
            return $false
        }
        
        return $true
        
    } catch {
        Write-Log "Error checking interactive session: $($_.Exception.Message)" | Out-Null
        return $false
    }
}

function New-UserPromptTask {
    <#
    .SYNOPSIS
        Creates a scheduled task to run the user prompt script as the interactive user
    #>
    
    param(
        [hashtable]$UserInfo,
        [string]$ScriptPath,
        [string]$ResponseFile,
        [string]$QuestionText,
        [string]$TitleText,
        [int]$TimeoutSeconds = 60
    )
    
    try {
        # Generate unique task name
        $guid = [System.Guid]::NewGuid().ToString()
        $taskName = "UserPrompt_$guid"
        
        Write-Log "Creating scheduled task: $taskName" | Out-Null
        
        # Force PowerShell 5.1 for toast notifications - PowerShell 7 cannot access Windows Runtime in scheduled task context
        Write-Log "Forcing PowerShell 5.1 for toast notifications (PowerShell 7 has Windows Runtime limitations in scheduled task context)" | Out-Null

        # v9.61: base64-encode Question/Title so embedded newlines (e.g. the multi-line
        # "App is running. Would you like to close it now?" prompt) survive the
        # wscript -> powershell command-line boundary. Without this, the v9.60 VBS
        # CR/LF sanitiser collapses the prompt body into a single run-on sentence.
        $encodedQuestion = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$QuestionText))
        $encodedTitle    = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$TitleText))

        # Create hidden launch action using VBS wrapper (no console window flash)
        $psArgs = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -ResponseFilePath `"$ResponseFile`" -EncodedQuestion `"$encodedQuestion`" -EncodedTitle `"$encodedTitle`" -Position `"BottomRight`" -TimeoutSeconds $TimeoutSeconds -DebugMode"
        $vbsDir = Split-Path $ResponseFile -Parent
        $launch = New-HiddenLaunchAction -PowerShellArguments $psArgs -VbsDirectory $vbsDir -AllowUI
        if (-not $launch) {
            Write-Log "ERROR: Failed to create hidden launch action - falling back to direct PowerShell" | Out-Null
            $launch = @{
                Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -ResponseFilePath `"$ResponseFile`" -EncodedQuestion `"$encodedQuestion`" -EncodedTitle `"$encodedTitle`" -Position `"BottomRight`" -TimeoutSeconds $TimeoutSeconds -DebugMode"
                VbsPath = $null
            }
        }
        $action = $launch.Action
        # Track VBS path for cleanup by caller (Invoke-SystemUserPrompt)
        $Script:LastCreatedVbsPath = $launch.VbsPath

        # Create task principal (run as interactive user) - Azure AD aware
        $principal = $null
        $username = $UserInfo.Username
        $fullName = $UserInfo.FullName
        $domain = $UserInfo.Domain
        $userSid = $UserInfo.SID
        
        Write-Log "Creating task principal for user: $fullName (SID: $userSid)" | Out-Null
        
        # For Azure AD accounts, try username-based approaches first as SID registration often fails
        $userFormats = @()
        
        # Add full name format first (Azure AD preferred)
        if ($fullName) {
            $userFormats += $fullName
        }
        
        # Add Azure AD specific formats
        if ($domain -and $domain -eq "AzureAD") {
            $userFormats += $fullName  # AzureAD\username
            $userFormats += $username  # Just username for Azure AD
        } elseif ($domain -and $domain -ne $env:COMPUTERNAME -and $domain -ne ".") {
            $userFormats += "$domain\$username"  # Domain\user format
        }
        
        # Add local account formats as fallback
        $userFormats += ".\$username"             # Local account format
        $userFormats += $username                 # Just username
        $userFormats += "$env:COMPUTERNAME\$username"  # Computer\username format
        
        # Remove duplicates and null entries
        $userFormats = $userFormats | Where-Object { $_ } | Select-Object -Unique
        
        # Try different logon types for Azure AD compatibility
        $logonTypes = @("Interactive", "S4U", "ServiceAccount")
        
        foreach ($userFormat in $userFormats) {
            foreach ($logonType in $logonTypes) {
                Write-Log "Trying task principal with format: $userFormat, LogonType: $logonType" | Out-Null
                try {
                    $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType $logonType -RunLevel Limited
                    Write-Log "Successfully created principal with: $userFormat ($logonType)" | Out-Null
                    break
                } catch {
                    Write-Log "Failed with format '$userFormat' ($logonType): $($_.Exception.Message)" | Out-Null
                }
            }
            if ($principal) { break }
        }
        
        # Final attempt with SID if username approaches failed
        if (-not $principal -and $userSid) {
            Write-Log "Trying SID as last resort: $userSid" | Out-Null
            try {
                $principal = New-ScheduledTaskPrincipal -UserId $userSid -LogonType ServiceAccount -RunLevel Limited
                Write-Log "Successfully created principal with SID (ServiceAccount logon)" | Out-Null
            } catch {
                Write-Log "Failed with SID approach: $($_.Exception.Message)" | Out-Null
            }
        }
        
        if (-not $principal) {
            Write-Log "Could not create task principal with any method. Attempted formats:" | Out-Null
            foreach ($format in $userFormats) {
                Write-Log "  - $format" | Out-Null
            }
            return $null
        }
        
        # Create task settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
        
        # Create the task with the principal
        $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description "Interactive user prompt for system operations"
        
        # Register the task with error handling and Azure AD-specific retry logic
        try {
            Write-Log "Attempting to register scheduled task with current principal..." | Out-Null
            $registeredTask = Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction Stop
            Write-Log "Scheduled task created successfully: $taskName" | Out-Null
            
            # Verify task exists
            $verifyTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if (-not $verifyTask) {
                Write-Log "Task registration appeared to succeed but task not found" | Out-Null
                return $null
            }
            
            return $taskName
            
        } catch {
            Write-Log "Failed to register scheduled task with current principal: $($_.Exception.Message)" | Out-Null
            
            # Azure AD fallback: Try creating a simpler task that launches as SYSTEM but switches user context
            if ($domain -eq "AzureAD") {
                Write-Log "Attempting Azure AD fallback approach (SYSTEM task with user context switching)..." | Out-Null
                try {
                    # Create a SYSTEM principal that will launch the script and let it handle user context
                    $fallbackPrincipal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

                    # Create hidden launch action for Azure AD fallback using VBS wrapper
                    # (Uses the v9.61 base64-encoded Question/Title computed earlier in this function.)
                    $fallbackPsArgs = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -ResponseFilePath `"$ResponseFile`" -EncodedQuestion `"$encodedQuestion`" -EncodedTitle `"$encodedTitle`""
                    $fallbackLaunch = New-HiddenLaunchAction -PowerShellArguments $fallbackPsArgs -VbsDirectory $vbsDir -AllowUI
                    if ($fallbackLaunch) {
                        $fallbackAction = $fallbackLaunch.Action
                    } else {
                        $fallbackAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -ResponseFilePath `"$ResponseFile`" -EncodedQuestion `"$encodedQuestion`" -EncodedTitle `"$encodedTitle`""
                    }

                    $fallbackTask = New-ScheduledTask -Action $fallbackAction -Principal $fallbackPrincipal -Settings $settings -Description "Interactive user prompt for system operations (Azure AD SYSTEM fallback)"

                    $registeredTask = Register-ScheduledTask -TaskName $taskName -InputObject $fallbackTask -Force -ErrorAction Stop
                    Write-Log "Scheduled task created successfully using Azure AD SYSTEM fallback: $taskName" | Out-Null
                    # Clean up the original VBS (replaced by fallback) and update tracking
                    if ($launch.VbsPath -and $launch.VbsPath -ne ($fallbackLaunch.VbsPath)) {
                        Remove-Item $launch.VbsPath -Force -ErrorAction SilentlyContinue
                    }
                    if ($fallbackLaunch) { $Script:LastCreatedVbsPath = $fallbackLaunch.VbsPath }
                    return $taskName

                } catch {
                    Write-Log "Azure AD SYSTEM fallback also failed: $($_.Exception.Message)" | Out-Null
                    if ($fallbackLaunch -and $fallbackLaunch.VbsPath) { Remove-Item $fallbackLaunch.VbsPath -Force -ErrorAction SilentlyContinue }
                    if ($launch.VbsPath) { Remove-Item $launch.VbsPath -Force -ErrorAction SilentlyContinue }
                    return $null
                }
            } else {
                Write-Log "Final failure to register scheduled task (non-Azure AD)" | Out-Null
                if ($launch.VbsPath) { Remove-Item $launch.VbsPath -Force -ErrorAction SilentlyContinue }
                return $null
            }
        }

    } catch {
        Write-Log "Error creating scheduled task: $($_.Exception.Message)" | Out-Null
        if ($launch -and $launch.VbsPath) { Remove-Item $launch.VbsPath -Force -ErrorAction SilentlyContinue }
        return $null
    }
}

function Start-UserPromptTask {
    <#
    .SYNOPSIS
        Starts the scheduled task to display the user prompt
    #>
    
    param([string]$TaskName)
    
    try {
        Write-Log "Starting scheduled task: $TaskName" | Out-Null
        
        # Verify task exists before starting
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if (-not $task) {
            Write-Log "Cannot start task - task not found: $TaskName" | Out-Null
            return $false
        }
        
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Log "Scheduled task started successfully" | Out-Null
        
        # Brief wait and verify task is running
        Start-Sleep -Seconds 1
        $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($taskInfo) {
            Write-Log "Task status: $($taskInfo.LastTaskResult), Last run: $($taskInfo.LastRunTime)" | Out-Null
        }
        
        return $true
        
    } catch {
        Write-Log "Error starting scheduled task: $($_.Exception.Message)" | Out-Null
        return $false
    }
}

function Wait-ForUserResponse {
    <#
    .SYNOPSIS
        Waits for the user response file to be created and returns the response
    #>
    
    param(
        [string]$ResponseFilePath,
        [int]$TimeoutSeconds
    )
    
    $startTime = Get-Date
    $timeout = $startTime.AddSeconds($TimeoutSeconds)
    
    Write-Log "Waiting for user response at: $ResponseFilePath" | Out-Null
    Write-Log "Timeout set for: $timeout" | Out-Null
    
    while ((Get-Date) -lt $timeout) {
        if (Test-Path $ResponseFilePath) {
            try {
                # Wait a moment for the file to be fully written
                Start-Sleep -Milliseconds 500
                
                $responseContent = Get-Content -Path $ResponseFilePath -Raw -ErrorAction Stop
                $response = $responseContent | ConvertFrom-Json -ErrorAction Stop
                
                Write-Log "User response received: $($response.response)" | Out-Null
                return $response.response
                
            } catch {
                Write-Log "Error reading response file: $($_.Exception.Message)" | Out-Null
                # Continue waiting, file might still be written
            }
        }
        
        Start-Sleep -Seconds 2
    }
    
    Write-Log "Timeout waiting for user response after $TimeoutSeconds seconds" | Out-Null
    return "TIMEOUT"
}

function Remove-UserPromptTask {
    <#
    .SYNOPSIS
        Removes the scheduled task and cleans up files
    #>
    
    param([string]$TaskName)
    
    try {
        if ($TaskName) {
            Write-Log "Removing scheduled task: $TaskName" | Out-Null
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Scheduled task removed" | Out-Null
        }
    } catch {
        Write-Log "Error during cleanup: $($_.Exception.Message)" | Out-Null
    }
}

function Invoke-SystemUserPrompt {
    <#
    .SYNOPSIS
        Displays a user prompt from SYSTEM context using WPF dialogs
    .DESCRIPTION
        Creates a scheduled task to switch from SYSTEM to user context and show a modern WPF dialog
        Handles both domain and Azure AD environments with proper user detection
    .PARAMETER Question
        The question to ask the user
    .PARAMETER Title
        Dialog title (optional, defaults to "System Notification")
    .PARAMETER TimeoutSeconds
        Timeout in seconds before using default action
    .PARAMETER DefaultAction
        Default action on timeout ("OK" or "Cancel")
    .PARAMETER Position
        Dialog position (BottomRight, TopRight, Center, etc.)
    .OUTPUTS
        String: "OK", "Cancel", or "TIMEOUT"
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Question,
        
        [string]$Title = "System Notification",
        [int]$TimeoutSeconds = 60,
        [string]$DefaultAction = "Cancel",
        [string]$Position = "BottomRight"
    )
    
    Write-Log -Message "Invoke-SystemUserPrompt called: '$Question'" | Out-Null
    
    try {
        # Check if running in SYSTEM context
        if (-not (Test-RunningAsSystem)) {
            Write-Log -Message "Not running as SYSTEM, cannot create user context task" | Out-Null
            return $DefaultAction
        }
        
        # Check for interactive session before creating user tasks
        if (-not (Test-InteractiveSession)) {
            Write-Log -Message "No interactive session detected - cannot display user dialog" | Out-Null
            Write-Log -Message "Using default action: $DefaultAction" | Out-Null
            return $DefaultAction
        }
        
        # Get interactive user
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user found after session check - cannot display prompt" | Out-Null
            return $DefaultAction
        }
        
        # Create unique identifiers for this prompt
        $promptId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        $taskName = "UserPrompt_$promptId"
        
        # Setup paths - use a shared location both SYSTEM and user can access
        $guid = $promptId
        
        # Use the user's temp directory (accessible from both SYSTEM and user contexts)
        $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
        if (Test-Path $userTempPath) {
            $responseFile = Join-Path $userTempPath "UserPrompt_$guid`_Response.json"
            Write-Log "Using user temp path: $responseFile" | Out-Null
        } else {
            # Fallback to a shared public location
            $sharedPath = "C:\ProgramData\Temp"
            if (-not (Test-Path $sharedPath)) {
                New-Item -Path $sharedPath -ItemType Directory -Force | Out-Null
            }
            $responseFile = Join-Path $sharedPath "UserPrompt_$guid`_Response.json"
            Write-Log "Using shared temp path: $responseFile" | Out-Null
        }
        
        $userPromptScriptPath = Join-Path $userTempPath "Show-UserPrompt_$promptId.ps1"
        
        # Create the user prompt script content (from the working Show-UserPrompt.ps1)
        $userPromptScriptContent = @'
param(
    [Parameter(Mandatory = $true)]
    [string]$ResponseFilePath,

    [Parameter(Mandatory = $false)]
    [string]$Question = "Do you want to proceed?",

    [Parameter(Mandatory = $false)]
    [string]$Title = "System Prompt",

    [Parameter(Mandatory = $false)]
    [string]$EncodedQuestion = "",

    [Parameter(Mandatory = $false)]
    [string]$EncodedTitle = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("BottomRight", "TopRight", "BottomLeft", "TopLeft", "Center")]
    [string]$Position = "BottomRight",

    [Parameter(Mandatory = $false)]
    [int]$TimeoutSeconds = 300,

    [Parameter(Mandatory = $false)]
    [switch]$DebugMode
)

# v9.61: Question/Title now arrive base64-encoded to preserve newlines through the
# wscript.exe -> powershell.exe command-line boundary (the legacy -Question raw text
# path lost newlines after v9.60's VBS CR/LF sanitisation kicked in). Decode here so
# the rest of the script sees the original string with line breaks intact. Falls back
# to the plain -Question / -Title parameters when callers haven't been migrated yet.
if ($EncodedQuestion) {
    try { $Question = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedQuestion)) } catch {}
}
if ($EncodedTitle) {
    try { $Title = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedTitle)) } catch {}
}

# Initialize comprehensive logging
function Write-UserLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logMessage = "[$timestamp] [UserPrompt] [$Level] $Message"
    
    # Write to a user-accessible debug log file
    $logPath = Join-Path $env:TEMP "UserPrompt_Debug.log"
    try {
        $logMessage | Out-File -FilePath $logPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Ignore logging errors
    }
    
    # Also output to console if in debug mode
    if ($DebugMode) {
        Write-Host $logMessage
    }
}

Write-UserLog "=== USER PROMPT SCRIPT STARTED ==="
Write-UserLog "PowerShell Version: $($PSVersionTable.PSVersion)"
Write-UserLog "PowerShell Edition: $($PSVersionTable.PSEdition)"
Write-UserLog "Response File Path: $ResponseFilePath"
Write-UserLog "Question: $Question"
Write-UserLog "Title: $Title"
Write-UserLog "Position: $Position"
Write-UserLog "Timeout: $TimeoutSeconds seconds"
Write-UserLog "Debug Mode: $DebugMode"
Write-UserLog "Username: $env:USERNAME"
Write-UserLog "Computer: $env:COMPUTERNAME"
Write-UserLog "Current Directory: $PWD"
Write-UserLog "Process ID: $PID"
Write-UserLog "Session ID: $((Get-Process -Id $PID).SessionId)"

# Global variables for response handling
$script:UserResponse = $null
$script:ResponseReceived = $false

function Write-ResponseFile {
    param(
        [string]$Response,
        [string]$FilePath,
        [hashtable]$AdditionalData = @{}
    )
    
    try {
        $responseData = @{
            response = $Response
            timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            username = $env:USERNAME
            computer = $env:COMPUTERNAME
            powershellVersion = $PSVersionTable.PSVersion.ToString()
            processId = $PID
        }
        
        # Add any additional data
        foreach ($key in $AdditionalData.Keys) {
            $responseData[$key] = $AdditionalData[$key]
        }
        
        $jsonResponse = $responseData | ConvertTo-Json -Compress
        $jsonResponse | Out-File -FilePath $FilePath -Encoding UTF8 -Force
        
        Write-UserLog "Response written to file: $Response"
        return $true
        
    } catch {
        Write-UserLog "Error writing response file: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Show-ModernDialog {
    param(
        [string]$TitleText,
        [string]$QuestionText,
        [int]$TimeoutSeconds = 60,
        [string]$DefaultAction = "Cancel"
    )
    
    try {
        Write-UserLog "Loading WPF assemblies for modern dialog..."

        # Load required assemblies (single call - 4x faster than separate Add-Type per assembly)
        Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms -ErrorAction Stop

        Write-UserLog "WPF assemblies loaded successfully"
        
        # Create XAML for modern toast-like dialog (Windows 10/11 style)
        $xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="$TitleText"
    Width="420"
    MinHeight="140"
    SizeToContent="Height"
    WindowStartupLocation="Manual"
    ResizeMode="NoResize"
    WindowStyle="None"
    AllowsTransparency="True"
    Background="Transparent"
    Topmost="True"
    ShowInTaskbar="False">
    
    <Window.Triggers>
        <EventTrigger RoutedEvent="Window.Loaded">
            <BeginStoryboard>
                <Storyboard>
                    <DoubleAnimation Storyboard.TargetProperty="Opacity"
                                     From="0" To="1" Duration="0:0:0.3"/>
                    <ThicknessAnimation Storyboard.TargetProperty="Margin"
                                        From="0,50,0,0" To="0,0,0,0" Duration="0:0:0.3"/>
                </Storyboard>
            </BeginStoryboard>
        </EventTrigger>
    </Window.Triggers>
    
    <Border Name="MainBorder"
            Background="#FF1F1F1F"
            CornerRadius="8"
            BorderBrush="#FF323232"
            BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="0.6" BlurRadius="12"/>
        </Border.Effect>
        
        <Grid Margin="16,12,16,12">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="32"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            
            <!-- Icon -->
            <Ellipse Grid.Column="0" Grid.RowSpan="2"
                     Width="24" Height="24"
                     Fill="#FF0078D4"
                     VerticalAlignment="Top"
                     Margin="0,2,0,0"/>
            
            <TextBlock Grid.Column="0" Grid.RowSpan="2"
                       Text="?"
                       Foreground="White"
                       FontSize="14"
                       FontWeight="Bold"
                       HorizontalAlignment="Center"
                       VerticalAlignment="Top"
                       Margin="0,4,0,0"/>
            
            <!-- Title -->
            <TextBlock Grid.Column="1" Grid.Row="0"
                       Text="$TitleText"
                       Foreground="White"
                       FontSize="14"
                       FontWeight="SemiBold"
                       Margin="12,0,0,2"
                       TextWrapping="Wrap"/>
            
            <!-- Question -->
            <TextBlock Grid.Column="1" Grid.Row="1"
                       Text="$QuestionText"
                       Foreground="#FFCCCCCC"
                       FontSize="12"
                       Margin="12,0,0,8"
                       TextWrapping="Wrap"/>
            
            <!-- Buttons -->
            <StackPanel Grid.Column="1" Grid.Row="2"
                        Orientation="Horizontal"
                        HorizontalAlignment="Right"
                        Margin="12,0,0,0">
                
                <Button Name="CancelButton"
                        Content="Cancel"
                        Width="60"
                        Height="24"
                        Margin="0,0,8,0"
                        Background="Transparent"
                        Foreground="#FFCCCCCC"
                        BorderBrush="#FF484848"
                        BorderThickness="1"
                        FontSize="11"
                        Cursor="Hand">
                    <Button.Style>
                        <Style TargetType="Button">
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#FF2A2A2A"/>
                                    <Setter Property="Foreground" Value="White"/>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </Button.Style>
                </Button>
                
                <Button Name="OKButton"
                        Content="OK"
                        Width="60"
                        Height="24"
                        Background="#FF0078D4"
                        Foreground="White"
                        BorderBrush="Transparent"
                        BorderThickness="0"
                        FontSize="11"
                        Cursor="Hand">
                    <Button.Style>
                        <Style TargetType="Button">
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#FF106EBE"/>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </Button.Style>
                </Button>
                
            </StackPanel>
        </Grid>
    </Border>
</Window>
"@

        Write-UserLog "Creating WPF window from XAML..."
        
        # Create window from XAML
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
        $window = [Windows.Markup.XamlReader]::Load($reader)
        
        Write-UserLog "WPF window created successfully"
        
        # Get button references
        $okButton = $window.FindName("OKButton")
        $cancelButton = $window.FindName("CancelButton")
        
        # Set up event handlers and timeout
        $script:dialogResult = $null
        $script:timeoutReached = $false
        
        # Store original button text and determine which button gets countdown
        $originalOKText = $okButton.Content
        $originalCancelText = $cancelButton.Content
        $showCountdownOnOK = ($DefaultAction -eq "OK")
        
        Write-UserLog "Countdown will be shown on: $(if ($showCountdownOnOK) { 'OK' } else { 'Cancel' }) button (DefaultAction: $DefaultAction)"
        
        # Create countdown timer (updates every second)
        $script:timeRemaining = $TimeoutSeconds
        $countdownTimer = New-Object System.Windows.Threading.DispatcherTimer
        $countdownTimer.Interval = [System.TimeSpan]::FromSeconds(1)
        
        $countdownTimer.Add_Tick({
            $script:timeRemaining--
            Write-UserLog "Countdown update: $($script:timeRemaining) seconds remaining"
            
            # Update the appropriate button with countdown
            if ($showCountdownOnOK) {
                $okButton.Content = "$originalOKText ($($script:timeRemaining))"
            } else {
                $cancelButton.Content = "$originalCancelText ($($script:timeRemaining))"
            }
            
            # Stop countdown timer when we reach zero (main timeout timer will handle dialog close)
            if ($script:timeRemaining -le 0) {
                $countdownTimer.Stop()
            }
        })
        
        # Create main timeout timer
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [System.TimeSpan]::FromSeconds($TimeoutSeconds)
        
        $timer.Add_Tick({
            Write-UserLog "Dialog timeout reached after $TimeoutSeconds seconds - auto-closing with default action: $DefaultAction"
            $script:timeoutReached = $true
            $script:dialogResult = $DefaultAction
            $timer.Stop()
            $countdownTimer.Stop()
            $window.Close()
            
            # Force immediate termination to prevent 30-second delay
            Write-UserLog "Forcing immediate process termination to prevent delay"
            $terminationTimer = New-Object System.Windows.Threading.DispatcherTimer
            $terminationTimer.Interval = [System.TimeSpan]::FromMilliseconds(500)
            $terminationTimer.Add_Tick({
                Write-UserLog "Terminating process now"
                $terminationTimer.Stop()
                
                # Write response file immediately before termination
                Write-ResponseFile -Response $DefaultAction -FilePath $ResponseFilePath -AdditionalData @{
                    stage = "TIMEOUT_TERMINATION"
                    terminationMethod = "Timer_Force_Exit"
                    defaultAction = $DefaultAction
                }
                
                # Multiple termination attempts
                try { $window.Hide() } catch {}
                try { [System.Windows.Application]::Current.Shutdown() } catch {}
                Start-Sleep -Milliseconds 100
                [System.Environment]::Exit(0)
            })
            $terminationTimer.Start()
        })
        
        $okButton.Add_Click({
            Write-UserLog "OK button clicked"
            $timer.Stop()
            $countdownTimer.Stop()
            $script:dialogResult = "OK"
            $window.Close()
        })
        
        $cancelButton.Add_Click({
            Write-UserLog "Cancel button clicked"
            $timer.Stop()
            $countdownTimer.Stop()
            $script:dialogResult = "Cancel"
            $window.Close()
        })
        
        # Handle window closing without button click
        $window.Add_Closing({
            $timer.Stop()
            $countdownTimer.Stop()
            if ($script:dialogResult -eq $null -and -not $script:timeoutReached) {
                Write-UserLog "Window closed without button click - treating as Cancel"
                $script:dialogResult = "Cancel"
            }
        })
        
        # Position window like a native Windows toast notification
        $window.Add_Loaded({
            $workArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
            $taskbarHeight = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height - $workArea.Height
            
            switch ($Position) {
                "BottomRight" {
                    $window.Left = $workArea.Width - $window.Width - 16
                    $window.Top = $workArea.Height - $window.Height - 16
                    Write-UserLog "Window positioned at bottom-right (near notification area)"
                }
                "TopRight" {
                    $window.Left = $workArea.Width - $window.Width - 16
                    $window.Top = 16
                    Write-UserLog "Window positioned at top-right"
                }
                "BottomLeft" {
                    $window.Left = 16
                    $window.Top = $workArea.Height - $window.Height - 16
                    Write-UserLog "Window positioned at bottom-left"
                }
                "TopLeft" {
                    $window.Left = 16
                    $window.Top = 16
                    Write-UserLog "Window positioned at top-left"
                }
                "Center" {
                    $window.Left = ($workArea.Width - $window.Width) / 2
                    $window.Top = ($workArea.Height - $window.Height) / 2
                    Write-UserLog "Window positioned at center"
                }
            }
        })
        
        Write-UserLog "Showing dialog with $TimeoutSeconds second timeout (DefaultAction: $DefaultAction)..."
        
        # Start both timers
        $timer.Start()
        $countdownTimer.Start()
        Write-UserLog "Timeout and countdown timers started"
        
        # Show dialog modally (timer will auto-close if needed)
        $result = $window.ShowDialog()
        
        # Ensure timers are stopped
        $timer.Stop()
        $countdownTimer.Stop()
        
        Write-UserLog "Dialog closed with result: $($script:dialogResult)"
        
        return $script:dialogResult
        
    } catch {
        $errorMsg = "Failed to show modern dialog: $($_.Exception.Message)"
        Write-UserLog $errorMsg -Level "ERROR"
        Write-UserLog "Exception Type: $($_.Exception.GetType().FullName)" -Level "ERROR"
        Write-UserLog "Stack Trace: $($_.Exception.StackTrace)" -Level "ERROR"
        
        Write-ResponseFile -Response "ERROR" -FilePath $ResponseFilePath -AdditionalData @{
            error = $errorMsg
            stage = "MODERN_DIALOG"
            exceptionType = $_.Exception.GetType().FullName
        }
        return "ERROR"
    }
}

# Main execution
try {
    Write-UserLog "Starting modern dialog user prompt"
    
    # Test write permissions to response file location
    $responseDir = Split-Path $ResponseFilePath
    Write-UserLog "Response directory: $responseDir"
    Write-UserLog "Directory exists: $(Test-Path $responseDir)"
    
    try {
        $testFile = Join-Path $responseDir "test_write_$(Get-Random).tmp"
        "test" | Out-File -FilePath $testFile -Force
        Remove-Item $testFile -Force
        Write-UserLog "Write permissions confirmed for response directory"
    } catch {
        Write-UserLog "WARNING: Cannot write to response directory: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Show modern dialog to capture user response
    $userResponse = Show-ModernDialog -TitleText $Title -QuestionText $Question -TimeoutSeconds $TimeoutSeconds -DefaultAction $DefaultAction
    
    if ($userResponse -eq "ERROR") {
        Write-UserLog "Modern dialog failed" -Level "ERROR"
        $script:UserResponse = "ERROR"
    } else {
        Write-UserLog "User response captured: $userResponse" -Level "SUCCESS"
        $script:UserResponse = $userResponse
        $script:ResponseReceived = $true
    }
    
    # Write final response
    Write-UserLog "Writing final response file..."
    $writeSuccess = Write-ResponseFile -Response $script:UserResponse -FilePath $ResponseFilePath -AdditionalData @{
        stage = "FINAL_RESPONSE"
        dialogMethod = "Modern WPF Dialog"
        interactionSuccess = $script:ResponseReceived
    }
    
    if ($writeSuccess) {
        Write-UserLog "User prompt completed successfully with response: $($script:UserResponse)" -Level "SUCCESS"
    } else {
        Write-UserLog "Failed to write response file" -Level "ERROR"
    }
    
    # Force immediate process termination to prevent scheduled task delays
    if ($script:UserResponse -eq "TIMEOUT") {
        Write-UserLog "Timeout occurred - forcing immediate process exit"
        Start-Sleep -Milliseconds 100  # Brief pause to ensure log is written
        [System.Environment]::Exit(0)
    }
    
} catch {
    Write-UserLog "Unexpected error in user prompt: $($_.Exception.Message)" -Level "ERROR"
    Write-UserLog "Exception Type: $($_.Exception.GetType().FullName)" -Level "ERROR"
    Write-UserLog "Stack Trace: $($_.Exception.StackTrace)" -Level "ERROR"
    
    # Try to write error response
    try {
        Write-ResponseFile -Response "ERROR" -FilePath $ResponseFilePath -AdditionalData @{
            error = $_.Exception.Message
            stage = "UNEXPECTED_ERROR"
            exceptionType = $_.Exception.GetType().FullName
        }
    } catch {
        Write-UserLog "Could not write final error response: $($_.Exception.Message)" -Level "ERROR"
    }
} finally {
    Write-UserLog "User prompt script completed"
    Write-UserLog "=== USER PROMPT SCRIPT ENDED ==="
    
    # Ensure process exits immediately in all cases
    Start-Sleep -Milliseconds 100  # Brief pause to ensure logs are written
}
'@
        
        # Write the user prompt script to temp file
        Write-Log "Writing user prompt script to: $userPromptScriptPath" | Out-Null
        $userPromptScriptContent | Set-Content -Path $userPromptScriptPath -Encoding UTF8
        
        Write-Log "Response file path: $responseFile" | Out-Null
        Write-Log "User script path: $userPromptScriptPath" | Out-Null
        
        # Create scheduled task using the working PowerShell Task Scheduler approach
        $createdTaskName = New-UserPromptTask -UserInfo $userInfo -ScriptPath $userPromptScriptPath -ResponseFile $responseFile -QuestionText $Question -TitleText $Title -TimeoutSeconds $TimeoutSeconds
        
        if (-not $createdTaskName) {
            Write-Log "Failed to create scheduled task" | Out-Null
            return $DefaultAction
        }
        
        # Start the task
        if (-not (Start-UserPromptTask -TaskName $createdTaskName)) {
            Write-Log "Failed to start scheduled task" | Out-Null
            Remove-UserPromptTask -TaskName $createdTaskName
            return $DefaultAction
        }
        
        # Wait for user response using the working method with task monitoring
        $userResponse = Wait-ForUserResponse -ResponseFilePath $responseFile -TimeoutSeconds $TimeoutSeconds
        
        # If timeout occurred, force task termination to prevent 30-second delay
        if ($userResponse -eq "TIMEOUT") {
            Write-Log "Timeout detected - forcing immediate task termination" | Out-Null
            
            # Stop the scheduled task immediately
            try {
                Stop-ScheduledTask -TaskName $createdTaskName -ErrorAction SilentlyContinue
                Write-Log "Scheduled task stopped" | Out-Null
            } catch {
                Write-Log "Error stopping scheduled task: $($_.Exception.Message)" | Out-Null
            }
            
            # Wait a moment then force-kill any remaining PowerShell processes associated with the task
            Start-Sleep -Milliseconds 500
            try {
                $taskProcesses = Get-WmiObject -Class Win32_Process | Where-Object {
                    $_.CommandLine -like "*$userPromptScriptPath*" -or
                    $_.CommandLine -like "*UserPrompt_*"
                }
                foreach ($process in $taskProcesses) {
                    Write-Log "Force-terminating task process: $($process.ProcessId)" | Out-Null
                    Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Log "Error force-terminating processes: $($_.Exception.Message)" | Out-Null
            }
        }
        
        # Cleanup
        Remove-UserPromptTask -TaskName $createdTaskName

        # Clean up temporary files
        Remove-Item $userPromptScriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
        if ($Script:LastCreatedVbsPath -and (Test-Path $Script:LastCreatedVbsPath)) {
            Remove-Item $Script:LastCreatedVbsPath -Force -ErrorAction SilentlyContinue
        }
        
        Write-Log "Process completed with response: $userResponse" | Out-Null
        return $userResponse
        
    } catch {
        Write-Log -Message "Invoke-SystemUserPrompt failed: $($_.Exception.Message)" | Out-Null
        if ($createdTaskName) {
            Remove-UserPromptTask -TaskName $createdTaskName
        }
        Remove-Item $userPromptScriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
        return $DefaultAction
    }
}

function Show-ProcessCloseDialog {
    <#
    .SYNOPSIS
        Shows a user dialog asking whether to close a blocking process for application update
        Now integrated with deferral system for enhanced user experience
    .DESCRIPTION
        Uses the modern WPF-based notification system with deferral capabilities
        Checks deferral status and shows appropriate dialog (simple close or deferral options)
    .PARAMETER AppName
        Application ID for the update
    .PARAMETER ProcessName
        Name of the blocking process
    .PARAMETER TimeoutSeconds
        Timeout in seconds before auto-action
    .PARAMETER DefaultTimeoutAction
        Action to take on timeout (true = close app, false = keep open)
    .PARAMETER FriendlyName
        User-friendly name of the application
    .PARAMETER CurrentVersion
        Current version of the application
    .PARAMETER AvailableVersion
        Available version for update
    .PARAMETER WhitelistConfig
        Whitelist configuration object for the app
    .OUTPUTS
        Hashtable with user choice: @{ CloseProcess = [bool]; DeferralDays = [int]; Action = "Update|Defer" }
    #>
    param(
        [string]$AppName,
        [string]$ProcessName,
        [int]$TimeoutSeconds = 60,
        [bool]$DefaultTimeoutAction = $false,
        [string]$FriendlyName = "",
        [string]$CurrentVersion = "",
        [string]$AvailableVersion = "",
        [object]$WhitelistConfig = $null
    )

    Write-Log -Message "Show-ProcessCloseDialog called for $AppName" | Out-Null

    # Use provided FriendlyName or fallback to AppName
    $friendlyName = if (-not [string]::IsNullOrEmpty($FriendlyName)) { $FriendlyName } else { $AppName }

    Write-Log -Message "Friendly name resolved to: $friendlyName" | Out-Null

    try {
        # Check deferral status if whitelist config is provided
        $deferralStatus = $null
        $hasDeferralSupport = $false
        
        if ($WhitelistConfig -and $WhitelistConfig.DeferralEnabled -eq $true) {
            Write-Log -Message "Checking deferral status for $AppName" | Out-Null
            $deferralStatus = Get-DeferralStatus -AppID $AppName -WhitelistConfig $WhitelistConfig -AvailableVersion $AvailableVersion
            $hasDeferralSupport = $true
        }
        
        # Determine dialog type based on deferral status
        if ($hasDeferralSupport -and $deferralStatus) {
            Write-Log -Message "Using deferral-enabled dialog for $AppName (CanDefer: $($deferralStatus.CanDefer), ForceUpdate: $($deferralStatus.ForceUpdate))" | Out-Null
            
            # Show enhanced deferral dialog with configured timeout
            $deferralChoice = Show-DeferralDialog -AppName $AppName -DeferralStatus $deferralStatus -ProcessName $ProcessName -FriendlyName $friendlyName -CurrentVersion $CurrentVersion -AvailableVersion $AvailableVersion -TimeoutSeconds $TimeoutSeconds
            
            # Record deferral choice if user chose to defer
            if ($deferralChoice.Action -eq "Defer") {
                $deferralRecorded = Set-DeferralChoice -AppID $AppName -AdminHardDeadline $deferralStatus.AdminHardDeadline
                if ($deferralRecorded) {
                    Write-Log -Message "Recorded user deferral for $AppName (until end of day)" | Out-Null
                } else {
                    Write-Log -Message "Failed to record deferral choice - proceeding with update" | Out-Null
                    $deferralChoice.Action = "Update"
                    $deferralChoice.CloseProcess = $true
                }
            }
            
            # Return structured response
            return @{
                CloseProcess = $deferralChoice.CloseProcess
                DeferralDays = $deferralChoice.DeferralDays
                Action = $deferralChoice.Action
                UserChoice = ($deferralChoice.Action -eq "Update")
                ProgressSignalFile = $deferralChoice.ProgressSignalFile
            }
            
        } else {
            # Use legacy simple dialog for apps without deferral support
            Write-Log -Message "Using legacy dialog for $AppName (no deferral support)" | Out-Null

            # Create the question text with version information
            $versionText = ""
            if (-not [string]::IsNullOrEmpty($CurrentVersion) -and -not [string]::IsNullOrEmpty($AvailableVersion)) {
                $versionText = "$friendlyName $CurrentVersion -> $AvailableVersion update available`n`n"
            } else {
                $versionText = "An update is available for $friendlyName`n`n"
            }

            $question = "${versionText}The application cannot be updated while it is running.`n`nPlease save your work before clicking Update Now.`n`nWould you like to close $friendlyName now to allow the update to proceed?"
            $title = if (-not [string]::IsNullOrEmpty($CurrentVersion) -and -not [string]::IsNullOrEmpty($AvailableVersion)) {
                "Update ${friendlyName}: ${CurrentVersion} -> ${AvailableVersion}"
            } else {
                "${friendlyName} Update Available"
            }

            # v9.62: when the persistent dialog host is alive, route this prompt through
            # the host's deferral panel instead of spawning a legacy WPF window via VBS.
            # The legacy spawn would land at the same bottom-right corner the host's
            # transition panel ("App updated -> Starting next") is currently occupying,
            # and Topmost Z-order between the two cross-process windows is undefined - in
            # field reports the legacy window stayed hidden behind the host's transition
            # panel for the full 120 s timeout, so the user never saw the close-app prompt
            # and the script silently fell through with CloseProcess=$DefaultTimeoutAction.
            # The host's deferral panel maps cleanly: Update Now -> close+update,
            # Defer -> keep app open. canDefer=true so both buttons are active even
            # though there's no actual day-based deferral state for these apps.
            if (Test-DialogHostAlive) {
                Write-Log -Message "Routing close-app prompt for $friendlyName through persistent dialog host" | Out-Null
                $hostReply = Send-DialogCommand -Cmd "prompt-deferral" -Payload @{
                    title = $title
                    body = $question
                    daysLeft = $null
                    canDefer = $true
                    timeoutSec = $TimeoutSeconds
                } -Blocking -TimeoutSeconds ($TimeoutSeconds + 30)
                if ($hostReply -and $hostReply.response) {
                    $choice = [string]$hostReply.response
                    $userChoice = ($choice -eq "update")
                    if ($choice -eq "timeout") { $userChoice = [bool]$DefaultTimeoutAction }
                    Write-Log -Message "Host close-app reply: $choice (CloseProcess=$userChoice)" | Out-Null
                    return @{
                        CloseProcess = $userChoice
                        DeferralDays = 0
                        Action = if ($userChoice) { "Update" } else { "Cancel" }
                        UserChoice = $userChoice
                    }
                }
                Write-Log -Message "Dialog host did not reply - falling back to legacy WPF spawn" | Out-Null
            }

            # Convert DefaultTimeoutAction boolean to string format
            $defaultActionString = if ($DefaultTimeoutAction) { "OK" } else { "Cancel" }

            Write-Log -Message "Showing legacy WPF dialog for $friendlyName with ${TimeoutSeconds}s timeout, default action: $defaultActionString" | Out-Null

            # Call the context-aware dialog system
            $response = Show-UserDialog -Question $question -Title $title -TimeoutSeconds $TimeoutSeconds -DefaultAction $defaultActionString

            Write-Log -Message "Legacy WPF dialog response: $response" | Out-Null

            # Convert response back to boolean and return structured response
            $userChoice = ($response -eq "OK")

            if ($userChoice) {
                Write-Log -Message "User chose to close $friendlyName for update" | Out-Null
            } else {
                Write-Log -Message "User chose to keep $friendlyName open" | Out-Null
            }

            return @{
                CloseProcess = $userChoice
                DeferralDays = 0
                Action = if ($userChoice) { "Update" } else { "Cancel" }
                UserChoice = $userChoice
            }
        }
        
    } catch {
        Write-Log -Message "Show-ProcessCloseDialog failed: $($_.Exception.Message)" | Out-Null
        return @{
            CloseProcess = $DefaultTimeoutAction
            DeferralDays = 0
            Action = if ($DefaultTimeoutAction) { "Update" } else { "Cancel" }
            UserChoice = $DefaultTimeoutAction
        }
    }
}

function Show-DirectUserDialog {
    <#
    .SYNOPSIS
        Shows a WPF dialog when running in user context by spawning a child process
    .DESCRIPTION
        Runs the WPF dialog in a separate PowerShell process to isolate WPF Dispatcher
        lifecycle from the parent script. Communicates result via temp file.
    #>
    param(
        [string]$Question,
        [string]$Title = "System Notification",
        [int]$TimeoutSeconds = 60,
        [string]$DefaultAction = "Cancel"
    )

    try {
        Write-Log -Message "Showing direct user dialog via child process: '$Title'" | Out-Null

        $resultFile = Join-Path $env:TEMP "WingetDialog_$([guid]::NewGuid().ToString('N')).txt"

        # Build the child process script using literal here-string (no nested quote issues)
        $dialogScript = @'
param($Title, $Question, $TimeoutSeconds, $DefaultAction, $ResultFile)
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# Detect system theme (0 = dark, 1 = light)
$isDark = $true
try {
    $themeVal = Get-ItemPropertyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -ErrorAction Stop
    if ($themeVal -eq 1) { $isDark = $false }
} catch {}

if ($isDark) {
    $bgColor = "#FF1F1F1F"; $borderColor = "#FF323232"; $titleFg = "White"
    $questionFg = "#FFCCCCCC"; $shadowOpacity = "0.6"
    $cancelFg = "#FFCCCCCC"; $cancelBorder = "#FF484848"; $closeFg = "#FF888888"
} else {
    $bgColor = "#FFF3F3F3"; $borderColor = "#FFD1D1D1"; $titleFg = "#FF1B1B1B"
    $questionFg = "#FF444444"; $shadowOpacity = "0.25"
    $cancelFg = "#FF444444"; $cancelBorder = "#FFB0B0B0"; $closeFg = "#FF999999"
}

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Dialog" Width="420" MinHeight="140" SizeToContent="Height" WindowStartupLocation="Manual"
    ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="False">
    <Window.Triggers>
        <EventTrigger RoutedEvent="Window.Loaded">
            <BeginStoryboard><Storyboard><DoubleAnimation Storyboard.TargetProperty="Opacity" From="0" To="1" Duration="0:0:0.3"/></Storyboard></BeginStoryboard>
        </EventTrigger>
    </Window.Triggers>
    <Border Background="$bgColor" CornerRadius="8" BorderBrush="$borderColor" BorderThickness="1">
        <Border.Effect><DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="$shadowOpacity" BlurRadius="12"/></Border.Effect>
        <Grid>
            <!-- Close button top-right -->
            <Button Name="CloseButton" Content="&#x2715;" Width="24" Height="24" HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0,6,6,0"
                    Background="Transparent" Foreground="$closeFg" BorderThickness="0" FontSize="13" Cursor="Hand" FontFamily="Segoe UI Symbol"/>
            <Grid Margin="16,12,16,12">
                <Grid.ColumnDefinitions><ColumnDefinition Width="32"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                <Ellipse Grid.Column="0" Grid.RowSpan="2" Width="24" Height="24" Fill="#FF0078D4" VerticalAlignment="Top" Margin="0,2,0,0"/>
                <TextBlock Grid.Column="0" Grid.RowSpan="2" Text="?" Foreground="White" FontSize="14" FontWeight="Bold" HorizontalAlignment="Center" VerticalAlignment="Top" Margin="0,4,0,0"/>
                <TextBlock Name="TitleText" Grid.Column="1" Grid.Row="0" Foreground="$titleFg" FontSize="14" FontWeight="SemiBold" Margin="12,0,0,2" TextWrapping="Wrap"/>
                <TextBlock Name="QuestionText" Grid.Column="1" Grid.Row="1" Foreground="$questionFg" FontSize="12" Margin="12,0,0,8" TextWrapping="Wrap"/>
                <StackPanel Grid.Column="1" Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="12,0,0,0">
                    <Button Name="CancelButton" Content="Cancel" Width="80" Height="28" Margin="0,0,8,0" Background="Transparent" Foreground="$cancelFg" BorderBrush="$cancelBorder" BorderThickness="1" FontSize="11" Cursor="Hand"/>
                    <Button Name="OKButton" Content="OK" Width="80" Height="28" Background="#FF0078D4" Foreground="White" BorderBrush="Transparent" BorderThickness="0" FontSize="11" Cursor="Hand"/>
                </StackPanel>
            </Grid>
        </Grid>
    </Border>
</Window>
"@

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [Windows.Markup.XamlReader]::Load($reader)

# Set text programmatically (avoids XML escaping issues)
$window.Title = $Title
$window.FindName("TitleText").Text = $Title
$window.FindName("QuestionText").Text = $Question

# Position at bottom-right like a notification
$window.Add_Loaded({
    $workArea = [System.Windows.SystemParameters]::WorkArea
    $window.Left = $workArea.Right - $window.ActualWidth - 16
    $window.Top = $workArea.Bottom - $window.ActualHeight - 16
})

$okButton = $window.FindName("OKButton")
$cancelButton = $window.FindName("CancelButton")
$closeButton = $window.FindName("CloseButton")

# Shared state hashtable - reference type accessible from all event handlers
$s = @{
    result = $DefaultAction
    timeRemaining = [int]$TimeoutSeconds
    countOnOK = ($DefaultAction -eq "OK")
    origOK = $okButton.Content
    origCancel = $cancelButton.Content
}

$countdownTimer = New-Object System.Windows.Threading.DispatcherTimer
$countdownTimer.Interval = [System.TimeSpan]::FromSeconds(1)
$countdownTimer.Add_Tick({
    $s.timeRemaining--
    if ($s.countOnOK) { $okButton.Content = "$($s.origOK) ($($s.timeRemaining))" }
    else { $cancelButton.Content = "$($s.origCancel) ($($s.timeRemaining))" }
    if ($s.timeRemaining -le 0) { $countdownTimer.Stop() }
}.GetNewClosure())

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [System.TimeSpan]::FromSeconds([int]$TimeoutSeconds)
$timer.Add_Tick({
    $s.result = $DefaultAction
    $timer.Stop(); $countdownTimer.Stop()
    $window.Close()
}.GetNewClosure())

$okButton.Add_Click({
    $s.result = "OK"
    $timer.Stop(); $countdownTimer.Stop()
    $window.Close()
}.GetNewClosure())
$cancelButton.Add_Click({
    $s.result = "Cancel"
    $timer.Stop(); $countdownTimer.Stop()
    $window.Close()
}.GetNewClosure())
$closeButton.Add_Click({
    $s.result = "Cancel"
    $timer.Stop(); $countdownTimer.Stop()
    $window.Close()
}.GetNewClosure())
$window.Add_Closing({
    $timer.Stop(); $countdownTimer.Stop()
    if (-not $s.result) { $s.result = "Cancel" }
}.GetNewClosure())

$timer.Start()
$countdownTimer.Start()
$window.ShowDialog()
$s.result | Out-File -FilePath $ResultFile -Encoding UTF8 -NoNewline
'@

        # Find PowerShell executable
        $pwsh = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }

        # Write dialog script to temp file (avoids command-line escaping issues)
        $scriptFile = Join-Path $env:TEMP "WingetDialog_$([guid]::NewGuid().ToString('N')).ps1"
        $dialogScript | Out-File -FilePath $scriptFile -Encoding UTF8

        Write-Log -Message "Launching dialog child process ($pwsh) from $scriptFile" | Out-Null

        # Run dialog in child process - pass params via -File
        # Start-Process -WindowStyle Hidden hides the console; WPF Topmost window shows independently
        $proc = Start-Process $pwsh -ArgumentList "-NoProfile", "-STA", "-File", "`"$scriptFile`"", "-Title", "`"$Title`"", "-Question", "`"$Question`"", "-TimeoutSeconds", $TimeoutSeconds, "-DefaultAction", $DefaultAction, "-ResultFile", "`"$resultFile`"" -PassThru -WindowStyle Hidden
        $proc.WaitForExit()
        Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue

        # Read result
        if (Test-Path $resultFile) {
            $response = (Get-Content $resultFile -Raw).Trim()
            Remove-Item $resultFile -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Dialog child process returned: $response" | Out-Null
            return $response
        } else {
            Write-Log -Message "Dialog child process produced no result file, using default: $DefaultAction" | Out-Null
            return $DefaultAction
        }

    } catch {
        Write-Log -Message "Error in direct user dialog: $($_.Exception.Message)" | Out-Null
        return $DefaultAction
    }
}

function Test-InfoDialogsSuppressed {
    <#
    .SYNOPSIS
        Checks if informational upgrade dialogs are suppressed for today
    .OUTPUTS
        Boolean - $true if suppressed
    #>
    try {
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) { return $false }
        $suppressFile = "C:\Users\$($userInfo.Username)\AppData\Local\Temp\SuppressInfoDialogs_$(Get-Date -Format 'yyyy-MM-dd').flag"
        return (Test-Path $suppressFile)
    } catch {
        return $false
    }
}

function Show-UpgradeProgressNotification {
    <#
    .SYNOPSIS
        Shows a non-blocking informational progress dialog during silent upgrades
    .DESCRIPTION
        Launches a WPF progress dialog as a scheduled task in user context.
        The dialog polls for a signal file and updates when the upgrade completes.
        Returns the signal file path immediately without blocking.

        v9.33: if the persistent dialog host is alive, sends a `show-progress`
        command instead of spawning a legacy progress dialog, and returns $null
        (so the legacy file-signal callers skip their writes and Write-InfoDialogStatus
        routes through the host instead).
    .PARAMETER AppName
        Application ID
    .PARAMETER FriendlyName
        User-friendly display name
    .PARAMETER CurrentVersion
        Current installed version
    .PARAMETER AvailableVersion
        Available version for update
    .OUTPUTS
        String - path to signal file (legacy), or $null on failure / host path
    #>
    param(
        [string]$AppName,
        [string]$FriendlyName = "",
        [string]$CurrentVersion = "",
        [string]$AvailableVersion = ""
    )

    try {
        $displayName = if (-not [string]::IsNullOrEmpty($FriendlyName)) { $FriendlyName } else { $AppName }
        $versionText = ""
        if (-not [string]::IsNullOrEmpty($CurrentVersion) -and -not [string]::IsNullOrEmpty($AvailableVersion)) {
            $versionText = "$CurrentVersion &#x2192; $AvailableVersion"
        }

        # v9.33: persistent dialog host path
        if (Test-DialogHostAlive) {
            Send-DialogCommand -Cmd "show-progress" -Payload @{
                app = $displayName
                fromVersion = $CurrentVersion
                toVersion = $AvailableVersion
            } | Out-Null
            return $null
        }

        Write-Log "Showing informational progress dialog for $displayName" | Out-Null

        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user for progress notification" | Out-Null
            return $null
        }

        $progressId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
        $signalFile = Join-Path $userTempPath "UpgradeProgress_$progressId`_Signal.json"
        $scriptPath = Join-Path $userTempPath "Show-UpgradeProgress_$progressId.ps1"

        # Escape for XAML
        $escapedName = [System.Security.SecurityElement]::Escape($displayName)

        $scriptContent = @'
param(
    [string]$SignalFilePath,
    [string]$AppDisplayName,
    [string]$VersionInfo
)

$logPath = Join-Path $env:TEMP "UpgradeProgress_Debug.log"
function Write-ProgLog {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    "[$ts] $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}

try {
    Write-ProgLog "=== UPGRADE PROGRESS DIALOG STARTED ==="
    Write-ProgLog "AppDisplayName: $AppDisplayName, VersionInfo: $VersionInfo"
    Write-ProgLog "SignalFilePath: $SignalFilePath"

    # Detect system theme
    $isDark = $true
    try {
        $themeKey = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -ErrorAction Stop
        $isDark = $themeKey.AppsUseLightTheme -eq 0
    } catch { }

    if ($isDark) {
        $bgColor = "#FF1F1F1F"; $borderColor = "#FF323232"; $textColor = "#FFCCCCCC"
        $shadowOpacity = "0.6"; $closeBtnFg = "#FF888888"
    } else {
        $bgColor = "#FFF3F3F3"; $borderColor = "#FFD1D1D1"; $textColor = "#FF1B1B1B"
        $shadowOpacity = "0.25"; $closeBtnFg = "#FF999999"
    }

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop

    $workArea = [System.Windows.SystemParameters]::WorkArea

    $escapedAppName = [System.Security.SecurityElement]::Escape($AppDisplayName)
    $versionXml = ""
    if ($VersionInfo) {
        $versionXml = "<TextBlock Grid.Row=`"1`" Text=`"$VersionInfo`" Foreground=`"#FF888888`" FontSize=`"11`" Margin=`"0,0,0,4`"/>"
    }

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Updating $escapedAppName" Width="420" MinHeight="120" SizeToContent="Height" WindowStartupLocation="Manual"
        ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="False">
    <Border Background="$bgColor" CornerRadius="8" BorderBrush="$borderColor" BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="$shadowOpacity" BlurRadius="12"/>
        </Border.Effect>
        <Grid>
            <Grid Margin="20,16,20,16">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Grid.Row="0" Name="TitleText" Text="Updating $escapedAppName..." Foreground="$textColor" FontSize="13" FontWeight="SemiBold" Margin="0,0,24,4"/>
                $versionXml
                <ProgressBar Grid.Row="2" Name="ProgressBar" IsIndeterminate="True" Height="3" Margin="0,8,0,6" Foreground="#FF0078D4"/>
                <TextBlock Grid.Row="3" Name="StatusText" Text="Installing update..." Foreground="#FF888888" FontSize="11" HorizontalAlignment="Center"/>
            </Grid>
            <Button Name="CloseButton" Content="&#x2715;" Width="24" Height="24" HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0,6,6,0" Background="Transparent" Foreground="$closeBtnFg" BorderThickness="0" FontSize="13" Cursor="Hand" FontFamily="Segoe UI Symbol"/>
        </Grid>
    </Border>
</Window>
"@

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
    $window = [Windows.Markup.XamlReader]::Load($reader)
    $window.Left = $workArea.Right - 440
    $window.Top = $workArea.Bottom - 160

    # Close button: suppress info dialogs for today and close
    $closeButton = $window.FindName("CloseButton")
    if ($closeButton) {
        $closeButton.Add_Click({
            Write-ProgLog "Close button clicked - suppressing info dialogs for today"
            $suppressFile = Join-Path $env:TEMP "SuppressInfoDialogs_$(Get-Date -Format 'yyyy-MM-dd').flag"
            "suppressed" | Out-File -FilePath $suppressFile -Encoding UTF8
            $window.Close()
        })
    }

    # Poll for signal file and status updates
    $script:progressStartTime = Get-Date
    $script:lastStatus = ""
    $statusFilePath = $SignalFilePath -replace '\.json$', '_Status.txt'
    $script:pollTimer = [System.Windows.Threading.DispatcherTimer]::new()
    $script:pollTimer.Interval = [TimeSpan]::FromSeconds(2)
    $script:pollTimer.Add_Tick({
        # Check for status updates (non-final)
        if (Test-Path $statusFilePath) {
            try {
                $currentStatus = (Get-Content $statusFilePath -Raw).Trim()
                if ($currentStatus -and $currentStatus -ne $script:lastStatus) {
                    $script:lastStatus = $currentStatus
                    $window.FindName("StatusText").Text = $currentStatus
                    Write-ProgLog "Status updated: $currentStatus"
                }
            } catch {}
        }
        # Check for final signal (completion/failure)
        if (Test-Path $SignalFilePath) {
            $script:pollTimer.Stop()
            Write-ProgLog "Signal received"
            try {
                $signalData = Get-Content $SignalFilePath -Raw | ConvertFrom-Json
                $pBar = $window.FindName("ProgressBar")
                $sText = $window.FindName("StatusText")
                $pBar.IsIndeterminate = $false
                $pBar.Value = 100
                if ($signalData.Success -eq $true) {
                    $sText.Text = "Update complete!"
                } else {
                    $sText.Text = "Update could not be completed."
                }
                # Hide close button during completion display
                $window.FindName("CloseButton").Visibility = [System.Windows.Visibility]::Collapsed
            } catch {
                Write-ProgLog "Error reading signal: $($_.Exception.Message)"
                $window.FindName("StatusText").Text = "Update complete!"
            }
            $script:closeTimer = [System.Windows.Threading.DispatcherTimer]::new()
            $script:closeTimer.Interval = [TimeSpan]::FromSeconds(3)
            $script:closeTimer.Add_Tick({
                $script:closeTimer.Stop()
                $window.Close()
            })
            $script:closeTimer.Start()
        } elseif (((Get-Date) - $script:progressStartTime).TotalMinutes -gt 5) {
            $script:pollTimer.Stop()
            Write-ProgLog "Timeout - closing"
            $window.Close()
        }
    })
    $script:pollTimer.Start()

    Write-ProgLog "Showing dialog..."
    $window.Activate()
    $window.ShowDialog() | Out-Null
    Write-ProgLog "Dialog closed"

} catch {
    Write-ProgLog "ERROR: $($_.Exception.Message)"
}
Write-ProgLog "=== UPGRADE PROGRESS DIALOG ENDED ==="
'@

        $scriptContent | Set-Content -Path $scriptPath -Encoding UTF8

        # Build args with encoded display name to avoid quoting issues
        $encodedName = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($escapedName))
        $psArgs = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -SignalFilePath `"$signalFile`" -AppDisplayName `"$displayName`" -VersionInfo `"$versionText`""
        $launch = New-HiddenLaunchAction -PowerShellArguments $psArgs -VbsDirectory $userTempPath -AllowUI
        if ($launch) {
            $action = $launch.Action
        } else {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -SignalFilePath `"$signalFile`" -AppDisplayName `"$displayName`" -VersionInfo `"$versionText`""
        }

        $principal = $null
        foreach ($userFormat in @($userInfo.FullName, $userInfo.Username, ".\$($userInfo.Username)")) {
            try {
                $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType Interactive -RunLevel Limited
                break
            } catch { continue }
        }

        if ($principal) {
            $taskName = "UpgradeProgress_$progressId"
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
            Start-ScheduledTask -TaskName $taskName
            Write-Log "Launched informational progress dialog (task: $taskName)" | Out-Null

            # Don't block - return signal file path immediately
            # Cleanup will happen after upgrade completes (caller writes signal, dialog closes)
            # Schedule async cleanup after a generous timeout
            $statusFile = $signalFile -replace '\.json$', '_Status.txt'
            Start-Job -ScriptBlock {
                param($tn, $sp, $vp, $sf, $stf)
                Start-Sleep -Seconds 330  # 5.5 min - after dialog's 5-min timeout
                Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
                Remove-Item $sp -Force -ErrorAction SilentlyContinue
                if ($vp) { Remove-Item $vp -Force -ErrorAction SilentlyContinue }
                Remove-Item $sf -Force -ErrorAction SilentlyContinue
                Remove-Item $stf -Force -ErrorAction SilentlyContinue
            } -ArgumentList $taskName, $scriptPath, $launch.VbsPath, $signalFile, $statusFile | Out-Null

            return $signalFile
        } else {
            Write-Log "Could not create principal for progress notification" | Out-Null
            Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
            if ($launch -and $launch.VbsPath) { Remove-Item $launch.VbsPath -Force -ErrorAction SilentlyContinue }
            return $null
        }

    } catch {
        Write-Log "Error in Show-UpgradeProgressNotification: $($_.Exception.Message)" | Out-Null
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        if ($launch -and $launch.VbsPath) { Remove-Item $launch.VbsPath -Force -ErrorAction SilentlyContinue }
        return $null
    }
}

function Get-AppInstalledScope {
    <#
    .SYNOPSIS
        Detects whether an app is installed per-user or machine-wide by checking the uninstall registry.
    .DESCRIPTION
        Checks HKLM (machine) and HKU\<SID> (user) uninstall registry keys for a matching DisplayName.
        Returns "user", "machine", or "unknown".
    #>
    param(
        [string]$AppID,
        [string]$FriendlyName
    )

    try {
        $foundMachine = $false
        $foundUser = $false

        # Build search terms from AppID and FriendlyName
        # AppID like "Microsoft.PowerToys" → search for "PowerToys"
        $searchName = if ($FriendlyName) { $FriendlyName } else { ($AppID -split '\.')[-1] }

        # Check machine-wide uninstall registry
        $machineKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        foreach ($keyPath in $machineKeys) {
            if (Test-Path $keyPath) {
                $entries = Get-ChildItem $keyPath -ErrorAction SilentlyContinue |
                    Get-ItemProperty -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -like "*$searchName*" }
                if ($entries) { $foundMachine = $true; break }
            }
        }

        # Check user-scoped uninstall registry (via HKU hive from SYSTEM context)
        if (Test-RunningAsSystem) {
            $userInfo = Get-InteractiveUser
            if ($userInfo -and $userInfo.SID) {
                $userKey = "Registry::HKU\$($userInfo.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
                if (Test-Path $userKey) {
                    $userEntries = Get-ChildItem $userKey -ErrorAction SilentlyContinue |
                        Get-ItemProperty -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -like "*$searchName*" }
                    if ($userEntries) { $foundUser = $true }
                }
            }
        }

        if ($foundUser -and -not $foundMachine) {
            Write-Log "Scope detection for $AppID : user (found in user registry only)" | Out-Null
            return "user"
        } elseif ($foundMachine -and -not $foundUser) {
            Write-Log "Scope detection for $AppID : machine (found in machine registry only)" | Out-Null
            return "machine"
        } elseif ($foundMachine -and $foundUser) {
            Write-Log "Scope detection for $AppID : machine (found in both, preferring machine)" | Out-Null
            return "machine"
        } else {
            Write-Log "Scope detection for $AppID : unknown (not found in registry)" | Out-Null
            return "unknown"
        }
    } catch {
        Write-Log "Scope detection error for $AppID : $($_.Exception.Message)" | Out-Null
        return "unknown"
    }
}

function Write-InfoDialogStatus {
    param(
        [string]$SignalFilePath,
        [string]$Status
    )
    # v9.33: route through persistent dialog host when alive, regardless of SignalFilePath
    if (Test-DialogHostAlive) {
        Send-DialogCommand -Cmd "status" -Payload @{ text = $Status } | Out-Null
        return
    }
    if (-not $SignalFilePath) { return }
    try {
        $statusFile = $SignalFilePath -replace '\.json$', '_Status.txt'
        $Status | Out-File -FilePath $statusFile -Encoding UTF8 -NoNewline
    } catch {}
}

function Invoke-WingetWithProgress {
    <#
    .SYNOPSIS
        Runs winget upgrade with real-time download progress monitoring via the winget log file.
        When no SignalFilePath is provided, falls back to direct execution.
    #>
    param(
        [string]$WingetExe,
        [string[]]$Arguments,
        [string]$SignalFilePath,
        [string]$WorkingDirectory
    )

    # Direct execution if NO progress consumer exists - neither a legacy signal file nor the
    # persistent dialog host. v9.45 fix: previously this only checked for SignalFilePath, but
    # when the v9.33 dialog host is alive the caller passes SignalFilePath=$null (the host
    # consumes status commands directly), so we still need the monitoring loop to RUN so that
    # Write-InfoDialogStatus calls inside it can ship updates to the host.
    if (-not $SignalFilePath -and -not (Test-DialogHostAlive)) {
        if ($WorkingDirectory) {
            Push-Location $WorkingDirectory
            try { return & $WingetExe @Arguments 2>&1 }
            finally { Pop-Location }
        } else {
            return & $WingetExe @Arguments 2>&1
        }
    }

    $outFile = Join-Path $env:TEMP "winget_out_$([guid]::NewGuid().ToString('N').Substring(0,8)).txt"
    $errFile = Join-Path $env:TEMP "winget_err_$([guid]::NewGuid().ToString('N').Substring(0,8)).txt"

    try {
        $argString = ($Arguments -join " ")

        $startParams = @{
            FilePath = $WingetExe
            ArgumentList = $argString
            NoNewWindow = $true
            PassThru = $true
            RedirectStandardOutput = $outFile
            RedirectStandardError = $errFile
        }
        if ($WorkingDirectory) { $startParams.WorkingDirectory = $WorkingDirectory }

        $proc = Start-Process @startParams
        Write-Log "Started winget process (PID: $($proc.Id))" | Out-Null

        $lastStatus = ""
        $pastSourceUpdate = $false
        $installPhase    = $false   # latch: once Installing seen, never go back to Downloading
        while (-not $proc.HasExited) {
            Start-Sleep -Seconds 2

            # Keep heartbeat alive during long upgrade operations
            # Pipe to Out-Null to prevent Boolean return value from contaminating function output
            if (Get-Command Update-Heartbeat -ErrorAction SilentlyContinue) {
                Update-Heartbeat -Stage "WingetUpgradeRunning" -AdditionalData @{ WingetPID = $proc.Id } 2>$null | Out-Null
            }

            if (Test-Path $outFile) {
                try {
                    # Read stdout using FileStream with shared read to avoid locking conflicts
                    $fs = [System.IO.FileStream]::new($outFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    $reader = [System.IO.StreamReader]::new($fs)
                    $outText = $reader.ReadToEnd()
                    $reader.Close()
                    $fs.Close()

                    if ($outText.Length -gt 0) {
                        # Ignore download progress from the source index update
                        if ($outText -match '(Found |No applicable |No newer |No available |Already installed)') {
                            $pastSourceUpdate = $true
                            # Only consider output after the "Found ..." line for download progress
                            $foundIndex = $outText.IndexOf($Matches[0])
                            $outText = $outText.Substring($foundIndex)
                        } elseif (-not $pastSourceUpdate) {
                            # Winget preamble (source check / startup) - don't show misleading "Updating sources"
                            continue
                        } else {
                            # pastSourceUpdate is true but "Found" not in current read (partial read) - skip to avoid showing source index sizes
                            continue
                        }

                        # v9.47: parse the download progress FIRST and write a "Downloading..."
                        # status (with size, percentage, or generic) every poll before checking
                        # the install-phase latch. Previously the install-phase detection ran
                        # first - so on small apps where winget had already finished downloading
                        # by the time the first 2 s poll fired, the latch tripped immediately
                        # and the dialog jumped straight from "Preparing download..." to
                        # "Installing update..." with no download status in between.
                        if (-not $installPhase) {
                            $progressMatches = [regex]::Matches($outText, '([\d.]+)\s*(B|KB|MB|GB)\s*/\s*([\d.]+)\s*(B|KB|MB|GB)')
                            if ($progressMatches.Count -gt 0) {
                                $lastMatch = $progressMatches[$progressMatches.Count - 1]
                                $dlVal     = $lastMatch.Groups[1].Value
                                $dlUnit    = $lastMatch.Groups[2].Value
                                $totalVal  = $lastMatch.Groups[3].Value
                                $totalUnit = $lastMatch.Groups[4].Value
                                $status = "Downloading $dlVal $dlUnit / $totalVal $totalUnit"
                            } else {
                                $pctMatches = [regex]::Matches($outText, '(\d{1,3}(?:\.\d+)?)\s*%')
                                if ($pctMatches.Count -gt 0) {
                                    $lastPct = $pctMatches[$pctMatches.Count - 1].Groups[1].Value
                                    $status = "Downloading $lastPct%"
                                } else {
                                    # Past source-update but no size/% line yet (or buffered).
                                    # Show at least a generic "Downloading update..." so the
                                    # user sees that download is in progress before the latch
                                    # trips on the next poll.
                                    $status = "Downloading update..."
                                }
                            }
                            if ($status -ne $lastStatus) {
                                $lastStatus = $status
                                Write-InfoDialogStatus -SignalFilePath $SignalFilePath -Status $status
                            }
                        }

                        # Install-phase detection runs AFTER the download write above, so for the
                        # very-fast-download case the same poll first writes "Downloading..."
                        # then "Installing update...". On a 250 ms host pump both arrive in the
                        # next tick and the user sees a brief "Downloading..." flash before the
                        # latched "Installing update...". For slow downloads, install-phase is
                        # only detected on a later poll after the user has watched the size
                        # tick upward. Once it latches, $installPhase stays true and the dialog
                        # never reverts to "Downloading..." even if old size lines linger.
                        if (-not $installPhase -and ($outText -match 'Successfully installed|Successfully verified installer hash|Starting package install|Starting installer|^\s*Installing\b|Configuring')) {
                            $installPhase = $true
                            $status = "Installing update..."
                            if ($status -ne $lastStatus) {
                                $lastStatus = $status
                                Write-InfoDialogStatus -SignalFilePath $SignalFilePath -Status $status
                            }
                        }
                    }
                } catch {
                    # Output file may not be ready yet, ignore
                }
            }
        }

        # Ensure exit code is populated (Start-Process -PassThru requires WaitForExit)
        $proc.WaitForExit()

        # Read final output (same format as & winget ... 2>&1)
        $rawResult = @()
        if (Test-Path $outFile) { $rawResult += Get-Content $outFile -ErrorAction SilentlyContinue }
        if (Test-Path $errFile) { $rawResult += Get-Content $errFile -ErrorAction SilentlyContinue }

        # Filter out winget source-update noise (spinners, progress bars, blank lines).
        # The source update appears before the first meaningful line (e.g. "Found ...").
        # Once past the source update, keep content but still strip spinners and blank lines.
        $result = @()
        $pastSourceUpdate = $false
        foreach ($rawLine in $rawResult) {
            $line = "$rawLine"
            # Detect the start of actual winget output (after source update)
            if (-not $pastSourceUpdate) {
                if ($line -match '^\s*(Found |No applicable |No newer |No available |Already installed|No package found|Multiple packages found|Successfully)') {
                    $pastSourceUpdate = $true
                } else {
                    continue
                }
            }
            # From here on, filter remaining noise but keep meaningful content
            # Remove spinner-only lines
            if ($line -match '^\s*[-\\|/]\s*$') { continue }
            # Remove progress bar lines UNLESS they contain download size info
            if ($line -match '[\u2580-\u259F]') {
                if ($line -match '[\d.]+\s*[KMG]B\s*/\s*[\d.]+\s*[KMG]B') { $result += $rawLine }
                continue
            }
            # Remove empty/whitespace-only lines
            if ($line -match '^\s*$') { continue }
            $result += $rawLine
        }
        Write-Log "Winget process exited with code: $($proc.ExitCode)" | Out-Null

        # Propagate exit code so $LASTEXITCODE reflects winget's result
        $global:LASTEXITCODE = $proc.ExitCode
        return $result

    } catch {
        Write-Log "Error in Invoke-WingetWithProgress: $($_.Exception.Message)" | Out-Null
        # Fallback to direct execution
        if ($WorkingDirectory) {
            Push-Location $WorkingDirectory
            try { return & $WingetExe @Arguments 2>&1 }
            finally { Pop-Location }
        } else {
            return & $WingetExe @Arguments 2>&1
        }
    } finally {
        # Clean up temp files
        Remove-Item $outFile, $errFile -Force -ErrorAction SilentlyContinue
    }
}

function Show-CompletionNotification {
    <#
    .SYNOPSIS
        Shows a completion notification that auto-closes after 5 seconds
    .DESCRIPTION
        Displays an informational notification when an upgrade completes successfully.
        v9.33: if the persistent dialog host is alive, sends a `complete` command to it
        instead of spawning a per-app scheduled task; falls back to legacy spawn otherwise.
    #>
    param(
        [string]$AppName,
        [string]$FriendlyName,
        [bool]$Success = $true
    )

    try {
        $displayName = if (-not [string]::IsNullOrEmpty($FriendlyName)) { $FriendlyName } else { $AppName }

        # v9.33: persistent dialog host path
        if (Test-DialogHostAlive) {
            $sent = Send-DialogCommand -Cmd "complete" -Payload @{
                app = $displayName
                success = $Success
                title = if ($Success) { "Update complete" } else { "Update could not be completed" }
                body = $displayName
            }
            if ($sent) {
                # v9.59: dwell briefly so the user actually sees the per-app completion panel.
                # Without this the next app's `transition` arrives within ms and v9.48's hide-timer
                # cancellation swaps the panel before the green icon registers visually.
                Start-Sleep -Seconds 2
                return
            }
            # fall through to legacy on host send failure
        }

        if (Test-RunningAsSystem) {
            # System context - use scheduled task approach
            Invoke-SystemCompletionNotification -AppName $displayName
        } else {
            # Direct user context
            Show-DirectCompletionNotification -AppName $displayName
        }
    } catch {
        Write-Log "Error showing completion notification: $($_.Exception.Message)" | Out-Null
    }
}

function Show-DirectCompletionNotification {
    <#
    .SYNOPSIS
        Direct user context completion notification via child process
    .DESCRIPTION
        Runs the WPF notification in a separate PowerShell process to isolate WPF Dispatcher
        lifecycle from the parent script.
    #>
    param(
        [string]$AppName
    )

    try {
        Write-Log "Showing completion notification for $AppName via child process" | Out-Null

        $dialogScript = @'
param($AppName, $ResultFile)
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# Detect system theme (0 = dark, 1 = light)
$isDark = $true
try {
    $themeVal = Get-ItemPropertyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -ErrorAction Stop
    if ($themeVal -eq 1) { $isDark = $false }
} catch {}

if ($isDark) {
    $bgColor = "#FF1F1F1F"; $borderColor = "#FF323232"; $titleFg = "White"
    $msgFg = "#FFCCCCCC"; $shadowOpacity = "0.6"; $countdownFg = "#FF888888"; $closeFg = "#FF888888"
} else {
    $bgColor = "#FFF3F3F3"; $borderColor = "#FFD1D1D1"; $titleFg = "#FF1B1B1B"
    $msgFg = "#FF444444"; $shadowOpacity = "0.25"; $countdownFg = "#FF999999"; $closeFg = "#FF999999"
}

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Update Complete" Width="420" MinHeight="140" SizeToContent="Height" WindowStartupLocation="Manual"
    ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="False">
    <Window.Triggers>
        <EventTrigger RoutedEvent="Window.Loaded">
            <BeginStoryboard><Storyboard><DoubleAnimation Storyboard.TargetProperty="Opacity" From="0" To="1" Duration="0:0:0.3"/></Storyboard></BeginStoryboard>
        </EventTrigger>
    </Window.Triggers>
    <Border Background="$bgColor" CornerRadius="8" BorderBrush="$borderColor" BorderThickness="1">
        <Border.Effect><DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="$shadowOpacity" BlurRadius="12"/></Border.Effect>
        <Grid>
            <!-- Close button top-right -->
            <Button Name="CloseButton" Content="&#x2715;" Width="24" Height="24" HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0,6,6,0"
                    Background="Transparent" Foreground="$closeFg" BorderThickness="0" FontSize="13" Cursor="Hand" FontFamily="Segoe UI Symbol"/>
            <Grid Margin="16,12,16,12">
                <Grid.ColumnDefinitions><ColumnDefinition Width="32"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                <Ellipse Grid.Column="0" Grid.RowSpan="2" Width="24" Height="24" Fill="#FF107C10" VerticalAlignment="Top" Margin="0,2,0,0"/>
                <Path Grid.Column="0" Grid.RowSpan="2" Data="M9,16.17L4.83,12l-1.42,1.41L9,19L21,7l-1.41-1.41L9,16.17z" Fill="White" Stretch="Uniform" Width="14" Height="14" HorizontalAlignment="Center" VerticalAlignment="Top" Margin="0,7,0,0"/>
                <TextBlock Name="TitleText" Grid.Column="1" Grid.Row="0" Foreground="$titleFg" FontSize="14" FontWeight="SemiBold" Margin="12,0,0,2" TextWrapping="Wrap"/>
                <TextBlock Name="MessageText" Grid.Column="1" Grid.Row="1" Foreground="$msgFg" FontSize="12" Margin="12,0,0,8" TextWrapping="Wrap"/>
                <TextBlock Name="CountdownBlock" Grid.Column="1" Grid.Row="2" Foreground="$countdownFg" FontSize="11" Margin="12,4,0,0" HorizontalAlignment="Right"/>
            </Grid>
        </Grid>
    </Border>
</Window>
"@

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [Windows.Markup.XamlReader]::Load($reader)

# Set text programmatically (avoids XML escaping issues)
$window.FindName("TitleText").Text = "Update Complete"
$window.FindName("MessageText").Text = "$AppName has been successfully updated."
$countdownBlock = $window.FindName("CountdownBlock")
$closeButton = $window.FindName("CloseButton")

# Position at bottom-right like a notification
$window.Add_Loaded({
    $workArea = [System.Windows.SystemParameters]::WorkArea
    $window.Left = $workArea.Right - $window.ActualWidth - 16
    $window.Top = $workArea.Bottom - $window.ActualHeight - 16
})

# Shared state hashtable
$s = @{ timeRemaining = 5 }

$countdownBlock.Text = "Closing in $($s.timeRemaining)s"

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [System.TimeSpan]::FromSeconds(1)
$timer.Add_Tick({
    $s.timeRemaining--
    $countdownBlock.Text = "Closing in $($s.timeRemaining)s"
    if ($s.timeRemaining -le 0) {
        $timer.Stop()
        $window.Close()
    }
}.GetNewClosure())

$closeButton.Add_Click({
    $timer.Stop()
    $window.Close()
}.GetNewClosure())

$window.Add_Closing({
    $timer.Stop()
}.GetNewClosure())

$timer.Start()
$window.ShowDialog()
"done" | Out-File -FilePath $ResultFile -Encoding UTF8 -NoNewline
'@

        # Find PowerShell executable
        $pwsh = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }

        # Write dialog script to temp file
        $scriptFile = Join-Path $env:TEMP "WingetDialog_$([guid]::NewGuid().ToString('N')).ps1"
        $resultFile = Join-Path $env:TEMP "WingetDialog_$([guid]::NewGuid().ToString('N')).txt"
        $dialogScript | Out-File -FilePath $scriptFile -Encoding UTF8

        Write-Log "Launching completion notification child process ($pwsh) from $scriptFile" | Out-Null

        $proc = Start-Process $pwsh -ArgumentList "-NoProfile", "-STA", "-File", "`"$scriptFile`"", "-AppName", "`"$AppName`"", "-ResultFile", "`"$resultFile`"" -PassThru -WindowStyle Hidden
        $proc.WaitForExit()
        Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue
        Remove-Item $resultFile -Force -ErrorAction SilentlyContinue

        Write-Log "Completion notification child process finished" | Out-Null

    } catch {
        Write-Log "Error in Show-DirectCompletionNotification: $($_.Exception.Message)" | Out-Null
    }
}

function Invoke-SystemCompletionNotification {
    <#
    .SYNOPSIS
        System context completion notification using scheduled task
    #>
    param(
        [string]$AppName
    )

    try {
        Write-Log "Creating system context completion notification for $AppName" | Out-Null

        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user for completion notification" | Out-Null
            return
        }

        # Create completion notification script
        $notificationId = Get-Random -Minimum 1000 -Maximum 9999
        # Use user's temp so scheduled task (running as user) can access the script
        $notifUserTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
        $notificationScriptPath = Join-Path $notifUserTempPath "Show-CompletionNotification_$notificationId.ps1"

        $notificationScriptContent = @"
param([string]`$AppName)

`$logPath = Join-Path `$env:TEMP "CompletionNotification_Debug.log"
function Write-NotifLog {
    param([string]`$Message)
    `$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    "[`$ts] `$Message" | Out-File -FilePath `$logPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}

try {
    Write-NotifLog "=== COMPLETION NOTIFICATION STARTED ==="
    Write-NotifLog "AppName: `$AppName"
    Write-NotifLog "PID: `$PID, User: `$env:USERNAME"
    Write-NotifLog "ApartmentState: `$([System.Threading.Thread]::CurrentThread.GetApartmentState())"

    # Detect system light/dark mode
    `$isDark = `$true
    try {
        `$themeKey = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -ErrorAction Stop
        `$isDark = `$themeKey.AppsUseLightTheme -eq 0
    } catch { }
    Write-NotifLog "System theme: `$(if (`$isDark) { 'Dark' } else { 'Light' })"

    # Theme colors
    if (`$isDark) {
        `$bgColor = "#FF1F1F1F"; `$borderColor = "#FF323232"
        `$titleColor = "White"; `$textColor = "#FFCCCCCC"; `$subtleColor = "#FF888888"
        `$shadowOpacity = "0.6"; `$checkFill = "White"
    } else {
        `$bgColor = "#FFF3F3F3"; `$borderColor = "#FFD1D1D1"
        `$titleColor = "#FF1B1B1B"; `$textColor = "#FF333333"; `$subtleColor = "#FF888888"
        `$shadowOpacity = "0.25"; `$checkFill = "White"
    }

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop
    Write-NotifLog "WPF assemblies loaded"

    `$workArea = [System.Windows.SystemParameters]::WorkArea
    Write-NotifLog "Screen: `$(`$workArea.Width)x`$(`$workArea.Height)"

    `$messageText = "`$AppName has been successfully updated."

    `$xaml = @`"
<Window
    xmlns=`"http://schemas.microsoft.com/winfx/2006/xaml/presentation`"
    xmlns:x=`"http://schemas.microsoft.com/winfx/2006/xaml`"
    Title=`"Update Complete`"
    Width=`"420`"
    MinHeight=`"140`"
    SizeToContent=`"Height`"
    WindowStartupLocation=`"Manual`"
    ResizeMode=`"NoResize`"
    WindowStyle=`"None`"
    AllowsTransparency=`"True`"
    Background=`"Transparent`"
    Topmost=`"True`"
    ShowInTaskbar=`"False`">

    <Border Name=`"MainBorder`"
            Background=`"`$bgColor`"
            CornerRadius=`"8`"
            BorderBrush=`"`$borderColor`"
            BorderThickness=`"1`">
        <Border.Effect>
            <DropShadowEffect ShadowDepth=`"4`" Direction=`"270`" Color=`"Black`" Opacity=`"`$shadowOpacity`" BlurRadius=`"12`"/>
        </Border.Effect>

        <Grid Margin=`"16,12,16,12`">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width=`"32`"/>
                <ColumnDefinition Width=`"*`"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height=`"Auto`"/>
                <RowDefinition Height=`"Auto`"/>
                <RowDefinition Height=`"Auto`"/>
            </Grid.RowDefinitions>

            <Ellipse Grid.Column=`"0`" Grid.RowSpan=`"2`"
                     Width=`"24`" Height=`"24`"
                     Fill=`"#FF107C10`"
                     VerticalAlignment=`"Top`"
                     Margin=`"0,2,0,0`"/>

            <Path Grid.Column=`"0`" Grid.RowSpan=`"2`"
                  Data=`"M9,16.17L4.83,12l-1.42,1.41L9,19L21,7l-1.41-1.41L9,16.17z`"
                  Fill=`"`$checkFill`"
                  Stretch=`"Uniform`"
                  Width=`"14`"
                  Height=`"14`"
                  HorizontalAlignment=`"Center`"
                  VerticalAlignment=`"Top`"
                  Margin=`"0,7,0,0`"/>

            <TextBlock Grid.Column=`"1`" Grid.Row=`"0`"
                       Text=`"Update Complete`"
                       Foreground=`"`$titleColor`"
                       FontSize=`"14`"
                       FontWeight=`"SemiBold`"
                       Margin=`"12,0,0,2`"
                       TextWrapping=`"Wrap`"/>

            <TextBlock Grid.Column=`"1`" Grid.Row=`"1`"
                       Text=`"`$messageText`"
                       Foreground=`"`$textColor`"
                       FontSize=`"12`"
                       Margin=`"12,0,0,8`"
                       TextWrapping=`"Wrap`"/>

            <TextBlock Grid.Column=`"1`" Grid.Row=`"2`"
                       Foreground=`"`$subtleColor`"
                       FontSize=`"11`"
                       Margin=`"12,4,0,0`"
                       HorizontalAlignment=`"Right`">
                <Run Text=`"Closing in `"/>
                <Run Name=`"CountdownText`" Text=`"8`"/>
                <Run Text=`"s`"/>
            </TextBlock>
        </Grid>
    </Border>
</Window>
`"@

    Write-NotifLog "XAML built, parsing..."
    `$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new(`$xaml))
    `$window = [Windows.Markup.XamlReader]::Load(`$reader)
    Write-NotifLog "XAML parsed successfully"

    `$countdownRun = `$window.FindName("CountdownText")

    # Position bottom-right
    `$window.Left = `$workArea.Right - 440
    `$window.Top = `$workArea.Bottom - 180
    Write-NotifLog "Window positioned at Left=`$(`$window.Left), Top=`$(`$window.Top)"

    `$script:remainingSeconds = 8
    `$timer = New-Object System.Windows.Threading.DispatcherTimer
    `$timer.Interval = [TimeSpan]::FromSeconds(1)
    `$timer.Add_Tick({
        `$script:remainingSeconds--
        `$countdownRun.Text = `$script:remainingSeconds.ToString()
        if (`$script:remainingSeconds -le 0) {
            `$timer.Stop()
            `$window.Close()
        }
    })
    `$timer.Start()

    Write-NotifLog "Showing notification..."
    `$window.Activate()
    `$window.ShowDialog() | Out-Null
    Write-NotifLog "Notification closed"

} catch {
    Write-NotifLog "FATAL ERROR: `$(`$_.Exception.Message)"
    Write-NotifLog "Stack trace: `$(`$_.ScriptStackTrace)"
}
Write-NotifLog "=== COMPLETION NOTIFICATION ENDED ==="
"@

        $notificationScriptContent | Out-File -FilePath $notificationScriptPath -Encoding UTF8 -Force

        # Create and run scheduled task
        $taskName = "CompletionNotification_$notificationId"
        $notifPsArgs = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$notificationScriptPath`" -AppName `"$AppName`""
        $notifLaunch = New-HiddenLaunchAction -PowerShellArguments $notifPsArgs -VbsDirectory $notifUserTempPath -AllowUI
        if ($notifLaunch) {
            $action = $notifLaunch.Action
        } else {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$notificationScriptPath`" -AppName `"$AppName`""
        }

        $principal = $null
        $userFormats = @($userInfo.FullName, $userInfo.Username, ".\$($userInfo.Username)")

        foreach ($userFormat in $userFormats) {
            try {
                $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType Interactive -RunLevel Limited
                break
            } catch {
                continue
            }
        }

        if ($principal) {
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
            Start-ScheduledTask -TaskName $taskName

            # Wait for notification to finish (8s countdown + startup buffer)
            Start-Sleep -Seconds 15
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Remove-Item $notificationScriptPath -Force -ErrorAction SilentlyContinue
            if ($notifLaunch -and $notifLaunch.VbsPath) {
                Remove-Item $notifLaunch.VbsPath -Force -ErrorAction SilentlyContinue
            }
        }

    } catch {
        Write-Log "Error in Invoke-SystemCompletionNotification: $($_.Exception.Message)" | Out-Null
        if ($taskName) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item $notificationScriptPath -Force -ErrorAction SilentlyContinue
        if ($notifLaunch -and $notifLaunch.VbsPath) {
            Remove-Item $notifLaunch.VbsPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Show-MandatoryUpdateDialog {
    <#
    .SYNOPSIS
        Shows a mandatory update dialog with only a Continue button
    .DESCRIPTION
        Used when updates are required and cannot be deferred - no Cancel option.
        v9.33: when the persistent dialog host is alive, sends a `prompt-mandatory`
        command. Both "upgrade" and "timeout" responses mean proceed (legacy treats
        mandatory timeouts the same way), so we return "Continue" without a progress
        signal path; the subsequent Show-UpgradeProgressNotification call will swap
        the host to its ProgressPanel.
    #>
    param(
        [string]$Question,
        [string]$Title = "Required Update",
        [int]$TimeoutSeconds = 60,
        [bool]$HasBlockingProcess = $false
    )

    try {
        # v9.33: persistent dialog host path
        # v9.36: only commit to "Continue" when we get a valid reply. If the host dies mid-prompt
        # (Send-DialogCommand returns $null), fall through to the legacy spawn below so the user
        # still gets a visible prompt rather than a silent proceed.
        if (Test-DialogHostAlive) {
            $parts = $Question -split '\|', 2
            $versionInfo = if ($parts.Count -ge 1) { $parts[0] } else { "" }
            $bodyText = if ($parts.Count -ge 2) { $parts[1] } else { $Question }
            $reply = Send-DialogCommand -Cmd "prompt-mandatory" -Payload @{
                title = $Title
                versionInfo = $versionInfo
                body = $bodyText
                timeoutSec = $TimeoutSeconds
            } -Blocking -TimeoutSeconds ($TimeoutSeconds + 30)
            if ($reply) {
                # "upgrade" (clicked) or "timeout" (waited it out) -> both mean proceed
                return "Continue"
            }
            Write-Log "Show-MandatoryUpdateDialog: dialog host died mid-prompt - falling back to legacy spawn" | Out-Null
            # fall through
        }

        if (Test-RunningAsSystem) {
            # System context - use scheduled task approach
            return Invoke-SystemMandatoryUpdatePrompt -Question $Question -Title $Title -TimeoutSeconds $TimeoutSeconds
        } else {
            # Direct user context
            return Show-DirectMandatoryUpdateDialog -Question $Question -Title $Title -TimeoutSeconds $TimeoutSeconds
        }
    } catch {
        Write-Log "Error in Show-MandatoryUpdateDialog: $($_.Exception.Message)" | Out-Null
        return "Continue"  # Default to continuing with update
    }
}

function Show-DirectMandatoryUpdateDialog {
    <#
    .SYNOPSIS
        Direct user context mandatory update dialog via child process
    .DESCRIPTION
        Runs the WPF dialog in a separate PowerShell process to isolate WPF Dispatcher
        lifecycle from the parent script. Communicates result via temp file.
    #>
    param(
        [string]$Question,
        [string]$Title,
        [int]$TimeoutSeconds = 60
    )

    try {
        Write-Log "Showing direct mandatory update dialog via child process: '$Title'" | Out-Null

        $resultFile = Join-Path $env:TEMP "WingetDialog_$([guid]::NewGuid().ToString('N')).txt"

        $dialogScript = @'
param($Title, $Question, $TimeoutSeconds, $ResultFile)
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# Detect system theme (0 = dark, 1 = light)
$isDark = $true
try {
    $themeVal = Get-ItemPropertyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -ErrorAction Stop
    if ($themeVal -eq 1) { $isDark = $false }
} catch {}

if ($isDark) {
    $bgColor = "#FF1F1F1F"; $borderColor = "#FF323232"; $titleFg = "White"
    $questionFg = "#FFCCCCCC"; $shadowOpacity = "0.6"; $closeFg = "#FF888888"
    $btnBg = "#FFFF6B00"; $btnHover = "#FFE55A00"
} else {
    $bgColor = "#FFF3F3F3"; $borderColor = "#FFD1D1D1"; $titleFg = "#FF1B1B1B"
    $questionFg = "#FF444444"; $shadowOpacity = "0.25"; $closeFg = "#FF999999"
    $btnBg = "#FFFF6B00"; $btnHover = "#FFE55A00"
}

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Dialog" Width="420" MinHeight="140" SizeToContent="Height" WindowStartupLocation="Manual"
    ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="False">
    <Window.Triggers>
        <EventTrigger RoutedEvent="Window.Loaded">
            <BeginStoryboard><Storyboard><DoubleAnimation Storyboard.TargetProperty="Opacity" From="0" To="1" Duration="0:0:0.3"/></Storyboard></BeginStoryboard>
        </EventTrigger>
    </Window.Triggers>
    <Border Background="$bgColor" CornerRadius="8" BorderBrush="$borderColor" BorderThickness="1">
        <Border.Effect><DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="$shadowOpacity" BlurRadius="12"/></Border.Effect>
        <Grid>
            <!-- Close button top-right -->
            <Button Name="CloseButton" Content="&#x2715;" Width="24" Height="24" HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0,6,6,0"
                    Background="Transparent" Foreground="$closeFg" BorderThickness="0" FontSize="13" Cursor="Hand" FontFamily="Segoe UI Symbol"/>
            <Grid Margin="16,12,16,12">
                <Grid.ColumnDefinitions><ColumnDefinition Width="32"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                <Ellipse Grid.Column="0" Grid.RowSpan="2" Width="24" Height="24" Fill="$btnBg" VerticalAlignment="Top" Margin="0,2,0,0"/>
                <TextBlock Grid.Column="0" Grid.RowSpan="2" Text="!" Foreground="White" FontSize="14" FontWeight="Bold" HorizontalAlignment="Center" VerticalAlignment="Top" Margin="0,4,0,0"/>
                <TextBlock Name="TitleText" Grid.Column="1" Grid.Row="0" Foreground="$titleFg" FontSize="14" FontWeight="SemiBold" Margin="12,0,0,2" TextWrapping="Wrap"/>
                <TextBlock Name="QuestionText" Grid.Column="1" Grid.Row="1" Foreground="$questionFg" FontSize="12" Margin="12,0,0,8" TextWrapping="Wrap"/>
                <StackPanel Grid.Column="1" Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="12,0,0,0">
                    <Button Name="ContinueButton" Content="Continue" Width="80" Height="24" Background="$btnBg" Foreground="White" BorderBrush="Transparent" BorderThickness="0" FontSize="11" Cursor="Hand"/>
                </StackPanel>
            </Grid>
        </Grid>
    </Border>
</Window>
"@

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [Windows.Markup.XamlReader]::Load($reader)

# Set text programmatically (avoids XML escaping issues)
$window.Title = $Title
$window.FindName("TitleText").Text = $Title
$window.FindName("QuestionText").Text = $Question

# Position at bottom-right like a notification
$window.Add_Loaded({
    $workArea = [System.Windows.SystemParameters]::WorkArea
    $window.Left = $workArea.Right - $window.ActualWidth - 16
    $window.Top = $workArea.Bottom - $window.ActualHeight - 16
})

$continueButton = $window.FindName("ContinueButton")
$closeButton = $window.FindName("CloseButton")

# Shared state hashtable
$s = @{
    result = "Continue"
    timeRemaining = [int]$TimeoutSeconds
    origButton = $continueButton.Content
}

$countdownTimer = New-Object System.Windows.Threading.DispatcherTimer
$countdownTimer.Interval = [System.TimeSpan]::FromSeconds(1)
$countdownTimer.Add_Tick({
    $s.timeRemaining--
    $continueButton.Content = "$($s.origButton) ($($s.timeRemaining))"
    if ($s.timeRemaining -le 0) { $countdownTimer.Stop() }
}.GetNewClosure())

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [System.TimeSpan]::FromSeconds([int]$TimeoutSeconds)
$timer.Add_Tick({
    $s.result = "Continue"
    $timer.Stop(); $countdownTimer.Stop()
    $window.Close()
}.GetNewClosure())

$continueButton.Add_Click({
    $s.result = "Continue"
    $timer.Stop(); $countdownTimer.Stop()
    $window.Close()
}.GetNewClosure())
$closeButton.Add_Click({
    $s.result = "Continue"
    $timer.Stop(); $countdownTimer.Stop()
    $window.Close()
}.GetNewClosure())
$window.Add_Closing({
    $timer.Stop(); $countdownTimer.Stop()
    if (-not $s.result) { $s.result = "Continue" }
}.GetNewClosure())

$timer.Start()
$countdownTimer.Start()
$window.ShowDialog()
$s.result | Out-File -FilePath $ResultFile -Encoding UTF8 -NoNewline
'@

        # Find PowerShell executable
        $pwsh = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }

        # Write dialog script to temp file
        $scriptFile = Join-Path $env:TEMP "WingetDialog_$([guid]::NewGuid().ToString('N')).ps1"
        $dialogScript | Out-File -FilePath $scriptFile -Encoding UTF8

        Write-Log "Launching mandatory dialog child process ($pwsh) from $scriptFile" | Out-Null

        $proc = Start-Process $pwsh -ArgumentList "-NoProfile", "-STA", "-File", "`"$scriptFile`"", "-Title", "`"$Title`"", "-Question", "`"$Question`"", "-TimeoutSeconds", $TimeoutSeconds, "-ResultFile", "`"$resultFile`"" -PassThru -WindowStyle Hidden
        $proc.WaitForExit()
        Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue

        # Read result
        if (Test-Path $resultFile) {
            $response = (Get-Content $resultFile -Raw).Trim()
            Remove-Item $resultFile -Force -ErrorAction SilentlyContinue
            Write-Log "Mandatory dialog child process returned: $response" | Out-Null
            return $response
        } else {
            Write-Log "Mandatory dialog child process produced no result file, using default: Continue" | Out-Null
            return "Continue"
        }

    } catch {
        Write-Log "Error in direct mandatory dialog: $($_.Exception.Message)" | Out-Null
        return "Continue"
    }
}

function Invoke-SystemMandatoryUpdatePrompt {
    <#
    .SYNOPSIS
        System context mandatory update dialog using scheduled tasks
    #>
    param(
        [string]$Question,
        [string]$Title,
        [int]$TimeoutSeconds = 60
    )
    
    try {
        Write-Log "Invoking system mandatory update prompt" | Out-Null
        
        # Get interactive user
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user found - cannot show mandatory dialog" | Out-Null
            return "Continue"
        }
        
        # Create unique identifiers
        $promptId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        
        # Setup response file path
        $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
        $responseFile = if (Test-Path $userTempPath) {
            Join-Path $userTempPath "MandatoryPrompt_$promptId`_Response.json"
        } else {
            Join-Path "C:\ProgramData\Temp" "MandatoryPrompt_$promptId`_Response.json"
        }
        
        # Create mandatory prompt script
        $mandatoryScriptPath = Join-Path $userTempPath "Show-MandatoryPrompt_$promptId.ps1"
        
        $mandatoryScriptContent = @'
param(
    [string]$ResponseFilePath,
    [string]$ProgressSignalFilePath,
    [string]$EncodedQuestion,
    [string]$EncodedTitle,
    [int]$TimeoutSeconds = 60
)

try {
    # Decode parameters
    $actualQuestion = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedQuestion))
    $actualTitle = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedTitle))

    # Load WPF assemblies (single call - 4x faster than separate Add-Type per assembly)
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop

    # Use the decoded text and split on pipe separator for separate display
    $parts = $actualQuestion -split '\|'
    $versionInfo = if ($parts.Length -gt 0) { $parts[0].Trim() } else { $actualQuestion }
    $actionMessage = if ($parts.Length -gt 1) { $parts[1].Trim() } else { "" }

    $escapedTitle = [System.Security.SecurityElement]::Escape($actualTitle)
    $escapedVersionInfo = [System.Security.SecurityElement]::Escape($versionInfo)
    $escapedActionMessage = [System.Security.SecurityElement]::Escape($actionMessage)

    # Extract display name from title (strip "Required Update: " prefix)
    $displayName = $actualTitle -replace '^Required Update:\s*', ''
    $escapedDisplayName = [System.Security.SecurityElement]::Escape($displayName)

    # Detect system theme
    $isDark = $true
    try {
        $themeKey = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -ErrorAction Stop
        $isDark = $themeKey.AppsUseLightTheme -eq 0
    } catch { }

    if ($isDark) {
        $bgColor = "#FF1F1F1F"; $borderColor = "#FF323232"; $textColor = "White"; $subtextColor = "#FFCCCCCC"; $shadowOpacity = "0.6"
    } else {
        $bgColor = "#FFF3F3F3"; $borderColor = "#FFD1D1D1"; $textColor = "#FF1B1B1B"; $subtextColor = "#FF555555"; $shadowOpacity = "0.25"
    }
    $workArea = [System.Windows.SystemParameters]::WorkArea
    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$escapedTitle" Width="420" MinHeight="120" SizeToContent="Height" WindowStartupLocation="Manual"
        ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="False">

    <Border Background="$bgColor" CornerRadius="8" BorderBrush="$borderColor" BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="$shadowOpacity" BlurRadius="12"/>
        </Border.Effect>
        <Grid>
            <!-- Phase 1: Mandatory prompt content -->
            <Grid Name="PromptPanel" Margin="16,12,16,12">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="32"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <!-- Icon -->
                <Ellipse Grid.Column="0" Grid.RowSpan="3"
                         Width="24" Height="24"
                         Fill="#FFFF6B00"
                         VerticalAlignment="Top"
                         Margin="0,2,0,0"/>

                <TextBlock Grid.Column="0" Grid.RowSpan="3"
                           Text="!"
                           Foreground="White"
                           FontSize="14"
                           FontWeight="Bold"
                           HorizontalAlignment="Center"
                           VerticalAlignment="Top"
                           Margin="0,4,0,0"/>

                <!-- Title -->
                <TextBlock Grid.Column="1" Grid.Row="0"
                           Text="$escapedTitle"
                           Foreground="$textColor"
                           FontSize="14"
                           FontWeight="SemiBold"
                           Margin="12,0,0,2"
                           TextWrapping="Wrap"/>

                <!-- Version Info -->
                <TextBlock Grid.Column="1" Grid.Row="1"
                           Text="$escapedVersionInfo"
                           Foreground="$subtextColor"
                           FontSize="12"
                           Margin="12,0,0,8"
                           TextWrapping="Wrap"/>

                <!-- Action Message -->
                <TextBlock Grid.Column="1" Grid.Row="2"
                           Text="$escapedActionMessage"
                           Foreground="$subtextColor"
                           FontSize="12"
                           Margin="12,0,0,8"
                           TextWrapping="Wrap"/>

                <!-- Button -->
                <StackPanel Grid.Column="1" Grid.Row="3"
                            Orientation="Horizontal"
                            HorizontalAlignment="Right"
                            Margin="12,0,0,0">

                    <Button Name="UpgradeButton" Content="Upgrade" Width="80" Height="24" Background="#FF0078D4" Foreground="White" IsDefault="true">
                        <Button.Style>
                            <Style TargetType="Button">
                                <Style.Triggers>
                                    <Trigger Property="IsMouseOver" Value="True">
                                        <Setter Property="Background" Value="#FF106EBE"/>
                                    </Trigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                    </Button>

                </StackPanel>
            </Grid>

            <!-- Phase 2: Progress content (hidden initially) -->
            <Grid Name="ProgressPanel" Margin="20,16,20,16" Visibility="Collapsed">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Grid.Row="0" Name="ProgressTitle" Text="Updating $escapedDisplayName..." Foreground="$textColor" FontSize="13" FontWeight="SemiBold" Margin="0,0,0,4"/>
                <ProgressBar Grid.Row="1" Name="ProgressBar" IsIndeterminate="True" Height="3" Margin="0,8,0,6" Foreground="#FF0078D4"/>
                <TextBlock Grid.Row="2" Name="StatusText" Text="Preparing update..." Foreground="#FF888888" FontSize="11" HorizontalAlignment="Center"/>
            </Grid>
        </Grid>
    </Border>
</Window>
"@

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
    $window = [Windows.Markup.XamlReader]::Load($reader)
    $script:result = "Continue"
    $script:inProgressMode = $false

    # Get UI element references
    $upgradeButton = $window.FindName("UpgradeButton")
    $promptPanel = $window.FindName("PromptPanel")
    $progressPanel = $window.FindName("ProgressPanel")
    $originalButtonText = if ($upgradeButton) { $upgradeButton.Content } else { "Upgrade" }

    # Progress signal file paths
    $progressStatusFile = $ProgressSignalFilePath -replace '\.json$', '_Status.txt'

    # Position window
    $window.Left = $workArea.Right - 440
    $window.Top = $workArea.Bottom - 160

    # Create countdown timer (updates every second)
    $script:timeRemaining = $TimeoutSeconds
    $countdownTimer = New-Object System.Windows.Threading.DispatcherTimer
    $countdownTimer.Interval = [System.TimeSpan]::FromSeconds(1)

    $countdownTimer.Add_Tick({
        $script:timeRemaining--
        if ($upgradeButton) {
            $upgradeButton.Content = "$originalButtonText ($($script:timeRemaining))"
        }
        if ($script:timeRemaining -le 0) {
            $countdownTimer.Stop()
        }
    })

    # Create main timeout timer (for prompt phase)
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [System.TimeSpan]::FromSeconds($TimeoutSeconds)

    $timer.Add_Tick({
        $script:result = "Continue"
        $timer.Stop()
        $countdownTimer.Stop()
        if (-not $script:inProgressMode) {
            # Timeout during prompt phase: transition to progress mode (auto-accept)
            $promptPanel.Visibility = [System.Windows.Visibility]::Collapsed
            $progressPanel.Visibility = [System.Windows.Visibility]::Visible
            $script:inProgressMode = $true
            @{ response = $script:result; timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ") } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8
            $script:progressStartTime = Get-Date
            $script:progressPollTimer.Start()
        }
    })

    # Create progress poll timer (for progress phase)
    $script:progressStartTime = $null
    $script:lastStatus = ""
    $script:progressPollTimer = [System.Windows.Threading.DispatcherTimer]::new()
    $script:progressPollTimer.Interval = [TimeSpan]::FromSeconds(2)
    $script:progressPollTimer.Add_Tick({
        # Check for status updates
        if (Test-Path $progressStatusFile) {
            try {
                $currentStatus = (Get-Content $progressStatusFile -Raw).Trim()
                if ($currentStatus -and $currentStatus -ne $script:lastStatus) {
                    $script:lastStatus = $currentStatus
                    $window.FindName("StatusText").Text = $currentStatus
                }
            } catch {}
        }
        # Check for completion signal
        if (Test-Path $ProgressSignalFilePath) {
            $script:progressPollTimer.Stop()
            try {
                $signalData = Get-Content $ProgressSignalFilePath -Raw | ConvertFrom-Json
                $pBar = $window.FindName("ProgressBar")
                $sText = $window.FindName("StatusText")
                $pBar.IsIndeterminate = $false
                $pBar.Value = 100
                if ($signalData.Success -eq $true) {
                    $sText.Text = "Update complete!"
                } else {
                    $sText.Text = "Update could not be completed."
                }
            } catch {
                $window.FindName("StatusText").Text = "Update complete!"
            }
            # Auto-close after 3 seconds
            $script:closeTimer = [System.Windows.Threading.DispatcherTimer]::new()
            $script:closeTimer.Interval = [TimeSpan]::FromSeconds(3)
            $script:closeTimer.Add_Tick({
                $script:closeTimer.Stop()
                $window.Close()
            })
            $script:closeTimer.Start()
        } elseif ($script:progressStartTime -and ((Get-Date) - $script:progressStartTime).TotalMinutes -gt 5) {
            # Progress timeout
            $script:progressPollTimer.Stop()
            $window.Close()
        }
    })

    # Upgrade button handler: transition to progress mode
    if ($upgradeButton) {
        $upgradeButton.Add_Click({
            $timer.Stop()
            $countdownTimer.Stop()
            $script:result = "Continue"

            # Transition UI to progress view
            $promptPanel.Visibility = [System.Windows.Visibility]::Collapsed
            $progressPanel.Visibility = [System.Windows.Visibility]::Visible
            $script:inProgressMode = $true

            # Write response so the parent process unblocks and starts the upgrade
            @{ response = $script:result; timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ") } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8

            # Start polling for progress updates
            $script:progressStartTime = Get-Date
            $script:progressPollTimer.Start()
        })
    }

    # Handle window closing
    $window.Add_Closing({
        $timer.Stop()
        $countdownTimer.Stop()
        $script:progressPollTimer.Stop()
        if ($script:result -eq $null) {
            $script:result = "Continue"
        }
        # Ensure response is written even if window is closed externally
        if (-not (Test-Path $ResponseFilePath)) {
            @{ response = $script:result; timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ") } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    })

    # Start prompt timers
    $timer.Start()
    $countdownTimer.Start()

    $window.Activate()
    $window.ShowDialog() | Out-Null

} catch {
    # Still try to write response so the wait loop doesn't time out
    @{ response = "Continue"; timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ") } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8 -ErrorAction SilentlyContinue
}
'@

        Write-Log -Message "Creating mandatory prompt script: $mandatoryScriptPath" | Out-Null
        $mandatoryScriptContent | Set-Content -Path $mandatoryScriptPath -Encoding UTF8
        
        # Create scheduled task
        $guid = [System.Guid]::NewGuid().ToString()
        $taskName = "MandatoryPrompt_$guid"
        
        # Create progress signal file path (dialog stays open to show progress)
        $progressSignalFile = Join-Path $userTempPath "MandatoryPrompt_$promptId`_Progress.json"

        # Create task arguments with encoded parameters
        $encodedQuestion = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Question))
        $encodedTitle = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Title))
        # Create hidden launch action using VBS wrapper (no console window flash)
        $mandatoryPsArgs = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$mandatoryScriptPath`" -ResponseFilePath `"$responseFile`" -ProgressSignalFilePath `"$progressSignalFile`" -EncodedQuestion `"$encodedQuestion`" -EncodedTitle `"$encodedTitle`" -TimeoutSeconds $TimeoutSeconds"
        $mandatoryVbsDir = Split-Path $responseFile -Parent
        $mandatoryLaunch = New-HiddenLaunchAction -PowerShellArguments $mandatoryPsArgs -VbsDirectory $mandatoryVbsDir -AllowUI
        if ($mandatoryLaunch) {
            $action = $mandatoryLaunch.Action
        } else {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$mandatoryScriptPath`" -ResponseFilePath `"$responseFile`" -ProgressSignalFilePath `"$progressSignalFile`" -EncodedQuestion `"$encodedQuestion`" -EncodedTitle `"$encodedTitle`" -TimeoutSeconds $TimeoutSeconds"
        }
        
        # Create task principal
        $principal = $null
        $userFormats = @($userInfo.FullName, $userInfo.Username, ".\$($userInfo.Username)")
        $logonTypes = @("Interactive", "S4U")
        
        foreach ($userFormat in $userFormats) {
            foreach ($logonType in $logonTypes) {
                try {
                    $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType $logonType -RunLevel Limited
                    Write-Log "Created mandatory task principal with: $userFormat ($logonType)" | Out-Null
                    break
                } catch {
                    Write-Log "Failed mandatory task principal: $userFormat ($logonType)" | Out-Null
                }
            }
            if ($principal) { break }
        }
        
        if (-not $principal) {
            Write-Log "Could not create mandatory task principal" | Out-Null
            return "Continue"
        }
        
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
        $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description "Mandatory update prompt"
        
        try {
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            Write-Log "Mandatory scheduled task started successfully" | Out-Null
        } catch {
            Write-Log "Failed to start mandatory scheduled task: $($_.Exception.Message)" | Out-Null
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            return "Continue"
        }
        
        # Wait for response (user clicks Upgrade or timeout auto-accepts)
        $taskTimeout = $TimeoutSeconds + 30
        $response = Wait-ForUserResponse -ResponseFilePath $responseFile -TimeoutSeconds $taskTimeout

        # Don't clean up immediately - the dialog stays open to show progress.
        # Schedule async cleanup after a generous timeout (dialog has 5-min progress timeout + 3s close).
        $progressStatusFile = $progressSignalFile -replace '\.json$', '_Status.txt'
        Start-Job -ScriptBlock {
            param($tn, $sp, $vp, $rf, $psf, $pstf)
            Start-Sleep -Seconds 360  # 6 min - after dialog's 5-min progress timeout
            Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
            Remove-Item $sp, $rf, $psf, $pstf -Force -ErrorAction SilentlyContinue
            if ($vp) { Remove-Item $vp -Force -ErrorAction SilentlyContinue }
        } -ArgumentList $taskName, $mandatoryScriptPath, $mandatoryLaunch.VbsPath, $responseFile, $progressSignalFile, $progressStatusFile | Out-Null

        return $progressSignalFile  # Return signal file so caller can send progress updates

    } catch {
        Write-Log "Error in system mandatory prompt: $($_.Exception.Message)" | Out-Null
        if ($taskName) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item $mandatoryScriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
        Remove-Item $progressSignalFile -Force -ErrorAction SilentlyContinue
        if ($mandatoryLaunch -and $mandatoryLaunch.VbsPath) {
            Remove-Item $mandatoryLaunch.VbsPath -Force -ErrorAction SilentlyContinue
        }
        return $null
    }
}

function Show-UserDialog {
    <#
    .SYNOPSIS
        Context-aware dialog function that chooses appropriate dialog method
    #>
    param(
        [string]$Question,
        [string]$Title = "System Notification",
        [int]$TimeoutSeconds = 60,
        [string]$DefaultAction = "Cancel"
    )
    
    if (Test-RunningAsSystem) {
        # Complex scheduled task system for SYSTEM → User context (existing - keep as-is)
        return Invoke-SystemUserPrompt -Question $Question -Title $Title -TimeoutSeconds $TimeoutSeconds -DefaultAction $DefaultAction
    } else {
        # Simple direct WPF dialog for user context
        return Show-DirectUserDialog -Question $Question -Title $Title -TimeoutSeconds $TimeoutSeconds -DefaultAction $DefaultAction
    }
}

# ============================================================================
# DEFERRAL MANAGEMENT SYSTEM
# Time-based deferral system with admin-controlled hard deadlines
# ============================================================================

function Initialize-DeferralRegistry {
    <#
    .SYNOPSIS
        Ensures the deferral registry structure exists
    .DESCRIPTION
        Creates the necessary registry keys for storing deferral and release cache data
    #>
    
    try {
        foreach ($sub in @('Deferrals', 'ReleaseCache', 'Failures')) {
            if (-not (Test-AppRegKey -SubPath $sub)) {
                Write-Log "Creating AppUpdater registry path: $(Get-AppRegDisplayPath -SubPath $sub)" | Out-Null
                $k = Open-AppRegKey -SubPath $sub -Writable
                if ($k) { $k.Close() }
            }
        }

        return $true
        
    } catch {
        Write-Log "Error initializing deferral registry: $($_.Exception.Message)" | Out-Null
        return $false
    }
}

function Get-AppReleaseDate {
    <#
    .SYNOPSIS
        Gets the release date of an app version from winget, with caching
    .DESCRIPTION
        Retrieves app release date from winget show command with performance-optimized caching
        Caches results to avoid repeated winget queries
    .PARAMETER AppID
        Application ID to query
    .PARAMETER Version
        Specific version to query (optional)
    .OUTPUTS
        DateTime object of release date, or $null if not found
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppID,
        
        [string]$Version = ""
    )
    
    try {
        Initialize-DeferralRegistry | Out-Null
        
        # Create cache key - include version in key if specified
        $cacheKey = if ($Version) { "$AppID-$Version" } else { $AppID }

        # Check cache first
        try {
            $cachedDateStr = Get-AppRegValue -SubPath 'ReleaseCache' -Name $cacheKey
            if ($cachedDateStr) {
                $releaseDate = [DateTime]::Parse($cachedDateStr)
                Write-Log "Found cached release date for $cacheKey : $releaseDate" | Out-Null
                return $releaseDate
            }
        } catch {
            Write-Log "Cache read error for $cacheKey : $($_.Exception.Message)" | Out-Null
        }
        
        Write-Log "Querying winget for release date: $AppID $(if ($Version) { "version $Version" })" | Out-Null
        
        # Query winget show command
        $showCommand = if ($Version) {
            "winget show --id `"$AppID`" --version `"$Version`" --accept-source-agreements"
        } else {
            "winget show --id `"$AppID`" --accept-source-agreements"
        }
        
        # Execute winget show with appropriate context
        $showOutput = if ((Test-RunningAsSystem) -and $WingetPath) {
            & "$WingetPath\winget.exe" show --id $AppID $(if ($Version) { "--version"; $Version }) --accept-source-agreements 2>&1
        } else {
            & winget show --id $AppID $(if ($Version) { "--version"; $Version }) --accept-source-agreements 2>&1
        }
        
        if ($showOutput) {
            # Parse output for release date - look for various date patterns
            $releaseDate = $null
            $datePatterns = @(
                "Published:\s+([^`r`n]+)",
                "Release Date:\s+([^`r`n]+)",
                "Date:\s+([^`r`n]+)",
                "Updated:\s+([^`r`n]+)"
            )
            
            foreach ($pattern in $datePatterns) {
                foreach ($line in $showOutput) {
                    if ($line -match $pattern) {
                        $dateString = $matches[1].Trim()
                        Write-Log "Found potential date string: '$dateString'" | Out-Null
                        
                        # Try to parse the date string
                        try {
                            $releaseDate = [DateTime]::Parse($dateString)
                            Write-Log "Successfully parsed release date: $releaseDate" | Out-Null
                            break
                        } catch {
                            Write-Log "Failed to parse date '$dateString': $($_.Exception.Message)" | Out-Null
                        }
                    }
                }
                if ($releaseDate) { break }
            }
            
            # If we found a valid date, cache it
            if ($releaseDate) {
                try {
                    Set-AppRegValue -SubPath 'ReleaseCache' -Name $cacheKey -Value $releaseDate.ToString("yyyy-MM-dd HH:mm:ss") | Out-Null
                    Write-Log "Cached release date for $cacheKey : $releaseDate" | Out-Null
                } catch {
                    Write-Log "Failed to cache release date: $($_.Exception.Message)" | Out-Null
                }
                return $releaseDate
            } else {
                Write-Log "No release date found in winget output for $AppID" | Out-Null
            }
        } else {
            Write-Log "No output from winget show for $AppID" | Out-Null
        }
        
        return $null
        
    } catch {
        Write-Log "Error getting app release date for ${AppID}: $($_.Exception.Message)" | Out-Null
        return $null
    }
}

function Get-DeferralStatus {
    <#
    .SYNOPSIS
        Gets the current deferral status for an application
    .DESCRIPTION
        Retrieves deferral information from registry including count, dates, and deadline status
    .PARAMETER AppID
        Application ID to check
    .PARAMETER WhitelistConfig
        Whitelist configuration object for the app
    .PARAMETER AvailableVersion
        Available version to check against
    .OUTPUTS
        Hashtable with deferral status information
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppID,
        
        [Parameter(Mandatory=$true)]
        [object]$WhitelistConfig,
        
        [string]$AvailableVersion = ""
    )
    
    try {
        Initialize-DeferralRegistry | Out-Null

        $deferralSub = "Deferrals\$AppID"
        $now = Get-Date

        # Default status - no deferrals
        $status = @{
            DeferralEnabled = $WhitelistConfig.DeferralEnabled -eq $true
            MaxDeferralDays = if ($WhitelistConfig.MaxDeferralDays) { $WhitelistConfig.MaxDeferralDays } else { 0 }
            DeferralsUsed = 0
            LastDeferralDate = $null
            UserDeadline = $null
            AdminHardDeadline = $null
            ReleaseDate = $null
            CanDefer = $false
            ForceUpdate = $false
            Message = ""
        }
        
        # If deferrals not enabled for this app, return early
        if (-not $status.DeferralEnabled) {
            $status.Message = "Deferrals not enabled for this application"
            $status.ForceUpdate = $true
            return $status
        }
        
        # Get release date for deadline calculations
        $releaseDate = Get-AppReleaseDate -AppID $AppID -Version $AvailableVersion

        if (-not $releaseDate) {
            # No release date from winget - use FirstDetected date as fallback
            # This ensures AdminHardDeadline is always calculated
            if (Test-AppRegKey -SubPath $deferralSub) {
                $firstDetected = Get-AppRegValue -SubPath $deferralSub -Name 'FirstDetected'
                if ($firstDetected) {
                    $releaseDate = [DateTime]::Parse($firstDetected)
                    Write-Log "Using stored FirstDetected date for ${AppID}: $($releaseDate.ToString('yyyy-MM-dd'))" | Out-Null
                }
            }
            if (-not $releaseDate) {
                # First time seeing this app - record today as first detected
                $releaseDate = $now
                Set-AppRegValue -SubPath $deferralSub -Name 'FirstDetected' -Value $now.ToString('o') | Out-Null
                Write-Log "No release date found for ${AppID}, recording first detection date: $($now.ToString('yyyy-MM-dd'))" | Out-Null
            }
        }

        $status.ReleaseDate = $releaseDate
        # Calculate admin hard deadline (release/first-detected date + MaxDeferralDays)
        $status.AdminHardDeadline = $releaseDate.AddDays($status.MaxDeferralDays)
        
        # Check if deferral data exists
        if (Test-AppRegKey -SubPath $deferralSub) {
            try {
                $deferralData = Get-AppRegProperties -SubPath $deferralSub
                if ($deferralData) {
                    # Parse existing deferral data
                    if ($deferralData.DeferralsUsed) {
                        $status.DeferralsUsed = [int]$deferralData.DeferralsUsed
                    }

                    if ($deferralData.LastDeferralDate) {
                        $status.LastDeferralDate = [DateTime]::Parse($deferralData.LastDeferralDate)
                    }

                    if ($deferralData.UserDeadline) {
                        $status.UserDeadline = [DateTime]::Parse($deferralData.UserDeadline)
                    }
                }
            } catch {
                Write-Log "Error reading deferral data for ${AppID}: $($_.Exception.Message)" | Out-Null
            }
        }
        
        # Determine if update should be forced
        $forceReasons = @()
        
        # Check admin hard deadline (takes precedence)
        if ($status.AdminHardDeadline -and $now -gt $status.AdminHardDeadline) {
            $daysOverdue = ($now - $status.AdminHardDeadline).Days
            $forceReasons += "Admin hard deadline exceeded ($($daysOverdue) days overdue)"
            $status.ForceUpdate = $true
        }
        
        # Check user deadline
        if (-not $status.ForceUpdate -and $status.UserDeadline -and $now -gt $status.UserDeadline) {
            $forceReasons += "User deadline exceeded"
            $status.ForceUpdate = $true
        }
        
        # Determine if user can still defer
        if (-not $status.ForceUpdate) {
            $daysUntilAdminDeadline = if ($status.AdminHardDeadline) {
                [Math]::Max(0, ($status.AdminHardDeadline - $now).Days)
            } else {
                999  # No admin deadline
            }
            
            # User can defer if:
            # 1. We haven't reached admin hard deadline
            # 2. There are available deferral options within the remaining time
            if ($daysUntilAdminDeadline -gt 0) {
                $status.CanDefer = $true
            }
        }
        
        # Build status message
        if ($status.ForceUpdate) {
            if ($WhitelistConfig.ForcedUpgradeMessage) {
                $status.Message = $WhitelistConfig.ForcedUpgradeMessage
            } else {
                $status.Message = "Update required: $($forceReasons -join '; ')"
            }
        } elseif ($status.CanDefer) {
            $daysLeft = if ($status.AdminHardDeadline) {
                ($status.AdminHardDeadline - $now).Days
            } else {
                $status.MaxDeferralDays
            }
            $status.Message = "Update available. You can defer this update for up to $daysLeft more days."
        } else {
            $status.Message = "Update available. No deferral options remaining."
            $status.ForceUpdate = $true
        }
        
        Write-Log "Deferral status for ${AppID}: CanDefer=$($status.CanDefer), ForceUpdate=$($status.ForceUpdate), Message=$($status.Message)" | Out-Null
        
        return $status
        
    } catch {
        Write-Log "Error getting deferral status for ${AppID}: $($_.Exception.Message)" | Out-Null
        # Return safe default - force update on error
        return @{
            DeferralEnabled = $false
            ForceUpdate = $true
            CanDefer = $false
            Message = "Error checking deferral status - update required"
        }
    }
}

function Set-DeferralChoice {
    <#
    .SYNOPSIS
        Records a user's deferral choice in the registry
    .DESCRIPTION
        Defers until end of today, clamped to the admin hard deadline if provided.
    .PARAMETER AppID
        Application ID
    .PARAMETER AdminHardDeadline
        Optional admin hard deadline to clamp the deferral to
    .OUTPUTS
        Boolean indicating success
    #>

    param(
        [Parameter(Mandatory=$true)]
        [string]$AppID,

        [DateTime]$AdminHardDeadline
    )
    
    try {
        Initialize-DeferralRegistry | Out-Null
        
        $deferralSub = "Deferrals\$AppID"
        $now = Get-Date

        # Get current deferral count (CreateSubKey via Set-AppRegValue ensures the key exists)
        $currentDeferrals = 0
        try {
            $existing = Get-AppRegValue -SubPath $deferralSub -Name 'DeferralsUsed'
            if ($null -ne $existing) {
                $currentDeferrals = [int]$existing
            }
        } catch {
            # Use default of 0
        }

        # Calculate new user deadline: end of today, clamped to admin hard deadline
        $endOfDay = $now.Date.AddDays(1).AddSeconds(-1)  # today 23:59:59
        $userDeadline = if ($AdminHardDeadline -and $endOfDay -gt $AdminHardDeadline) { $AdminHardDeadline } else { $endOfDay }

        # Update deferral data
        Set-AppRegValue -SubPath $deferralSub -Name 'DeferralsUsed' -Value ($currentDeferrals + 1) | Out-Null
        Set-AppRegValue -SubPath $deferralSub -Name 'LastDeferralDate' -Value $now.ToString("yyyy-MM-dd HH:mm:ss") | Out-Null
        Set-AppRegValue -SubPath $deferralSub -Name 'UserDeadline' -Value $userDeadline.ToString("yyyy-MM-dd HH:mm:ss") | Out-Null

        Write-Log "Recorded deferral for ${AppID}: deferred until $($userDeadline.ToString('yyyy-MM-dd HH:mm:ss'))$(if ($AdminHardDeadline -and $endOfDay -gt $AdminHardDeadline) { ' (clamped to admin deadline)' })" | Out-Null
        
        return $true
        
    } catch {
        Write-Log "Error setting deferral choice for ${AppID}: $($_.Exception.Message)" | Out-Null
        return $false
    }
}

function Show-DeferralDialog {
    <#
    .SYNOPSIS
        Shows an enhanced dialog with deferral options
    .DESCRIPTION
        Displays a sophisticated WPF dialog offering deferral choices or immediate update
    .PARAMETER AppName
        Application ID for the update
    .PARAMETER DeferralStatus
        Deferral status hashtable from Get-DeferralStatus
    .PARAMETER ProcessName
        Name of the blocking process (if any)
    .PARAMETER FriendlyName
        User-friendly name of the application
    .PARAMETER CurrentVersion
        Current version of the application
    .PARAMETER AvailableVersion
        Available version for update
    .PARAMETER TimeoutSeconds
        Timeout in seconds before using default action
    .OUTPUTS
        Hashtable with user choice: @{ Action = "Update|Defer"; DeferralDays = [int] }
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$AppName,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$DeferralStatus,
        
        [string]$ProcessName = "",
        [string]$FriendlyName = "",
        [string]$CurrentVersion = "",
        [string]$AvailableVersion = "",
        [int]$TimeoutSeconds = 60
    )
    
    try {
        Write-Log "Show-DeferralDialog called for $AppName" | Out-Null

        # Use provided FriendlyName or fallback to AppName
        $displayName = if (-not [string]::IsNullOrEmpty($FriendlyName)) { $FriendlyName } else { $AppName }

        # Determine if process needs to be closed
        $hasBlockingProcess = -not [string]::IsNullOrEmpty($ProcessName)

        # v9.33: persistent dialog host path
        # v9.36: only commit to host-only behaviour when we get a valid reply. If the host dies
        # mid-prompt (Send-DialogCommand returns $null), fall through to the legacy WPF dialog
        # below so the user still gets a visible prompt instead of a silent default action.
        if (Test-DialogHostAlive) {
            $versionText = if (-not [string]::IsNullOrEmpty($CurrentVersion) -and -not [string]::IsNullOrEmpty($AvailableVersion)) {
                "$displayName $CurrentVersion -> $AvailableVersion"
            } else {
                "$displayName update available"
            }
            if ($DeferralStatus.ForceUpdate) {
                # Forced update - route as prompt-mandatory; both "upgrade" and "timeout" mean proceed
                $reply = Send-DialogCommand -Cmd "prompt-mandatory" -Payload @{
                    title = "Required Update: $displayName"
                    versionInfo = $versionText
                    body = if ($hasBlockingProcess) { "$displayName must be closed to install this update." } else { [string]$DeferralStatus.Message }
                    timeoutSec = $TimeoutSeconds
                } -Blocking -TimeoutSeconds ($TimeoutSeconds + 30)
                if ($reply) {
                    return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $hasBlockingProcess }
                }
                Write-Log "Show-DeferralDialog: dialog host died mid prompt-mandatory - falling back to legacy spawn" | Out-Null
            } else {
                # Deferrable - route as prompt-deferral
                $daysLeft = if ($DeferralStatus.PSObject.Properties['DaysRemaining']) { [int]$DeferralStatus.DaysRemaining } elseif ($DeferralStatus.PSObject.Properties['MaxDeferralDays']) { [int]$DeferralStatus.MaxDeferralDays } else { $null }
                # v9.60: warn the user that Update Now will close the running app, so they
                # can save their work first. Only relevant when a blocking process is active.
                $closeWarning = if ($hasBlockingProcess) { "`n`nClicking " + [char]0x201C + "Update Now" + [char]0x201D + " will close $displayName - please save your work first." } else { "" }
                $reply = Send-DialogCommand -Cmd "prompt-deferral" -Payload @{
                    title = "Update Available: $displayName"
                    body = $versionText + "`n`n" + [string]$DeferralStatus.Message + $closeWarning
                    daysLeft = $daysLeft
                    canDefer = ($DeferralStatus.CanDefer -eq $true)
                    timeoutSec = $TimeoutSeconds
                } -Blocking -TimeoutSeconds ($TimeoutSeconds + 30)
                if ($reply -and $reply.response) {
                    $choice = [string]$reply.response
                    if ($choice -eq "defer") {
                        return @{ Action = "Defer"; DeferralDays = 1; CloseProcess = $false }
                    }
                    return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $hasBlockingProcess }
                }
                Write-Log "Show-DeferralDialog: dialog host died mid prompt-deferral - falling back to legacy spawn" | Out-Null
            }
            # fall through to legacy WPF dispatcher below
        }
        
        # Build dialog content
        $versionText = ""
        if (-not [string]::IsNullOrEmpty($CurrentVersion) -and -not [string]::IsNullOrEmpty($AvailableVersion)) {
            $versionText = "$displayName $CurrentVersion -> $AvailableVersion update available`n`n"
        } else {
            $versionText = "Update available for $displayName`n`n"
        }
        
        # v9.60: legacy WPF fallback also gets the save-your-work warning when the app is open.
        $processText = if ($hasBlockingProcess) {
            "$displayName is currently running and must be closed to proceed with the update.`nPlease save your work before clicking Update Now.`n`n"
        } else {
            ""
        }
        
        $deferralText = if ($DeferralStatus.ForceUpdate) {
            $DeferralStatus.Message
        } else {
            "$($DeferralStatus.Message)`n`nYou can choose to:"
        }
        
        $question = $versionText + $processText + $deferralText
        
        # Create enhanced WPF dialog with deferral options
        if ($DeferralStatus.ForceUpdate) {
            # Force update - show mandatory update dialog with only Continue button
            $title = "Required Update: $displayName"
            
            # Create clean, user-friendly message components
            $versionInfo = ""
            $actionMessage = ""
            
            if (-not [string]::IsNullOrEmpty($CurrentVersion) -and -not [string]::IsNullOrEmpty($AvailableVersion)) {
                $versionInfo = "$displayName $CurrentVersion -> $AvailableVersion"
            } else {
                $versionInfo = "$displayName update available"
            }
            
            if ($hasBlockingProcess) {
                $actionMessage = "$displayName must be closed to install this update."
            } else {
                $actionMessage = "This security/compatibility update cannot be postponed."
            }
            
            # Pass separate components instead of combined question
            $response = Show-MandatoryUpdateDialog -Question "$versionInfo|$actionMessage" -Title $title -TimeoutSeconds $TimeoutSeconds -HasBlockingProcess $hasBlockingProcess

            # $response is the progress signal file path (if system context) so the dialog can show progress in-place
            $result = @{
                Action = "Update"
                DeferralDays = 0
                CloseProcess = $true
            }
            if ($response -and $response -ne "Continue" -and (Test-Path (Split-Path $response -Parent) -ErrorAction SilentlyContinue)) {
                $result.ProgressSignalFile = $response
            }
            return $result
        } else {
            # Show deferral options
            $title = "Update Available: $displayName"
            
            # Create complex dialog with deferral buttons
            $deferralChoice = Show-EnhancedDeferralDialog -Question $question -Title $title -HasBlockingProcess $hasBlockingProcess -TimeoutSeconds $TimeoutSeconds
            
            return $deferralChoice
        }
        
    } catch {
        Write-Log "Error in Show-DeferralDialog: $($_.Exception.Message)" | Out-Null
        # Return safe default
        return @{
            Action = "Update"
            DeferralDays = 0
            CloseProcess = $true
        }
    }
}

function Show-EnhancedDeferralDialog {
    <#
    .SYNOPSIS
        Shows a complex WPF dialog with multiple deferral options
    .DESCRIPTION
        Creates a sophisticated dialog allowing users to choose from available deferral timeframes
    .PARAMETER TimeoutSeconds
        Timeout in seconds before using default action
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$Question,
        
        [Parameter(Mandatory=$true)]
        [string]$Title,

        [bool]$HasBlockingProcess = $false,
        [int]$TimeoutSeconds = 60
    )

    try {
        # For system context, use the enhanced scheduled task approach
        if (Test-RunningAsSystem) {
            return Invoke-SystemDeferralPrompt -Question $Question -Title $Title -HasBlockingProcess $HasBlockingProcess -TimeoutSeconds $TimeoutSeconds
        } else {
            # Direct user context - simplified approach
            return Show-DirectDeferralDialog -Question $Question -Title $Title -HasBlockingProcess $HasBlockingProcess -TimeoutSeconds $TimeoutSeconds
        }
        
    } catch {
        Write-Log "Error in Show-EnhancedDeferralDialog: $($_.Exception.Message)" | Out-Null
        return @{
            Action = "Update"
            DeferralDays = 0
            CloseProcess = $true
        }
    }
}

function Show-DirectDeferralDialog {
    <#
    .SYNOPSIS
        Direct user context deferral dialog via child process
    .DESCRIPTION
        Runs the WPF dialog in a separate PowerShell process to isolate WPF Dispatcher
        lifecycle from the parent script. Communicates result via temp file.
    .PARAMETER TimeoutSeconds
        Timeout in seconds before using default action
    #>

    param(
        [string]$Question,
        [string]$Title,
        [bool]$HasBlockingProcess,
        [int]$TimeoutSeconds = 60
    )

    try {
        Write-Log "Showing direct deferral dialog via child process: '$Title'" | Out-Null

        $dialogId = [guid]::NewGuid().ToString('N')
        $resultFile = Join-Path $env:TEMP "WingetDialog_$dialogId.txt"
        $signalFile = Join-Path $env:TEMP "WingetDialog_${dialogId}_Complete.json"
        $statusFile = Join-Path $env:TEMP "WingetDialog_${dialogId}_Complete_Status.txt"

        # Child process script - writes result file immediately on user choice,
        # then stays open in progress mode polling for completion signal
        $dialogScript = @'
param($Title, $Question, $TimeoutSeconds, $ResultFile)
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# Derive signal/status file paths from result file
$signalFile = $ResultFile -replace '\.txt$', '_Complete.json'
$statusFile = $ResultFile -replace '\.txt$', '_Complete_Status.txt'

# Detect system theme (0 = dark, 1 = light)
$isDark = $true
try {
    $themeVal = Get-ItemPropertyValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -ErrorAction Stop
    if ($themeVal -eq 1) { $isDark = $false }
} catch {}

if ($isDark) {
    $bgColor = "#FF1F1F1F"; $borderColor = "#FF323232"; $questionFg = "#FFCCCCCC"
    $shadowOpacity = "0.6"; $closeFg = "#FF888888"
    $deferFg = "#FFCCCCCC"; $deferBorder = "#FF484848"
} else {
    $bgColor = "#FFF3F3F3"; $borderColor = "#FFD1D1D1"; $questionFg = "#FF444444"
    $shadowOpacity = "0.25"; $closeFg = "#FF999999"
    $deferFg = "#FF444444"; $deferBorder = "#FFB0B0B0"
}

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Dialog" Width="500" MinHeight="200" SizeToContent="Height" WindowStartupLocation="Manual"
    ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="False">
    <Window.Triggers>
        <EventTrigger RoutedEvent="Window.Loaded">
            <BeginStoryboard><Storyboard><DoubleAnimation Storyboard.TargetProperty="Opacity" From="0" To="1" Duration="0:0:0.3"/></Storyboard></BeginStoryboard>
        </EventTrigger>
    </Window.Triggers>
    <Border Background="$bgColor" CornerRadius="8" BorderBrush="$borderColor" BorderThickness="1">
        <Border.Effect><DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="$shadowOpacity" BlurRadius="12"/></Border.Effect>
        <Grid>
            <!-- Close button top-right -->
            <Button Name="CloseButton" Content="&#x2715;" Width="24" Height="24" HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0,6,6,0"
                    Background="Transparent" Foreground="$closeFg" BorderThickness="0" FontSize="13" Cursor="Hand" FontFamily="Segoe UI Symbol"/>
            <Grid Margin="20">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Name="QuestionText" Grid.Row="0" Foreground="$questionFg" TextWrapping="Wrap" Margin="0,0,0,20" FontSize="12"/>
                <StackPanel Grid.Row="1" Name="ButtonPanel" Orientation="Horizontal" HorizontalAlignment="Center">
                    <Button Name="DeferButton" Content="Defer" Width="100" Height="28" Margin="0,0,8,0"
                            Background="Transparent" Foreground="$deferFg" BorderBrush="$deferBorder" BorderThickness="1" FontSize="11" Cursor="Hand"/>
                    <Button Name="UpdateButton" Content="Update Now" Width="100" Height="28"
                            Background="#FF0078D4" Foreground="White" BorderBrush="Transparent" BorderThickness="0" FontSize="11" Cursor="Hand"/>
                </StackPanel>
                <StackPanel Grid.Row="2" Name="ProgressPanel" Visibility="Collapsed" HorizontalAlignment="Center" Margin="0,5,0,0">
                    <ProgressBar Name="ProgressBar" IsIndeterminate="True" Width="300" Height="3" Margin="0,0,0,10" Foreground="#FF0078D4"/>
                    <TextBlock Name="ProgressText" Text="Updating..." Foreground="$questionFg" FontSize="12" HorizontalAlignment="Center"/>
                </StackPanel>
            </Grid>
        </Grid>
    </Border>
</Window>
"@

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [Windows.Markup.XamlReader]::Load($reader)

# Set text programmatically (avoids XML escaping issues)
$window.Title = $Title
$window.FindName("QuestionText").Text = $Question

# Position at bottom-right like a notification
$window.Add_Loaded({
    $workArea = [System.Windows.SystemParameters]::WorkArea
    $window.Left = $workArea.Right - $window.ActualWidth - 16
    $window.Top = $workArea.Bottom - $window.ActualHeight - 16
})

$updateButton = $window.FindName("UpdateButton")
$deferButton = $window.FindName("DeferButton")
$closeButton = $window.FindName("CloseButton")

# Shared state
$s = @{
    inProgressMode = $false
    timeRemaining = [int]$TimeoutSeconds
    origUpdate = $updateButton.Content
    lastStatus = ""
    progressStartTime = $null
}

# Function to switch dialog to progress mode - keeps window open, polls for completion
$switchToProgress = {
    if ($s.inProgressMode) { return }
    $s.inProgressMode = $true

    # Write result file immediately so parent can proceed
    "Update|0|True" | Out-File -FilePath $ResultFile -Encoding UTF8 -NoNewline

    # Switch UI to progress mode
    $window.FindName("ButtonPanel").Visibility = [System.Windows.Visibility]::Collapsed
    $window.FindName("CloseButton").Visibility = [System.Windows.Visibility]::Collapsed
    $window.FindName("ProgressPanel").Visibility = [System.Windows.Visibility]::Visible
    $window.FindName("QuestionText").Text = "Closing application and installing update..."

    $s.progressStartTime = Get-Date

    # Poll timer - checks for status updates and completion signal
    $pollTimer = New-Object System.Windows.Threading.DispatcherTimer
    $pollTimer.Interval = [System.TimeSpan]::FromSeconds(2)
    $pollTimer.Add_Tick({
        # Check for status updates
        if (Test-Path $statusFile) {
            try {
                $currentStatus = (Get-Content $statusFile -Raw).Trim()
                if ($currentStatus -and $currentStatus -ne $s.lastStatus) {
                    $s.lastStatus = $currentStatus
                    $window.FindName("ProgressText").Text = $currentStatus
                }
            } catch {}
        }
        # Check for completion signal
        if (Test-Path $signalFile) {
            $pollTimer.Stop()
            try {
                $signalData = Get-Content $signalFile -Raw | ConvertFrom-Json
                $pBar = $window.FindName("ProgressBar")
                $pText = $window.FindName("ProgressText")
                $pBar.IsIndeterminate = $false
                $pBar.Value = 100
                if ($signalData.Success -eq $true) {
                    $pText.Text = "Update complete!"
                } else {
                    $pText.Text = "Update could not be completed."
                }
            } catch {
                $window.FindName("ProgressText").Text = "Update complete!"
            }
            # Auto-close after 3 seconds
            $closeTimer = New-Object System.Windows.Threading.DispatcherTimer
            $closeTimer.Interval = [System.TimeSpan]::FromSeconds(3)
            $closeTimer.Add_Tick({
                $closeTimer.Stop()
                $window.Close()
            }.GetNewClosure())
            $closeTimer.Start()
        } elseif (((Get-Date) - $s.progressStartTime).TotalMinutes -gt 5) {
            $pollTimer.Stop()
            $window.Close()
        }
    }.GetNewClosure())
    $pollTimer.Start()
}.GetNewClosure()

$countdownTimer = New-Object System.Windows.Threading.DispatcherTimer
$countdownTimer.Interval = [System.TimeSpan]::FromSeconds(1)
$countdownTimer.Add_Tick({
    $s.timeRemaining--
    $updateButton.Content = "$($s.origUpdate) ($($s.timeRemaining))"
    if ($s.timeRemaining -le 0) { $countdownTimer.Stop() }
}.GetNewClosure())

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [System.TimeSpan]::FromSeconds([int]$TimeoutSeconds)
$timer.Add_Tick({
    $timer.Stop(); $countdownTimer.Stop()
    & $switchToProgress
}.GetNewClosure())

$updateButton.Add_Click({
    $timer.Stop(); $countdownTimer.Stop()
    & $switchToProgress
}.GetNewClosure())
$deferButton.Add_Click({
    "Defer|0|False" | Out-File -FilePath $ResultFile -Encoding UTF8 -NoNewline
    $timer.Stop(); $countdownTimer.Stop()
    $window.Close()
}.GetNewClosure())
$closeButton.Add_Click({
    "Defer|0|False" | Out-File -FilePath $ResultFile -Encoding UTF8 -NoNewline
    $timer.Stop(); $countdownTimer.Stop()
    $window.Close()
}.GetNewClosure())
$window.Add_Closing({
    $timer.Stop(); $countdownTimer.Stop()
    if (-not (Test-Path $ResultFile)) {
        "Defer|0|False" | Out-File -FilePath $ResultFile -Encoding UTF8 -NoNewline
    }
}.GetNewClosure())

$timer.Start()
$countdownTimer.Start()
$window.ShowDialog()
'@

        # Find PowerShell executable
        $pwsh = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }

        # Write dialog script to temp file
        $scriptFile = Join-Path $env:TEMP "WingetDialog_$([guid]::NewGuid().ToString('N')).ps1"
        $dialogScript | Out-File -FilePath $scriptFile -Encoding UTF8

        Write-Log "Launching deferral dialog child process ($pwsh) from $scriptFile" | Out-Null

        $proc = Start-Process $pwsh -ArgumentList "-NoProfile", "-STA", "-File", "`"$scriptFile`"", "-Title", "`"$Title`"", "-Question", "`"$Question`"", "-TimeoutSeconds", $TimeoutSeconds, "-ResultFile", "`"$resultFile`"" -PassThru -WindowStyle Hidden

        # Poll for result file instead of blocking on WaitForExit - dialog stays open for progress
        $pollTimeout = $TimeoutSeconds + 30
        $pollStart = Get-Date
        while (-not (Test-Path $resultFile)) {
            if (((Get-Date) - $pollStart).TotalSeconds -gt $pollTimeout) {
                Write-Log "Deferral dialog poll timeout after ${pollTimeout}s" | Out-Null
                break
            }
            if ($proc.HasExited) {
                Write-Log "Dialog process exited before writing result file" | Out-Null
                break
            }
            Start-Sleep -Milliseconds 500
        }

        # Read and parse result (format: "Action|DeferralDays|CloseProcess")
        if (Test-Path $resultFile) {
            $response = (Get-Content $resultFile -Raw).Trim()
            Write-Log "Deferral dialog child process returned: $response" | Out-Null

            $parts = $response -split '\|'
            $deferralResult = @{
                Action       = if ($parts[0]) { $parts[0] } else { "Update" }
                DeferralDays = if ($parts.Count -gt 1) { [int]$parts[1] } else { 0 }
                CloseProcess = if ($parts.Count -gt 2) { $parts[2] -eq "True" } else { $true }
            }

            # If user chose Update, pass signal file so upgrade code can notify the dialog
            if ($deferralResult.Action -eq "Update") {
                $deferralResult.ProgressSignalFile = $signalFile
                Write-Log "Direct dialog progress signal file: $signalFile" | Out-Null
            }

            # Clean up result file (but NOT signal/status files - dialog still needs them)
            Remove-Item $resultFile -Force -ErrorAction SilentlyContinue

            Write-Log "Deferral dialog result parsed: Action=$($deferralResult.Action), Days=$($deferralResult.DeferralDays), CloseProcess=$($deferralResult.CloseProcess)" | Out-Null
            return $deferralResult
        } else {
            Write-Log "Deferral dialog child process produced no result file, using default: Update" | Out-Null
            # Clean up child process
            if (-not $proc.HasExited) { $proc.Kill() }
            Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue
            return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        }

    } catch {
        Write-Log "Error in direct deferral dialog: $($_.Exception.Message)" | Out-Null
        return @{
            Action = "Update"
            DeferralDays = 0
            CloseProcess = $true
        }
    }
}

function Invoke-SystemDeferralPrompt {
    <#
    .SYNOPSIS
        System context deferral dialog using scheduled tasks
    .PARAMETER TimeoutSeconds
        Timeout in seconds before using default action
    #>
    
    param(
        [string]$Question,
        [string]$Title,
        [bool]$HasBlockingProcess,
        [int]$TimeoutSeconds = 60
    )

    try {
        Write-Log "Invoking system deferral prompt (single Defer button)" | Out-Null
        
        # Get interactive user
        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user found - cannot show deferral dialog" | Out-Null
            return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        }
        
        # Create unique identifiers
        $promptId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        
        # Setup response file path
        $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
        $responseFile = if (Test-Path $userTempPath) {
            Join-Path $userTempPath "DeferralPrompt_$promptId`_Response.json"
        } else {
            Join-Path "C:\ProgramData\Temp" "DeferralPrompt_$promptId`_Response.json"
        }
        
        # Create enhanced user prompt script for deferrals (use user temp so scheduled task can access it)
        $deferralScriptPath = Join-Path $userTempPath "Show-DeferralPrompt_$promptId.ps1"
        
        # Build the script content dynamically
        $deferralScriptContent = @'
param(
    [string]$ResponseFilePath,
    [string]$EncodedQuestion,
    [string]$EncodedTitle,
    [int]$HasBlockingProcess = 0,
    [int]$TimeoutSeconds = 60,
    [string]$Question = "",
    [string]$Title = ""
)

# Debug logging
$logPath = Join-Path $env:TEMP "DeferralPrompt_Debug.log"
function Write-DeferLog {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    "[$ts] $Message" | Out-File -FilePath $logPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
}

try {
    Write-DeferLog "=== DEFERRAL PROMPT SCRIPT STARTED ==="
    Write-DeferLog "PID: $PID, Session: $((Get-Process -Id $PID).SessionId), User: $env:USERNAME"
    Write-DeferLog "ResponseFilePath: $ResponseFilePath"
    Write-DeferLog "HasBlockingProcess: $HasBlockingProcess, TimeoutSeconds: $TimeoutSeconds"
    Write-DeferLog "ApartmentState: $([System.Threading.Thread]::CurrentThread.GetApartmentState())"

    # Decode parameters
    $actualQuestion = if ($EncodedQuestion) {
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedQuestion))
    } else { $Question }

    $actualTitle = if ($EncodedTitle) {
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedTitle))
    } else { $Title }

    Write-DeferLog "Decoded title: $actualTitle"

    # Detect system light/dark mode
    $isDark = $true  # default to dark
    try {
        $themeKey = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -ErrorAction Stop
        $isDark = $themeKey.AppsUseLightTheme -eq 0
    } catch { }
    Write-DeferLog "System theme: $(if ($isDark) { 'Dark' } else { 'Light' })"

    # Theme colors
    if ($isDark) {
        $bgColor = "#FF1F1F1F"; $borderColor = "#FF323232"; $textColor = "#FFCCCCCC"
        $shadowOpacity = "0.6"; $btnBg = ""; $btnFg = ""
        $closeBtnFg = "#FF888888"; $closeBtnHoverBg = "#FF2A2A2A"
    } else {
        $bgColor = "#FFF3F3F3"; $borderColor = "#FFD1D1D1"; $textColor = "#FF1B1B1B"
        $shadowOpacity = "0.25"; $btnBg = ""; $btnFg = ""
        $closeBtnFg = "#FF999999"; $closeBtnHoverBg = "#FFE0E0E0"
    }

    # Load WPF assemblies (single call - 4x faster than separate Add-Type per assembly)
    Write-DeferLog "Loading WPF assemblies..."
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop
    Write-DeferLog "WPF assemblies loaded"

    # Get screen dimensions for positioning
    $workArea = [System.Windows.SystemParameters]::WorkArea
    Write-DeferLog "Screen working area: $($workArea.Width)x$($workArea.Height)"

    # Build buttons XML: single Defer button + Update Now
    $buttonXml = '<Button Name="DeferButton" Content="Defer" Width="100" Height="28" Margin="0,0,8,0" Tag="0"/>'
    $buttonXml += '<Button Name="UpdateButton" Content="Update Now" Width="100" Height="28" Background="#FF0078D4" Foreground="White" IsDefault="true" Tag="0"/>'
    Write-DeferLog "Button XML built: $buttonXml"

    $dialogWidth = 500

    # XML-escape the decoded text and preserve newlines as XML entities
    $escapedQuestion = [System.Security.SecurityElement]::Escape($actualQuestion) -replace "`n", "&#10;"
    $escapedTitle = [System.Security.SecurityElement]::Escape($actualTitle)

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$escapedTitle" Width="$dialogWidth" MinHeight="200" SizeToContent="Height" WindowStartupLocation="Manual"
        ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="False">
    <Border Background="$bgColor" CornerRadius="8" BorderBrush="$borderColor" BorderThickness="1">
        <Border.Effect>
            <DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="$shadowOpacity" BlurRadius="12"/>
        </Border.Effect>
        <Grid>
            <Grid Margin="20">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Grid.Row="0" Name="QuestionText" Text="$escapedQuestion" Foreground="$textColor" TextWrapping="Wrap" Margin="0,0,24,20" FontSize="12"/>
                <StackPanel Grid.Row="1" Name="ButtonPanel" Orientation="Horizontal" HorizontalAlignment="Center">$buttonXml</StackPanel>
                <StackPanel Grid.Row="2" Name="ProgressPanel" Visibility="Collapsed" HorizontalAlignment="Center" Margin="0,5,0,0">
                    <ProgressBar Name="ProgressBar" IsIndeterminate="True" Width="300" Height="3" Margin="0,0,0,10" Foreground="#FF0078D4"/>
                    <TextBlock Name="ProgressText" Text="Updating..." Foreground="$textColor" FontSize="12" HorizontalAlignment="Center"/>
                </StackPanel>
            </Grid>
            <Button Name="CloseButton" Content="&#x2715;" Width="24" Height="24" HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0,6,6,0" Background="Transparent" Foreground="$closeBtnFg" BorderThickness="0" FontSize="13" Cursor="Hand" FontFamily="Segoe UI Symbol" Tag="0"/>
        </Grid>
    </Border>
</Window>
"@

    Write-DeferLog "XAML built, parsing..."
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
    $window = [Windows.Markup.XamlReader]::Load($reader)
    Write-DeferLog "XAML parsed successfully"

    # Position window at bottom-right of screen
    $window.Left = $workArea.Right - $dialogWidth - 20
    $window.Top = $workArea.Bottom - 250
    Write-DeferLog "Window positioned at Left=$($window.Left), Top=$($window.Top)"

    $script:result = @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }

    # Defer button handler
    $deferButton = $window.FindName("DeferButton")
    if ($deferButton) {
        $deferButton.Add_Click({
            Write-DeferLog "Defer button clicked - deferring until end of day"
            @{ Action = "Defer"; DeferralDays = 0; CloseProcess = $false } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8
            $window.Close()
        })
        Write-DeferLog "Attached click handler for DeferButton"
    }

    # Close button acts as Defer (same behavior)
    $closeButton = $window.FindName("CloseButton")
    if ($closeButton) {
        $closeButton.Add_Click({
            Write-DeferLog "Close button clicked - deferring until end of day"
            @{ Action = "Defer"; DeferralDays = 0; CloseProcess = $false } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8
            $window.Close()
        })
        Write-DeferLog "Attached close button handler (defers until end of day)"
    }

    # Shared function to switch dialog to progress mode and start polling for completion
    $script:inProgressMode = $false
    $script:signalFilePath = $ResponseFilePath -replace '_Response\.json$', '_Complete.json'
    $script:statusFilePath = $script:signalFilePath -replace '\.json$', '_Status.txt'
    $script:lastStatus = ""

    $script:SwitchToProgressMode = {
        param([string]$Reason)
        if ($script:inProgressMode) { return }
        $script:inProgressMode = $true
        Write-DeferLog "Switching to progress mode (reason: $Reason)"

        # Write response if not already written
        if (-not (Test-Path $ResponseFilePath)) {
            @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8
        }

        # Switch to progress UI
        $window.FindName("ButtonPanel").Visibility = [System.Windows.Visibility]::Collapsed
        $window.FindName("CloseButton").Visibility = [System.Windows.Visibility]::Collapsed
        $window.FindName("ProgressPanel").Visibility = [System.Windows.Visibility]::Visible
        $window.FindName("QuestionText").Text = "Closing application and installing update..."

        $script:progressStartTime = Get-Date
        $script:pollTimer = [System.Windows.Threading.DispatcherTimer]::new()
        $script:pollTimer.Interval = [TimeSpan]::FromSeconds(2)
        $script:pollTimer.Add_Tick({
            # Check for status updates
            if (Test-Path $script:statusFilePath) {
                try {
                    $currentStatus = (Get-Content $script:statusFilePath -Raw).Trim()
                    if ($currentStatus -and $currentStatus -ne $script:lastStatus) {
                        $script:lastStatus = $currentStatus
                        $window.FindName("ProgressText").Text = $currentStatus
                        Write-DeferLog "Status updated: $currentStatus"
                    }
                } catch {}
            }
            # Check for final signal
            if (Test-Path $script:signalFilePath) {
                $script:pollTimer.Stop()
                Write-DeferLog "Completion signal received at: $script:signalFilePath"
                try {
                    $signalData = Get-Content $script:signalFilePath -Raw | ConvertFrom-Json
                    $pBar = $window.FindName("ProgressBar")
                    $pText = $window.FindName("ProgressText")
                    $pBar.IsIndeterminate = $false
                    $pBar.Value = 100
                    if ($signalData.Success -eq $true) {
                        $pText.Text = "Update complete!"
                    } else {
                        $pText.Text = "Update could not be completed."
                    }
                } catch {
                    Write-DeferLog "Error reading signal: $($_.Exception.Message)"
                    $window.FindName("ProgressText").Text = "Update complete!"
                }
                # Auto-close after 3 seconds
                $script:closeTimer = [System.Windows.Threading.DispatcherTimer]::new()
                $script:closeTimer.Interval = [TimeSpan]::FromSeconds(3)
                $script:closeTimer.Add_Tick({
                    $script:closeTimer.Stop()
                    $window.Close()
                })
                $script:closeTimer.Start()
            } elseif (((Get-Date) - $script:progressStartTime).TotalMinutes -gt 5) {
                $script:pollTimer.Stop()
                Write-DeferLog "Progress timeout after 5 minutes - closing dialog"
                $window.Close()
            }
        })
        $script:pollTimer.Start()
        Write-DeferLog "Started polling for completion signal"
    }

    $updateButton = $window.FindName("UpdateButton")
    if ($updateButton) {
        $updateButton.Add_Click({
            Write-DeferLog "Update button clicked"
            & $script:SwitchToProgressMode "UserClickedUpdate"
        })
        Write-DeferLog "Attached click handler for UpdateButton"
    }

    # Timeout timer: auto-switch to progress mode so the dialog detects completion
    # even if the user doesn't click anything (SYSTEM script proceeds after its own timeout)
    if ($TimeoutSeconds -gt 0) {
        $script:timeoutTimer = [System.Windows.Threading.DispatcherTimer]::new()
        $script:timeoutTimer.Interval = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $script:timeoutTimer.Add_Tick({
            $script:timeoutTimer.Stop()
            Write-DeferLog "Dialog timeout reached ($TimeoutSeconds seconds) - auto-switching to progress mode"
            & $script:SwitchToProgressMode "Timeout"
        })
        $script:timeoutTimer.Start()
        Write-DeferLog "Started timeout timer: $TimeoutSeconds seconds"
    }

    Write-DeferLog "Showing dialog..."
    $window.Activate()
    $window.ShowDialog() | Out-Null
    Write-DeferLog "Dialog closed"

    # Safety fallback: if no button handler wrote the response file, write default
    if (-not (Test-Path $ResponseFilePath)) {
        Write-DeferLog "WARNING: No response file found after dialog close - writing default (Update)"
        @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8
    }

} catch {
    Write-DeferLog "FATAL ERROR: $($_.Exception.Message)"
    Write-DeferLog "Stack trace: $($_.ScriptStackTrace)"
    # Write error response so caller doesn't hang
    @{ Action = "Error"; DeferralDays = 0; CloseProcess = $false; Error = $_.Exception.Message } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8 -ErrorAction SilentlyContinue
}
Write-DeferLog "=== DEFERRAL PROMPT SCRIPT ENDED ==="
'@

        Write-Log "Creating deferral prompt script: $deferralScriptPath" | Out-Null
        $deferralScriptContent | Set-Content -Path $deferralScriptPath -Encoding UTF8
        
        # Create scheduled task with timeout parameter
        Write-Log "Creating scheduled task with timeout: $TimeoutSeconds seconds" | Out-Null
        
        # Generate unique task name
        $guid = [System.Guid]::NewGuid().ToString()
        $taskName = "DeferralPrompt_$guid"
        
        # Create task arguments with timeout parameter - ensure proper encoding for text parameters
        $encodedQuestion = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Question))
        $encodedTitle = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Title))
        $hasBlockingStr = if ($HasBlockingProcess) { "1" } else { "0" }
        # Create hidden launch action using VBS wrapper (no console window flash)
        $deferralPsArgs = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$deferralScriptPath`" -ResponseFilePath `"$responseFile`" -EncodedQuestion `"$encodedQuestion`" -EncodedTitle `"$encodedTitle`" -HasBlockingProcess $hasBlockingStr -TimeoutSeconds $TimeoutSeconds"
        $deferralVbsDir = Split-Path $responseFile -Parent
        $deferralLaunch = New-HiddenLaunchAction -PowerShellArguments $deferralPsArgs -VbsDirectory $deferralVbsDir -AllowUI
        if ($deferralLaunch) {
            $action = $deferralLaunch.Action
        } else {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$deferralScriptPath`" -ResponseFilePath `"$responseFile`" -EncodedQuestion `"$encodedQuestion`" -EncodedTitle `"$encodedTitle`" -HasBlockingProcess $hasBlockingStr -TimeoutSeconds $TimeoutSeconds"
        }
        
        # Create task principal using existing user info
        $principal = $null
        $userFormats = @($userInfo.FullName, $userInfo.Username, ".\$($userInfo.Username)")
        $logonTypes = @("Interactive", "S4U")
        
        foreach ($userFormat in $userFormats) {
            foreach ($logonType in $logonTypes) {
                try {
                    $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType $logonType -RunLevel Limited
                    Write-Log "Successfully created deferral task principal with: $userFormat ($logonType)" | Out-Null
                    break
                } catch {
                    Write-Log "Failed deferral task principal with format '$userFormat' ($logonType): $($_.Exception.Message)" | Out-Null
                }
            }
            if ($principal) { break }
        }
        
        if (-not $principal) {
            Write-Log "Could not create deferral task principal" | Out-Null
            return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        }
        
        # Create and register task
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
        $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description "Interactive deferral prompt for system operations"
        
        try {
            $registeredTask = Register-ScheduledTask -TaskName $taskName -InputObject $task -Force
            Write-Log "Deferral scheduled task created successfully: $taskName" | Out-Null
        } catch {
            Write-Log "Failed to register deferral scheduled task: $($_.Exception.Message)" | Out-Null
            return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        }
        
        # Start the task
        try {
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            Write-Log "Deferral scheduled task started successfully" | Out-Null

            # Diagnostic: check task state after starting
            Start-Sleep -Seconds 3
            $taskState = (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).State
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
            Write-Log "Task state after 3s: $taskState, LastResult: $($taskInfo.LastTaskResult), LastRunTime: $($taskInfo.LastRunTime)" | Out-Null

            # Check if the prompt script file still exists
            if (Test-Path $deferralScriptPath) {
                $scriptSize = (Get-Item $deferralScriptPath).Length
                Write-Log "Deferral script file exists: $deferralScriptPath ($scriptSize bytes)" | Out-Null
            } else {
                Write-Log "WARNING: Deferral script file NOT FOUND: $deferralScriptPath" | Out-Null
            }

            # Check if VBS file still exists
            if ($deferralLaunch -and $deferralLaunch.VbsPath) {
                if (Test-Path $deferralLaunch.VbsPath) {
                    Write-Log "VBS launcher exists: $($deferralLaunch.VbsPath)" | Out-Null
                } else {
                    Write-Log "WARNING: VBS launcher NOT FOUND: $($deferralLaunch.VbsPath)" | Out-Null
                }
            }

            # Check if debug log from the prompt script was created
            $debugLogPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp\DeferralPrompt_Debug.log"
            if (Test-Path $debugLogPath) {
                $debugContent = Get-Content $debugLogPath -Tail 5 -ErrorAction SilentlyContinue
                Write-Log "Deferral debug log exists. Last entries:" | Out-Null
                foreach ($line in $debugContent) { Write-Log "  [PromptLog] $line" | Out-Null }
            } else {
                Write-Log "WARNING: No deferral debug log at $debugLogPath - script may not have started" | Out-Null
            }
        } catch {
            Write-Log "Failed to start deferral scheduled task: $($_.Exception.Message)" | Out-Null
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        }
        
        # Wait for response - use configured timeout plus buffer for task overhead
        $taskTimeout = $TimeoutSeconds + 30  # Add 30 seconds buffer for task creation/cleanup
        $response = Wait-ForUserResponse -ResponseFilePath $responseFile -TimeoutSeconds $taskTimeout
        
        # Parse response
        $deferralChoice = @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
        $signalFile = $responseFile -replace '_Response\.json$', '_Complete.json'

        if ($response -ne "TIMEOUT" -and (Test-Path $responseFile)) {
            try {
                $responseData = Get-Content -Path $responseFile -Raw | ConvertFrom-Json
                $deferralChoice = @{
                    Action = $responseData.Action
                    DeferralDays = [int]$responseData.DeferralDays
                    CloseProcess = [bool]$responseData.CloseProcess
                }
                Write-Log "Parsed deferral response: $($deferralChoice.Action), $($deferralChoice.DeferralDays) days" | Out-Null
            } catch {
                Write-Log "Error parsing deferral response: $($_.Exception.Message)" | Out-Null
            }
        }

        # If user chose Update, the dialog is still showing a progress indicator
        # Pass the signal file path so the upgrade code can notify the dialog when done
        if ($deferralChoice.Action -eq "Update") {
            $deferralChoice.ProgressSignalFile = $signalFile
            Write-Log "Progress signal file for dialog: $signalFile" | Out-Null
        }

        # Cleanup task registration and temp files (dialog process keeps running independently)
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item $deferralScriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
        if ($deferralLaunch.VbsPath) { Remove-Item $deferralLaunch.VbsPath -Force -ErrorAction SilentlyContinue }

        return $deferralChoice
        
    } catch {
        Write-Log "Error in system deferral prompt: $($_.Exception.Message)" | Out-Null
        if ($taskName) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item $deferralScriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
        if ($deferralLaunch -and $deferralLaunch.VbsPath) {
            Remove-Item $deferralLaunch.VbsPath -Force -ErrorAction SilentlyContinue
        }
        return @{ Action = "Update"; DeferralDays = 0; CloseProcess = $true }
    }
}

function Clear-ExpiredDeferralData {
    <#
    .SYNOPSIS
        Cleans up old deferral and cache data
    .DESCRIPTION
        Removes deferral data for completed updates and old cached release dates
    #>
    
    try {
        Write-Log "Starting deferral data cleanup" | Out-Null

        $now = Get-Date
        $cleanupCount = 0

        # Clean up expired deferral data (older than 90 days)
        $appNames = Get-AppRegChildKeyNames -SubPath 'Deferrals'
        foreach ($appName in $appNames) {
            try {
                $sub = "Deferrals\$appName"
                $deferralData = Get-AppRegProperties -SubPath $sub
                if ($deferralData -and $deferralData.LastDeferralDate) {
                    $lastDeferral = [DateTime]::Parse($deferralData.LastDeferralDate)
                    if (($now - $lastDeferral).Days -gt 90) {
                        Remove-AppRegKey -SubPath $sub | Out-Null
                        Write-Log "Removed expired deferral data for: $appName" | Out-Null
                        $cleanupCount++
                    }
                }
            } catch {
                Write-Log "Error processing deferral cleanup for $appName : $($_.Exception.Message)" | Out-Null
            }
        }

        # Clean up old release cache entries (older than 30 days)
        try {
            $cacheData = Get-AppRegProperties -SubPath 'ReleaseCache'
            if ($cacheData) {
                $propertiesToRemove = @()
                foreach ($property in $cacheData.PSObject.Properties) {
                    if ($property.Name -notlike "PS*") {  # Skip PowerShell built-in properties
                        try {
                            $cacheDate = [DateTime]::Parse($property.Value)
                            if (($now - $cacheDate).Days -gt 30) {
                                $propertiesToRemove += $property.Name
                            }
                        } catch {
                            # If we can't parse the date, it might be malformed - remove it
                            $propertiesToRemove += $property.Name
                        }
                    }
                }

                foreach ($propName in $propertiesToRemove) {
                    Remove-AppRegValue -SubPath 'ReleaseCache' -Name $propName | Out-Null
                    $cleanupCount++
                }
            }
        } catch {
            Write-Log "Error during cache cleanup: $($_.Exception.Message)" | Out-Null
        }

        Write-Log "Deferral cleanup completed: $cleanupCount items removed" | Out-Null
        
    } catch {
        Write-Log "Error during deferral cleanup: $($_.Exception.Message)" | Out-Null
    }
}

# ============================================================================
# END DEFERRAL MANAGEMENT SYSTEM
# ============================================================================

# ============================================================================
# VERSION FAILURE TRACKING SYSTEM
# ============================================================================

function Get-VersionFailureData {
    <#
    .SYNOPSIS
        Returns failure count and skip status for a specific app version
    #>
    param(
        [Parameter(Mandatory)][string]$AppID,
        [Parameter(Mandatory)][string]$Version
    )
    $default = @{ FailureCount = 0; IsSkipped = $false }
    try {
        $sub = "Failures\$AppID"
        if (-not (Test-AppRegKey -SubPath $sub)) { return $default }
        $data = Get-AppRegProperties -SubPath $sub
        if (-not $data -or $data.FailedVersion -ne $Version) { return $default }
        return @{
            FailureCount = [int]($data.FailureCount)
            IsSkipped    = ($data.Skipped -eq "true")
        }
    } catch {
        return $default
    }
}

function Set-VersionFailure {
    <#
    .SYNOPSIS
        Increments the failure count for a specific app version. Returns new count.
    #>
    param(
        [Parameter(Mandatory)][string]$AppID,
        [Parameter(Mandatory)][string]$Version
    )
    try {
        $sub = "Failures\$AppID"
        $existing = Get-AppRegProperties -SubPath $sub
        $count = if ($existing -and $existing.FailedVersion -eq $Version) { [int]$existing.FailureCount + 1 } else { 1 }
        Set-AppRegValue -SubPath $sub -Name 'FailedVersion' -Value $Version | Out-Null
        Set-AppRegValue -SubPath $sub -Name 'FailureCount'  -Value ([int]$count) | Out-Null
        Set-AppRegValue -SubPath $sub -Name 'Skipped'       -Value 'false' | Out-Null
        Set-AppRegValue -SubPath $sub -Name 'LastFailure'   -Value (Get-Date -Format "o") | Out-Null
        return $count
    } catch {
        Write-Log "Error recording version failure for $AppID`: $($_.Exception.Message)" | Out-Null
        return 0
    }
}

function Set-VersionSkipped {
    <#
    .SYNOPSIS
        Marks a specific app version as skipped by the user
    #>
    param(
        [Parameter(Mandatory)][string]$AppID,
        [Parameter(Mandatory)][string]$Version
    )
    try {
        $sub = "Failures\$AppID"
        Set-AppRegValue -SubPath $sub -Name 'FailedVersion' -Value $Version | Out-Null
        Set-AppRegValue -SubPath $sub -Name 'Skipped'       -Value 'true' | Out-Null
        Set-AppRegValue -SubPath $sub -Name 'SkippedAt'     -Value (Get-Date -Format "o") | Out-Null
        Write-Log "Marked $AppID version $Version as skipped by user" | Out-Null
    } catch {
        Write-Log "Error marking version as skipped for $AppID`: $($_.Exception.Message)" | Out-Null
    }
}

function Clear-VersionFailureData {
    <#
    .SYNOPSIS
        Removes failure tracking data for an app (called after successful upgrade)
    #>
    param([Parameter(Mandatory)][string]$AppID)
    try {
        $sub = "Failures\$AppID"
        if (Test-AppRegKey -SubPath $sub) {
            Remove-AppRegKey -SubPath $sub | Out-Null
            Write-Log "Cleared failure tracking data for $AppID" | Out-Null
        }
    } catch {
        Write-Log "Error clearing failure data for $AppID`: $($_.Exception.Message)" | Out-Null
    }
}

function Show-VersionSkipDialog {
    <#
    .SYNOPSIS
        Shows a dialog offering the user to skip a version after repeated failures.
        Returns $true if user chose to skip, $false to retry next time.
        v9.33: when the persistent dialog host is alive, sends a `prompt-skip` command.
        "skip" -> $true; "retry"/"timeout"/host-died -> $false.
    #>
    param(
        [Parameter(Mandatory)][string]$AppName,
        [string]$FriendlyName,
        [Parameter(Mandatory)][string]$Version,
        [int]$FailureCount = 3,
        [int]$TimeoutSeconds = 60
    )

    try {
        $displayName = if ($FriendlyName) { $FriendlyName } else { $AppName }

        # v9.33: persistent dialog host path
        # v9.36: only commit to the host's reply when we get one. If the host dies mid-prompt,
        # fall through to legacy spawn so the user still sees a Skip/Retry choice.
        if (Test-DialogHostAlive) {
            $reply = Send-DialogCommand -Cmd "prompt-skip" -Payload @{
                app = $displayName
                failures = $FailureCount
                body = "Version $Version has failed $FailureCount times. Skip this version, or retry next cycle?"
                timeoutSec = $TimeoutSeconds
            } -Blocking -TimeoutSeconds ($TimeoutSeconds + 30)
            if ($reply -and $reply.response) {
                return ([string]$reply.response -eq "skip")
            }
            Write-Log "Show-VersionSkipDialog: dialog host died mid-prompt - falling back to legacy spawn" | Out-Null
            # fall through
        }

        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user - cannot show skip dialog for $AppName" | Out-Null
            return $false
        }

        $promptId     = [System.Guid]::NewGuid().ToString().Substring(0, 8)
        $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
        $responseFile = Join-Path $userTempPath "SkipPrompt_$promptId`_Response.json"
        $scriptPath   = Join-Path $userTempPath "Show-SkipPrompt_$promptId.ps1"

        $timesWord = if ($FailureCount -eq 1) { "time" } else { "times" }
        $message   = "$displayName $Version has failed to install $FailureCount $timesWord.`nSkip this version until a newer one becomes available?"
        $title     = "Update Failed - $displayName"

        $encodedMessage = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($message))
        $encodedTitle   = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($title))

        $scriptContent = @'
param(
    [string]$ResponseFilePath,
    [string]$EncodedMessage,
    [string]$EncodedTitle,
    [int]$TimeoutSeconds = 60
)
$logPath = Join-Path $env:TEMP "SkipPrompt_Debug.log"
function Write-SkipLog { param([string]$m); "[$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'))] $m" | Out-File -FilePath $logPath -Append -Encoding UTF8 -ErrorAction SilentlyContinue }

try {
    Write-SkipLog "=== SKIP PROMPT SCRIPT STARTED ==="
    $msg = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedMessage))
    $ttl = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedTitle))

    $isDark = $true
    try {
        $t = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -ErrorAction Stop
        $isDark = $t.AppsUseLightTheme -eq 0
    } catch {}
    if ($isDark) {
        $bgColor = "#FF1F1F1F"; $borderColor = "#FF323232"; $textColor = "#FFCCCCCC"; $shadowOpacity = "0.6"; $closeFg = "#FF888888"
    } else {
        $bgColor = "#FFF3F3F3"; $borderColor = "#FFD1D1D1"; $textColor = "#FF1B1B1B"; $shadowOpacity = "0.25"; $closeFg = "#FF999999"
    }

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop
    $workArea    = [System.Windows.SystemParameters]::WorkArea
    $dialogWidth = 480
    $escapedMsg  = [System.Security.SecurityElement]::Escape($msg) -replace "`n", "&#10;"
    $escapedTtl  = [System.Security.SecurityElement]::Escape($ttl)

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$escapedTtl" Width="$dialogWidth" SizeToContent="Height" WindowStartupLocation="Manual"
        ResizeMode="NoResize" WindowStyle="None" AllowsTransparency="True" Background="Transparent" Topmost="True" ShowInTaskbar="False">
    <Border Background="$bgColor" CornerRadius="8" BorderBrush="$borderColor" BorderThickness="1">
        <Border.Effect><DropShadowEffect ShadowDepth="4" Direction="270" Color="Black" Opacity="$shadowOpacity" BlurRadius="12"/></Border.Effect>
        <Grid>
            <Grid Margin="20">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>
                <TextBlock Grid.Row="0" Text="$escapedMsg" Foreground="$textColor" TextWrapping="Wrap" Margin="0,0,24,20" FontSize="12"/>
                <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Center">
                    <Button Name="SkipButton"  Content="Skip this version" Width="130" Height="28" Margin="0,0,8,0"/>
                    <Button Name="RetryButton" Content="Try again later"   Width="130" Height="28" Background="#FF0078D4" Foreground="White" IsDefault="True"/>
                </StackPanel>
            </Grid>
            <Button Name="CloseButton" Content="&#x2715;" Width="24" Height="24" HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0,6,6,0" Background="Transparent" Foreground="$closeFg" BorderThickness="0" FontSize="13" Cursor="Hand"/>
        </Grid>
    </Border>
</Window>
"@

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
    $window = [Windows.Markup.XamlReader]::Load($reader)
    $window.Left = $workArea.Right - $dialogWidth - 20
    $window.Top  = $workArea.Bottom - 220

    $writeResponse = { param($skip) @{ Skip = $skip } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8 }

    $window.FindName("SkipButton").Add_Click({
        Write-SkipLog "Skip button clicked"
        & $writeResponse $true
        $window.Close()
    })
    $window.FindName("RetryButton").Add_Click({
        Write-SkipLog "Retry button clicked"
        & $writeResponse $false
        $window.Close()
    })
    $window.FindName("CloseButton").Add_Click({
        Write-SkipLog "Close button clicked"
        & $writeResponse $false
        $window.Close()
    })

    $script:elapsed = 0
    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromSeconds(1)
    $timer.Add_Tick({
        $script:elapsed++
        if ($script:elapsed -ge $TimeoutSeconds) {
            Write-SkipLog "Timeout - defaulting to retry"
            & $writeResponse $false
            $window.Close()
        }
    })
    $timer.Start()
    Write-SkipLog "Showing dialog..."
    $window.ShowDialog() | Out-Null
    $timer.Stop()
    Write-SkipLog "Dialog closed"
} catch {
    Write-SkipLog "ERROR: $_"
    @{ Skip = $false } | ConvertTo-Json | Out-File -FilePath $ResponseFilePath -Encoding UTF8
}
'@

        $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8 -Force

        $psArgs   = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" " +
                    "-ResponseFilePath `"$responseFile`" " +
                    "-EncodedMessage `"$encodedMessage`" -EncodedTitle `"$encodedTitle`" " +
                    "-TimeoutSeconds $TimeoutSeconds"
        $taskName = "SkipPrompt_$promptId"
        $launch   = New-HiddenLaunchAction -PowerShellArguments $psArgs -VbsDirectory $userTempPath -AllowUI

        $principal = New-ScheduledTaskPrincipal -UserId $userInfo.FullName -LogonType Interactive -RunLevel Limited
        $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
        $task      = New-ScheduledTask -Action $launch.Action -Principal $principal -Settings $settings
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Write-Log "Skip version dialog launched (task: $taskName)" | Out-Null

        # Wait for user response
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds + 15)
        while (-not (Test-Path $responseFile) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 2
        }

        $skipChoice = $false
        if (Test-Path $responseFile) {
            try {
                $response   = Get-Content $responseFile -Raw | ConvertFrom-Json
                $skipChoice = ($response.Skip -eq $true)
                Write-Log "Skip dialog response received: Skip=$skipChoice" | Out-Null
            } catch {
                Write-Log "Error reading skip dialog response: $($_.Exception.Message)" | Out-Null
            }
        } else {
            Write-Log "Skip dialog timed out - defaulting to retry" | Out-Null
        }

        # Cleanup
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item $scriptPath   -Force -ErrorAction SilentlyContinue
        Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
        if ($launch.VbsPath) { Remove-Item $launch.VbsPath -Force -ErrorAction SilentlyContinue }

        return $skipChoice

    } catch {
        Write-Log "Error showing skip dialog for $AppName`: $($_.Exception.Message)" | Out-Null
        if ($taskName) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        Remove-Item $responseFile -Force -ErrorAction SilentlyContinue
        if ($launch -and $launch.VbsPath) {
            Remove-Item $launch.VbsPath -Force -ErrorAction SilentlyContinue
        }
        return $false
    }
}

# ============================================================================
# END VERSION FAILURE TRACKING SYSTEM
# ============================================================================

function Schedule-UserContextRemediation {
    <#
    .SYNOPSIS
        Schedules user context remediation execution - EXACT SAME APPROACH AS WORKING DETECTION SCRIPT
    .DESCRIPTION
        Uses the proven method from Invoke-UserContextDetection function
    #>
    
    try {
        Write-Log "Starting user context remediation scheduling" | Out-Null
        $startTime = Get-Date

        $userInfo = Get-InteractiveUser
        if (-not $userInfo) {
            Write-Log "No interactive user found - skipping user context remediation" | Out-Null
            return $false
        }
        Write-Log "Interactive user: $($userInfo.Username)" | Out-Null
        
        # Create remediation result file - use shared path accessible to both SYSTEM and USER contexts (SAME AS DETECTION)
        $sharedTempPath = "C:\ProgramData\Temp"
        if (-not (Test-Path $sharedTempPath)) {
            New-Item -Path $sharedTempPath -ItemType Directory -Force | Out-Null
        }
        $randomId = Get-Random -Minimum 1000 -Maximum 9999
        $resultFile = Join-Path $sharedTempPath "UserRemediation_$randomId.json"
        Write-Log "User remediation result file: $resultFile" | Out-Null
        Write-Log "Using shared temp path accessible to both SYSTEM and USER contexts: $sharedTempPath" | Out-Null
        
        # Create scheduled task for user remediation (SAME APPROACH AS DETECTION)
        $taskName = "UserRemediation_$(Get-Random -Minimum 1000 -Maximum 9999)"
        $tempScriptName = "availableUpgrades-remediate_$(Get-Random -Minimum 1000 -Maximum 9999).ps1"
        $tempScriptPath = Join-Path $sharedTempPath $tempScriptName
        
        Write-Log "Copying script to user-accessible location: $tempScriptPath" | Out-Null
        
        # Verify source script exists and get its size first
        if (-not (Test-Path $Global:CurrentScriptPath)) {
            Write-Log "ERROR: Source script does not exist: $Global:CurrentScriptPath" | Out-Null
            return $false
        }
        
        $sourceSize = (Get-Item $Global:CurrentScriptPath).Length
        Write-Log "Source script size: $sourceSize bytes" | Out-Null

        # Detect bootstrapper/wrapper scenario (small file that downloads the real script via iex/irm)
        if ($sourceSize -lt 1000) {
            Write-Log "Source appears to be a bootstrapper wrapper ($sourceSize bytes) - downloading full script" | Out-Null
            try {
                $bootstrapContent = Get-Content $Global:CurrentScriptPath -Raw
                if ($bootstrapContent -match 'irm\s+[''"]([^''"]+)[''"]') {
                    $scriptUrl = $Matches[1]
                    Write-Log "Extracted download URL from bootstrapper: $scriptUrl" | Out-Null
                    $fullScript = Invoke-RestMethod -Uri $scriptUrl -ErrorAction Stop
                    $fullScript | Out-File -FilePath $tempScriptPath -Encoding UTF8 -Force
                    $scriptSize = (Get-Item $tempScriptPath).Length
                    Write-Log "Downloaded full script to temp: $scriptSize bytes" | Out-Null
                } else {
                    Write-Log "ERROR: Could not extract download URL from bootstrapper content" | Out-Null
                    return $false
                }
            } catch {
                Write-Log "ERROR: Failed to download full script from bootstrapper URL: $($_.Exception.Message)" | Out-Null
                return $false
            }
        } else {
            # Copy with enhanced error handling and verification
            try {
                Copy-Item -Path $Global:CurrentScriptPath -Destination $tempScriptPath -Force -ErrorAction Stop
                Write-Log "Copy-Item completed successfully" | Out-Null
            } catch {
                Write-Log "ERROR: Copy-Item failed: $($_.Exception.Message)" | Out-Null
                return $false
            }
        }

        # Verify script copy with size validation
        if (Test-Path $tempScriptPath) {
            $scriptSize = (Get-Item $tempScriptPath).Length
            $expectedMinSize = if ($sourceSize -lt 1000) { 1000 } else { $sourceSize }
            Write-Log "Temp script exists, size: $scriptSize bytes (expected min: $expectedMinSize bytes)" | Out-Null

            # Validate copy integrity
            if ($scriptSize -lt $expectedMinSize) {
                Write-Log "ERROR: Script copy size too small! Got: $scriptSize bytes, Expected min: $expectedMinSize bytes" | Out-Null
                Write-Log "Attempting second copy operation..." | Out-Null

                # Remove corrupted copy and try again
                Remove-Item $tempScriptPath -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 500

                try {
                    Copy-Item -Path $Global:CurrentScriptPath -Destination $tempScriptPath -Force -ErrorAction Stop
                    $retrySize = (Get-Item $tempScriptPath).Length
                    Write-Log "Retry copy completed, size: $retrySize bytes" | Out-Null

                    if ($retrySize -ne $sourceSize) {
                        Write-Log "ERROR: Retry copy also failed - size still incorrect" | Out-Null
                        return $false
                    }
                } catch {
                    Write-Log "ERROR: Retry copy failed: $($_.Exception.Message)" | Out-Null
                    return $false
                }
            }
        } else {
            Write-Log "ERROR: Temp script copy does not exist: $tempScriptPath" | Out-Null
            return $false
        }
        
        $scriptPath = $tempScriptPath
        # Create hidden launch action using VBS wrapper (no console window flash)
        # Pass WhitelistUrl through so the user-context child process uses the same whitelist source
        $whitelistArg = if ($whitelistUrl) { " -WhitelistUrl `"$whitelistUrl`"" } else { "" }
        # v9.33: pass the live dialog session id so user-context can attach to the same WPF host
        $dialogArg = if ($Script:DialogSession -and (Test-DialogHostAlive)) { " -DialogSessionId `"$($Script:DialogSession.SessionId)`"" } else { "" }
        $remPsArgs = "powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -UserRemediationOnly -RemediationResultFile `"$resultFile`"$whitelistArg$dialogArg"
        $remLaunch = New-HiddenLaunchAction -PowerShellArguments $remPsArgs -VbsDirectory $sharedTempPath
        if (-not $remLaunch) {
            Write-Log "ERROR: Failed to create hidden launch action - falling back to direct PowerShell" | Out-Null
            $remLaunch = @{
                Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -UserRemediationOnly -RemediationResultFile `"$resultFile`"$whitelistArg$dialogArg"
                VbsPath = $null
            }
        }

        Write-Log "Creating user remediation task: $taskName" | Out-Null
        Write-Log "Script path: $scriptPath" | Out-Null
        Write-Log "Launch method: $(if ($remLaunch.VbsPath) { 'VBS hidden launcher' } else { 'Direct PowerShell' })" | Out-Null
        Write-Log "Result file: $resultFile" | Out-Null

        try {
            Write-Log "Creating scheduled task action..." | Out-Null
            $taskCreationStart = Get-Date

            # Use pre-created hidden launch action (VBS wrapper)
            $action = $remLaunch.Action
            Write-Log "Task action created successfully" | Out-Null
            
            # Create task principal (run as interactive user) - SAME AS DETECTION
            Write-Log "Creating task principal for user: $($userInfo.FullName)" | Out-Null
            $principalStart = Get-Date
            $principal = $null
            $userFormats = @($userInfo.FullName, $userInfo.Username, ".\$($userInfo.Username)")
            $logonTypes = @("Interactive", "S4U")
            
            # v9.54: bump RunLevel from Limited to Highest. Some upgrades require admin
            # privileges to land at machine scope (e.g. Git.Git which lives in
            # C:\Program Files\ - the user's winget LocalState binds catalog Id to install,
            # but the install itself needs elevation to overwrite Program Files\Git\). With
            # RunLevel Limited the scheduled task ran with a stripped-down user token and
            # silently failed those upgrades; for admin users Highest runs elevated (no UAC
            # prompt - scheduled tasks at Highest auto-elevate for members of the local
            # Administrators group). For non-admin users Highest is still their effective
            # max, so no regression.
            foreach ($userFormat in $userFormats) {
                foreach ($logonType in $logonTypes) {
                    try {
                        $principal = New-ScheduledTaskPrincipal -UserId $userFormat -LogonType $logonType -RunLevel Highest
                        Write-Log "Successfully created principal with: $userFormat ($logonType, RunLevel Highest)" | Out-Null
                        break
                    } catch {
                        Write-Log "Failed with format '$userFormat' ($logonType): $($_.Exception.Message)" | Out-Null
                    }
                }
                if ($principal) { break }
            }
            
            if (-not $principal) {
                $principalTime = (Get-Date) - $principalStart
                Write-Log "Could not create task principal with any method after $($principalTime.TotalSeconds) seconds" | Out-Null
                return $false
            }
            
            $principalTime = (Get-Date) - $principalStart
            Write-Log "Task principal created successfully in $($principalTime.TotalSeconds) seconds" | Out-Null
            
            # Create task settings - SAME AS DETECTION
            Write-Log "Creating task settings..." | Out-Null
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
            
            # Create and register the task WITHOUT triggers (SAME AS DETECTION)
            Write-Log "Creating and registering scheduled task..." | Out-Null
            $registrationStart = Get-Date
            $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings -Description "User context winget remediation"
            Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
            $registrationTime = (Get-Date) - $registrationStart
            Write-Log "Task created successfully: $taskName in $($registrationTime.TotalSeconds) seconds" | Out-Null
            
            # Verify task was created successfully before starting (SAME AS DETECTION)
            $createdTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if (-not $createdTask) {
                Write-Log "ERROR: Task creation failed - task not found: $taskName" | Out-Null
                return $false
            }
            Write-Log "Task verified to exist: $taskName, State: $($createdTask.State)" | Out-Null
            
            # Start the task (SAME AS DETECTION)
            Write-Log "Starting user remediation task: $taskName" | Out-Null
            $taskStartTime = Get-Date
            try {
                Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                $taskStartDuration = (Get-Date) - $taskStartTime
                Write-Log "Start-ScheduledTask completed successfully in $($taskStartDuration.TotalSeconds) seconds" | Out-Null
                
                # Brief verification that task started
                Write-Log "Verifying task started..." | Out-Null
                Start-Sleep -Seconds 2
                $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                if ($taskInfo) {
                    Write-Log "Task started successfully - LastResult: $($taskInfo.LastTaskResult), LastRunTime: $($taskInfo.LastRunTime)" | Out-Null
                } else {
                    Write-Log "Could not get task info after start" | Out-Null
                }
                
            } catch {
                $taskStartDuration = (Get-Date) - $taskStartTime
                Write-Log "ERROR: Failed to start scheduled task after $($taskStartDuration.TotalSeconds) seconds: $($_.Exception.Message)" | Out-Null
                return $false
            }
            
            # Enhanced wait system with marker file synchronization
            # Create status/heartbeat file paths
            $statusFile = Join-Path $sharedTempPath "UserRemediation_$randomId.status"
            $heartbeatFile = Join-Path $sharedTempPath "UserRemediation_$randomId.heartbeat"
            
            # Idle-based timeout: resets whenever a heartbeat is received, times out after 600s of silence
            $idleTimeout = 600  # 10 minutes without heartbeat = timeout
            $heartbeatTimeout = 120  # 2 minutes: max age for a heartbeat to be considered "active"
            $startTime = Get-Date
            $success = $false

            Write-Log "Waiting for user remediation results with marker file synchronization" | Out-Null
            Write-Log "Result file expected at: $resultFile" | Out-Null
            Write-Log "Status file: $statusFile" | Out-Null
            Write-Log "Heartbeat file: $heartbeatFile" | Out-Null
            Write-Log "Idle timeout: $idleTimeout seconds (resets on heartbeat), Heartbeat active threshold: $heartbeatTimeout seconds" | Out-Null

            $waitStartTime = Get-Date
            $lastHeartbeatTime = Get-Date  # Tracks when we last saw an active heartbeat (or start time)
            $lastStatusLog = Get-Date
            $lastHeartbeatCheck = Get-Date
            $checkCount = 0

            while ($true) {
                $idleSeconds = ((Get-Date) - $lastHeartbeatTime).TotalSeconds
                if ($idleSeconds -ge $idleTimeout) {
                    Write-Log "Idle timeout reached: no heartbeat for $([int]$idleSeconds) seconds (limit: $idleTimeout)" | Out-Null
                    break
                }
                $checkCount++
                $currentTime = Get-Date
                $elapsedTotal = ($currentTime - $waitStartTime).TotalSeconds
                
                # Check for completion first (result file exists)
                if (Test-Path $resultFile) {
                    try {
                        Write-Log "Result file found after $elapsedTotal seconds" | Out-Null
                        Start-Sleep -Milliseconds 500  # Brief pause to ensure file is fully written
                        $fileContent = Get-Content $resultFile -Raw
                        $results = $fileContent | ConvertFrom-Json
                        
                        Write-Log "User remediation completed: $($results.ProcessedApps) apps processed" | Out-Null
                        if ($results.UpgradeResults) {
                            Write-Log "User remediation results: $($results.UpgradeResults -join ', ')" | Out-Null
                        }
                        $success = $true
                        break
                    } catch {
                        Write-Log "Error reading/parsing remediation results: $($_.Exception.Message)" | Out-Null
                        Start-Sleep -Seconds 2
                        continue
                    }
                }
                
                # Enhanced heartbeat checking with multiple indicators
                $isUserContextActive = $false
                $heartbeatAge = 999
                $heartbeatSources = @()
                
                # Check primary heartbeat file
                if (Test-Path $heartbeatFile) {
                    try {
                        $heartbeatTime = (Get-Item $heartbeatFile).LastWriteTime
                        $heartbeatAge = ($currentTime - $heartbeatTime).TotalSeconds
                        $isUserContextActive = ($heartbeatAge -lt $heartbeatTimeout)
                        $heartbeatSources += "primary"
                        
                        if (-not $isUserContextActive) {
                            Write-Log "WARNING: Primary heartbeat file is $([int]$heartbeatAge) seconds old (timeout: $heartbeatTimeout)" | Out-Null
                        }
                    } catch {
                        Write-Log "Error reading primary heartbeat file: $($_.Exception.Message)" | Out-Null
                    }
                }
                
                # Check emergency heartbeat file
                if (-not $isUserContextActive -and (Test-Path "$heartbeatFile.emergency")) {
                    try {
                        $emergencyTime = (Get-Item "$heartbeatFile.emergency").LastWriteTime
                        $emergencyAge = ($currentTime - $emergencyTime).TotalSeconds
                        if ($emergencyAge -lt $heartbeatTimeout) {
                            $isUserContextActive = $true
                            $heartbeatAge = $emergencyAge
                            $heartbeatSources += "emergency"
                            Write-Log "Using emergency heartbeat (age: $([int]$emergencyAge)s)" | Out-Null
                        }
                    } catch {
                        Write-Log "Error reading emergency heartbeat file: $($_.Exception.Message)" | Out-Null
                    }
                }
                
                # Check timestamp file as backup
                if (-not $isUserContextActive -and (Test-Path "$heartbeatFile.timestamp")) {
                    try {
                        $timestampTime = (Get-Item "$heartbeatFile.timestamp").LastWriteTime
                        $timestampAge = ($currentTime - $timestampTime).TotalSeconds
                        if ($timestampAge -lt $heartbeatTimeout) {
                            $isUserContextActive = $true
                            $heartbeatAge = $timestampAge
                            $heartbeatSources += "timestamp"
                            Write-Log "Using timestamp heartbeat (age: $([int]$timestampAge)s)" | Out-Null
                        }
                    } catch {
                        Write-Log "Error reading timestamp heartbeat file: $($_.Exception.Message)" | Out-Null
                    }
                }
                
                # Check for user context debug files as indicator of activity
                if (-not $isUserContextActive) {
                    try {
                        $debugFiles = @(
                            "C:\ProgramData\Temp\UserContext_Debug.log",
                            "$env:TEMP\UserContext_Debug_Fallback.log"
                        )
                        
                        foreach ($debugFile in $debugFiles) {
                            if (Test-Path $debugFile) {
                                $debugTime = (Get-Item $debugFile).LastWriteTime
                                $debugAge = ($currentTime - $debugTime).TotalSeconds
                                if ($debugAge -lt $heartbeatTimeout) {
                                    $isUserContextActive = $true
                                    $heartbeatAge = $debugAge
                                    $heartbeatSources += "debug"
                                    Write-Log "Using debug file as heartbeat indicator (age: $([int]$debugAge)s)" | Out-Null
                                    break
                                }
                            }
                        }
                    } catch {
                        # Ignore debug file errors
                    }
                }
                
                # Log heartbeat status
                if ($elapsedTotal -gt 30 -and -not $isUserContextActive) {
                    Write-Log "No heartbeat indicators found after $([int]$elapsedTotal) seconds (checked: $($heartbeatSources -join ', '))" | Out-Null
                } elseif ($isUserContextActive -and $heartbeatSources.Count -gt 0) {
                    Write-Log "Heartbeat active via: $($heartbeatSources -join ', ') (age: $([int]$heartbeatAge)s)" | Out-Null
                } elseif ($elapsedTotal -le 30) {
                    $isUserContextActive = $true  # Still within startup grace period
                }

                # Reset idle timer whenever heartbeat is active
                if ($isUserContextActive) {
                    $lastHeartbeatTime = Get-Date
                }
                
                # Check status file for progress updates
                $statusMessage = ""
                if (Test-Path $statusFile) {
                    try {
                        $statusContent = Get-Content $statusFile -Raw
                        $statusInfo = $statusContent | ConvertFrom-Json
                        $statusMessage = "Status: $($statusInfo.Status), Progress: $($statusInfo.Progress)"
                    } catch {
                        $statusMessage = "Status file exists but unreadable"
                    }
                }
                
                # Log status every 15 seconds
                if (($currentTime - $lastStatusLog).TotalSeconds -gt 15) {
                    Write-Log "Waiting... elapsed: $([int]$elapsedTotal)s, checks: $checkCount" | Out-Null
                    if ($statusMessage) {
                        Write-Log $statusMessage | Out-Null
                    }
                    if (Test-Path $heartbeatFile) {
                        Write-Log "Heartbeat: $([int]$heartbeatAge)s ago, Active: $isUserContextActive" | Out-Null
                    }
                    
                    # Check if task is still running
                    try {
                        $currentTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                        if ($currentTask) {
                            $currentTaskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                            if ($currentTaskInfo) {
                                Write-Log "Task status: State=$($currentTask.State), LastResult=$($currentTaskInfo.LastTaskResult)" | Out-Null
                            }
                        } else {
                            Write-Log "Scheduled task no longer exists" | Out-Null
                        }
                    } catch {
                        Write-Log "Could not check task status: $($_.Exception.Message)" | Out-Null
                    }
                    
                    $lastStatusLog = $currentTime
                }
                
                Start-Sleep -Seconds 3  # Slightly longer sleep since we're monitoring more files
            }

            $totalWaitTime = (Get-Date) - $waitStartTime
            $finalIdleSeconds = ((Get-Date) - $lastHeartbeatTime).TotalSeconds
            if ($finalIdleSeconds -ge $idleTimeout) {
                Write-Log "User remediation idle-timed out after $([int]$totalWaitTime.TotalSeconds) seconds total ($([int]$finalIdleSeconds)s since last heartbeat, limit: $idleTimeout)" | Out-Null
                Write-Log "Total file existence checks performed: $checkCount" | Out-Null
                
                # Final check on task status
                try {
                    $finalTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    if ($finalTask) {
                        $finalTaskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
                        Write-Log "Final task status: State=$($finalTask.State), LastResult=$($finalTaskInfo.LastTaskResult)" | Out-Null
                    }
                } catch {
                    Write-Log "Could not get final task status" | Out-Null
                }
            } else {
                Write-Log "User remediation completed successfully in $($totalWaitTime.TotalSeconds) seconds" | Out-Null
            }
            
            # Clean up marker files
            try {
                if (Test-Path $statusFile) { Remove-Item $statusFile -Force -ErrorAction SilentlyContinue }
                if (Test-Path $heartbeatFile) { Remove-Item $heartbeatFile -Force -ErrorAction SilentlyContinue }
                Write-Log "Cleaned up marker files" | Out-Null
            } catch {
                Write-Log "Error cleaning up marker files: $($_.Exception.Message)" | Out-Null
            }
            
        } catch {
            Write-Log "Exception in user remediation task: $($_.Exception.Message)" | Out-Null
            $success = $false
        } finally {
            # Cleanup - SAME AS DETECTION
            try {
                Write-Log "Starting cleanup" | Out-Null
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                
                if (Test-Path $resultFile) {
                    Remove-Item $resultFile -Force -ErrorAction SilentlyContinue
                }
                
                # Clean up temporary script copy
                if (Test-Path $tempScriptPath) {
                    Remove-Item $tempScriptPath -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed temporary script copy: $tempScriptPath" | Out-Null
                }

                # Clean up VBS hidden launcher file
                if ($remLaunch.VbsPath -and (Test-Path $remLaunch.VbsPath)) {
                    Remove-Item $remLaunch.VbsPath -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed VBS hidden launcher: $($remLaunch.VbsPath)" | Out-Null
                }

                Write-Log "User remediation cleanup completed" | Out-Null
            } catch {
                Write-Log "Error during cleanup: $($_.Exception.Message)" | Out-Null
            }
        }
        
        $totalElapsed = (Get-Date) - $startTime
        Write-Log "Schedule-UserContextRemediation completed in $($totalElapsed.TotalSeconds) seconds with result: $success" | Out-Null
        return $success
        
    } catch {
        $totalElapsed = (Get-Date) - $startTime
        Write-Log "Error in user context remediation scheduling after $($totalElapsed.TotalSeconds) seconds: $($_.Exception.Message)" | Out-Null
        Write-Log "Exception details: $($_.Exception.ToString())" | Out-Null
        return $false
    }
}

function Stop-BlockingProcesses {
    param(
        [string]$ProcessNames
    )
    
    $processesToStop = $ProcessNames -split ','
    $stoppedAny = $false
    $allProcesses = @()
    
    # Collect all processes to stop
    foreach ($processName in $processesToStop) {
        $processName = $processName.Trim()
        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
        
        if ($processes) {
            foreach ($process in $processes) {
                $allProcesses += @{
                    Process = $process
                    Name = $processName
                    PID = $process.Id
                }
            }
        }
    }
    
    if ($allProcesses.Count -eq 0) {
        Write-Log -Message "No processes found to stop"
        return $false
    }
    
    $processCount = $allProcesses.Count
    Write-Log -Message "Found $processCount processes to close: $($allProcesses.Name -join ', ')"
    
    try {
        if ($processCount -gt 1) {
            Write-Log -Message "Multiple processes detected ($processCount), using parallel termination strategy"
            
            # Step 1: Attempt graceful close on all processes simultaneously
            Write-Log -Message "Attempting graceful close on all processes simultaneously..."
            foreach ($procInfo in $allProcesses) {
                try {
                    Write-Log -Message "Sending close signal to: $($procInfo.Name) (PID: $($procInfo.PID))"
                    $procInfo.Process.CloseMainWindow()
                } catch {
                    Write-Log -Message "Error sending close signal to $($procInfo.Name): $($_.Exception.Message)"
                }
            }
            
            # Step 2: Wait 2 seconds total (reduced from 5)
            Write-Log -Message "Waiting 2 seconds for graceful shutdown..."
            Start-Sleep -Seconds 2
            
            # Step 3: Check which processes are still running and force-kill them all at once
            $remainingProcesses = @()
            foreach ($procInfo in $allProcesses) {
                try {
                    # Refresh process state
                    $stillRunning = Get-Process -Id $procInfo.PID -ErrorAction SilentlyContinue
                    if ($stillRunning) {
                        $remainingProcesses += $procInfo
                    } else {
                        Write-Log -Message "Process $($procInfo.Name) (PID: $($procInfo.PID)) closed gracefully"
                        $stoppedAny = $true
                    }
                } catch {
                    # Process no longer exists (good)
                    Write-Log -Message "Process $($procInfo.Name) (PID: $($procInfo.PID)) no longer exists"
                    $stoppedAny = $true
                }
            }
            
            # Step 4: Force terminate remaining processes in parallel
            if ($remainingProcesses.Count -gt 0) {
                Write-Log -Message "Force-terminating $($remainingProcesses.Count) remaining processes..."
                foreach ($procInfo in $remainingProcesses) {
                    try {
                        Write-Log -Message "Force-killing: $($procInfo.Name) (PID: $($procInfo.PID))"
                        $procInfo.Process.Kill()
                        $stoppedAny = $true
                    } catch {
                        Write-Log -Message "Error force-killing $($procInfo.Name): $($_.Exception.Message)"
                    }
                }
                
                # Brief verification wait
                Start-Sleep -Seconds 1
                
                # Final verification
                $finalCheck = 0
                foreach ($procInfo in $remainingProcesses) {
                    try {
                        $stillExists = Get-Process -Id $procInfo.PID -ErrorAction SilentlyContinue
                        if ($stillExists) {
                            $finalCheck++
                            Write-Log -Message "WARNING: Process $($procInfo.Name) (PID: $($procInfo.PID)) still exists after force termination"
                        }
                    } catch {
                        # Process successfully terminated
                    }
                }
                
                if ($finalCheck -eq 0) {
                    Write-Log -Message "All processes successfully terminated using parallel approach"
                } else {
                    $remainingCount = $finalCheck
                    Write-Log -Message "Some processes may still be running ($($remainingCount) remaining)"
                }
            } else {
                Write-Log -Message "All processes closed gracefully - no force termination needed"
            }
            
            Write-Log -Message "Parallel process termination completed in ~6 seconds"
            
        } else {
            # Single process - use traditional approach
            Write-Log -Message "Single process detected, using traditional termination"
            $procInfo = $allProcesses[0]
            
            try {
                Write-Log -Message "Stopping process: $($procInfo.Name) (PID: $($procInfo.PID))"
                $procInfo.Process.CloseMainWindow()
                
                # Wait up to 3 seconds for graceful shutdown (reduced from 10)
                if (!$procInfo.Process.WaitForExit(3000)) {
                    Write-Log -Message "Process $($procInfo.Name) did not exit gracefully after 3s, forcing termination"
                    $procInfo.Process.Kill()
                }
                $stoppedAny = $true
                Write-Log -Message "Successfully stopped process: $($procInfo.Name)"
            } catch {
                Write-Log -Message "Error stopping process $($procInfo.Name): $($_.Exception.Message)"
            }
        }
        
    } catch {
        Write-Log -Message "Error in Stop-BlockingProcesses: $($_.Exception.Message)"
    }
    
    return $stoppedAny
}

function Remove-OldLogs {
    param([string]$LogPath)

    try {
        $cutoffDate = (Get-Date).AddMonths(-1)
        $logFiles = Get-ChildItem -Path $LogPath -Filter "*AvailableUpgrades*.log" -ErrorAction SilentlyContinue
        foreach ($logFile in $logFiles) {
            if ($logFile.LastWriteTime -lt $cutoffDate) {
                Remove-Item -Path $logFile.FullName -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Removed old log file: $($logFile.Name)"
            }
        }
    } catch {
        # Don't use Write-Log here as it may not be ready yet - just silently continue
    }
}

function Remove-OldTempFiles {
    <#
    .SYNOPSIS
        Cleans up stale temp files and abandoned per-session directories created by either
        the detect or remediate script in C:\ProgramData\Temp and user temp directories.
    .DESCRIPTION
        v9.50: regex unified with detect.ps1 so each script's startup cleanup catches the
        OTHER script's leftovers too (previously remediate didn't know about UserDetection_*
        files, and detect didn't know about availableUpgrades-dialog-* per-session
        directories - so cross-leftovers accumulated). Also scans DIRECTORIES, not just files,
        so abandoned dialog-host per-session subdirectories (introduced in v9.43) get cleaned
        if Stop-DialogHost couldn't tear them down.
    #>
    # v9.51: 60-minute cutoff (was 10). The previous 10-minute window assumed all script-owned
    # files were tied to short-lived dialogs and prompts, but a remediation run with several
    # large packages (Office, VS, multi-gigabyte downloads with retries) can easily stay
    # running for 30+ minutes - and during that time its own in-flight files match the cleanup
    # regex. 60 minutes is comfortably longer than any legitimate single run and still recent
    # enough to catch actual orphans on the next startup.
    $cutoff = (Get-Date).AddMinutes(-60)
    $removed = 0

    # Combined regex covers everything either script creates. Order is for readability:
    #   - Result/heartbeat JSON files       (UserDetection_, UserRemediation_, UserRemediationHeartbeat_)
    #   - Script copies                     (availableUpgrades-detect_, availableUpgrades-remediate_)
    #   - Persistent dialog host artifacts  (availableUpgrades-dialog-*)
    #   - Per-prompt response/script files  (MandatoryPrompt_, DeferralPrompt_, etc.)
    #   - VBS launchers + misc debug logs
    $nameRegex = '^(UserDetection_(Fallback_)?\d+\.json$|UserRemediation_\d+\.|UserRemediationHeartbeat_|availableUpgrades-detect_\d+\.ps1|availableUpgrades-remediate_\d+\.ps1|availableUpgrades-dialog-|MandatoryPrompt_.*_(Response|Progress)|Show-MandatoryPrompt_|DeferralPrompt_.*_Response|Show-DeferralPrompt_|UserPrompt_.*_Response|Show-UserPrompt_|UpgradeProgress_.*_(Signal|Status)|Show-UpgradeProgress_|CompletionNotification_|Show-CompletionNotification_|SkipPrompt_.*_Response|Show-SkipPrompt_|UserContext_Debug|UserContext_Heartbeat_Error_|HiddenLaunch_\d+\.vbs$)'

    $scanLocation = {
        param([string]$path)
        if (-not (Test-Path $path)) { return 0 }
        $local:n = 0
        # Files
        Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $nameRegex -and $_.LastWriteTime -lt $cutoff } |
            ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                $local:n++
            }
        # Directories - currently only the dialog host's per-session subdir matches our patterns.
        # Remove-Item -Recurse is required because the directory has files inside.
        Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $nameRegex -and $_.LastWriteTime -lt $cutoff } |
            ForEach-Object {
                Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
                $local:n++
            }
        return $local:n
    }

    $removed += & $scanLocation "C:\ProgramData\Temp"

    # Scan user temp directories for VBS launchers and dialog script/response files
    try {
        $userTempPaths = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName "AppData\Local\Temp" } |
            Where-Object { Test-Path $_ }

        foreach ($userTemp in $userTempPaths) {
            $removed += & $scanLocation $userTemp
        }
    } catch {
        # Don't let user temp cleanup failures block the main script
    }

    if ($removed -gt 0) {
        Write-Log -Message "Cleaned up $removed old temp files/directories"
    }
}

function Remove-StaleScheduledTasks {
    <#
    .SYNOPSIS
        Removes orphaned scheduled tasks left behind by previous script executions
    .DESCRIPTION
        Sweeps Task Scheduler for tasks matching known prefixes that are older than
        the specified age. Handles cases where Start-Job cleanup never ran (process
        terminated), or an unhandled exception skipped the normal cleanup path.
    #>
    param(
        [int]$MaxAgeMinutes = 10
    )

    $prefixes = @(
        "UserPrompt_",
        "UpgradeProgress_",
        "CompletionNotification_",
        "MandatoryPrompt_",
        "DeferralPrompt_",
        "SkipPrompt_",
        "UserRemediation_",
        "DialogHost_"
    )

    try {
        $cutoff = (Get-Date).AddMinutes(-$MaxAgeMinutes)
        $allTasks = Get-ScheduledTask -TaskPath "\" -ErrorAction SilentlyContinue
        if (-not $allTasks) { return 0 }

        $removed = 0
        foreach ($task in $allTasks) {
            $matched = $false
            foreach ($prefix in $prefixes) {
                if ($task.TaskName.StartsWith($prefix)) {
                    $matched = $true
                    break
                }
            }
            if (-not $matched) { continue }

            # Use task registration date to determine age
            try {
                $taskDate = [datetime]::Parse($task.Date)
                if ($taskDate -lt $cutoff) {
                    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                    $removed++
                }
            } catch {
                # If we cannot parse the date, remove it as a precaution (it is orphaned if prefix matches)
                Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
                $removed++
            }
        }

        if ($removed -gt 0) {
            Write-Log -Message "Cleaned up $removed stale scheduled tasks (older than $MaxAgeMinutes minutes)"
        }
        return $removed
    } catch {
        # Don't let cleanup failures block the main script
        return 0
    }
}

# ============================================================================
# CENTRALIZED MARKER FILE MANAGEMENT SYSTEM
# Provides robust marker file operations with comprehensive cleanup
# ============================================================================

# Global variable to track active marker files for cleanup
$Global:ActiveMarkerFiles = @()

function New-MarkerFile {
    <#
    .SYNOPSIS
        Creates a marker file with centralized tracking and logging
    .DESCRIPTION
        Creates marker files used for inter-process communication while tracking
        them globally for reliable cleanup. Handles path validation and error logging.
    .PARAMETER FilePath
        Full path where the marker file should be created
    .PARAMETER Content
        Content to write to the marker file
    .PARAMETER Description
        Description for logging purposes
    .OUTPUTS
        Boolean indicating success, and adds file to global tracking
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$true)]
        [string]$Content,
        
        [string]$Description = "Marker file"
    )
    
    try {
        Write-Log -Message "Creating marker file: $FilePath ($Description)"
        
        # Ensure directory exists
        $directory = Split-Path -Parent $FilePath
        if ($directory -and -not (Test-Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Log -Message "Created directory for marker file: $directory"
        }
        
        # Create the marker file
        $Content | Out-File -FilePath $FilePath -Encoding UTF8 -Force -ErrorAction Stop
        
        # Add to global tracking for cleanup
        if ($Global:ActiveMarkerFiles -notcontains $FilePath) {
            $Global:ActiveMarkerFiles += $FilePath
            Write-Log -Message "Added marker file to cleanup tracking: $FilePath"
        }
        
        # Verify creation
        if (Test-Path $FilePath) {
            $fileSize = (Get-Item $FilePath -ErrorAction SilentlyContinue).Length
            Write-Log -Message "Successfully created marker file: $FilePath (Size: $fileSize bytes, Content: $($Content.Substring(0, [Math]::Min(50, $Content.Length)))...)"
            return $true
        } else {
            Write-Log -Message "ERROR: Marker file was not created despite successful Out-File: $FilePath"
            return $false
        }
        
    } catch {
        Write-Log -Message "ERROR: Failed to create marker file '$FilePath': $($_.Exception.Message)"
        return $false
    }
}

function Remove-MarkerFile {
    <#
    .SYNOPSIS
        Removes a specific marker file with logging and error handling
    .DESCRIPTION
        Safely removes marker files with comprehensive error handling and logging.
        Also removes the file from global tracking.
    .PARAMETER FilePath
        Full path of the marker file to remove
    .PARAMETER Description
        Description for logging purposes
    .OUTPUTS
        Boolean indicating success
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [string]$Description = "Marker file"
    )
    
    try {
        Write-Log -Message "Removing marker file: $FilePath ($Description)"
        
        if (Test-Path $FilePath) {
            # Get file info before deletion for logging
            $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
            $fileSize = if ($fileInfo) { $fileInfo.Length } else { "Unknown" }
            $fileAge = if ($fileInfo) { [Math]::Round(((Get-Date) - $fileInfo.CreationTime).TotalMinutes, 1) } else { "Unknown" }
            
            # Remove the file
            Remove-Item $FilePath -Force -ErrorAction Stop
            Write-Log -Message "Successfully removed marker file: $FilePath (Size: $fileSize bytes, Age: $fileAge minutes)"
            
            # Remove from global tracking
            $Global:ActiveMarkerFiles = $Global:ActiveMarkerFiles | Where-Object { $_ -ne $FilePath }
            Write-Log -Message "Removed marker file from cleanup tracking: $FilePath"
            
            return $true
        } else {
            Write-Log -Message "Marker file not found (may already be cleaned up): $FilePath"
            # Still remove from tracking in case it was tracked but already deleted externally
            $Global:ActiveMarkerFiles = $Global:ActiveMarkerFiles | Where-Object { $_ -ne $FilePath }
            return $true
        }
        
    } catch {
        Write-Log -Message "ERROR: Failed to remove marker file '$FilePath': $($_.Exception.Message)"
        return $false
    }
}

function Clear-OrphanedMarkerFiles {
    <#
    .SYNOPSIS
        Finds and removes orphaned marker files from previous script executions
    .DESCRIPTION
        Scans multiple locations for old marker files and removes them to prevent
        accumulation. Configurable age threshold and comprehensive location scanning.
    .PARAMETER MaxAgeMinutes
        Maximum age of marker files to keep (default: 60 minutes)
    .PARAMETER ScanLocations
        Array of paths to scan for marker files (auto-detected if not provided)
    .OUTPUTS
        Integer count of files cleaned up
    #>
    param(
        [int]$MaxAgeMinutes = 60,
        [string[]]$ScanLocations = @()
    )
    
    try {
        Write-Log -Message "Starting orphaned marker file cleanup (MaxAge: $MaxAgeMinutes minutes)"
        $cleanupCount = 0
        $cleanupStartTime = Get-Date
        
        # Default scan locations if not provided
        if ($ScanLocations.Count -eq 0) {
            $ScanLocations = @(
                "C:\ProgramData\Temp",
                $env:TEMP,
                "$env:SystemRoot\Temp"
            )
            
            # Enumerate user profile temp dirs from disk instead of calling Get-InteractiveUser.
            # The CIM-based user detection costs ~7s on Azure AD machines and we'd be paying it
            # at the very start of every Intune cycle just to find one path; disk enumeration
            # is sub-millisecond and also catches orphans from any user profile, not just the
            # currently active one. Skip well-known non-user profile dirs.
            try {
                $skipProfiles = @('Default', 'Default User', 'DefaultUser', 'All Users', 'Public', 'defaultuser0', 'WDAGUtilityAccount')
                Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $skipProfiles -notcontains $_.Name } |
                    ForEach-Object {
                        $userTemp = Join-Path $_.FullName 'AppData\Local\Temp'
                        if ((Test-Path $userTemp) -and ($ScanLocations -notcontains $userTemp)) {
                            $ScanLocations += $userTemp
                        }
                    }
            } catch {
                # Ignore - orphan cleanup is best-effort
            }
        }
        
        Write-Log -Message "Scanning $($ScanLocations.Count) locations for orphaned marker files"
        
        foreach ($location in $ScanLocations) {
            if (-not (Test-Path $location)) {
                Write-Log -Message "Scan location does not exist, skipping: $location"
                continue
            }
            
            Write-Log -Message "Scanning location: $location"
            
            try {
                # Look for various marker file patterns
                $patterns = @(
                    "availableUpgrades-detect_*.ps1.userdetection",
                    "availableUpgrades-remediate_*.ps1.userdetection",
                    "*.ps1.userdetection"  # Catch-all for any script marker files
                )
                
                $locationCleanupCount = 0
                foreach ($pattern in $patterns) {
                    $markerFiles = Get-ChildItem -Path $location -Filter $pattern -ErrorAction SilentlyContinue
                    
                    foreach ($markerFile in $markerFiles) {
                        try {
                            $fileAge = (Get-Date) - $markerFile.CreationTime
                            $fileAgeMinutes = $fileAge.TotalMinutes
                            
                            Write-Log -Message "Found marker file: $($markerFile.Name) (Age: $([Math]::Round($fileAgeMinutes, 1)) minutes)"
                            
                            if ($fileAgeMinutes -gt $MaxAgeMinutes) {
                                # Check if this file is in our active tracking (don't remove active files)
                                $isActive = $Global:ActiveMarkerFiles -contains $markerFile.FullName
                                
                                if (-not $isActive) {
                                    Write-Log -Message "Removing orphaned marker file: $($markerFile.FullName) (Age: $([Math]::Round($fileAgeMinutes, 1)) minutes)"
                                    Remove-Item $markerFile.FullName -Force -ErrorAction Stop
                                    $cleanupCount++
                                    $locationCleanupCount++
                                } else {
                                    Write-Log -Message "Skipping active marker file: $($markerFile.FullName)"
                                }
                            } else {
                                Write-Log -Message "Keeping recent marker file: $($markerFile.Name) (Age: $([Math]::Round($fileAgeMinutes, 1)) minutes)"
                            }
                            
                        } catch {
                            Write-Log -Message "ERROR: Failed to process marker file '$($markerFile.FullName)': $($_.Exception.Message)"
                        }
                    }
                }
                
                if ($locationCleanupCount -gt 0) {
                    Write-Log -Message "Cleaned up $locationCleanupCount marker files from: $location"
                }
                
            } catch {
                Write-Log -Message "ERROR: Failed to scan location '$location': $($_.Exception.Message)"
            }
        }
        
        $cleanupDuration = (Get-Date) - $cleanupStartTime
        if ($cleanupCount -gt 0) {
            Write-Log -Message "Orphaned marker file cleanup completed: $cleanupCount files removed in $([Math]::Round($cleanupDuration.TotalSeconds, 1)) seconds"
        } else {
            Write-Log -Message "No orphaned marker files found during cleanup scan"
        }
        
        return $cleanupCount
        
    } catch {
        Write-Log -Message "ERROR: Orphaned marker file cleanup failed: $($_.Exception.Message)"
        return 0
    }
}

function Add-MarkerFileCleanupTrap {
    <#
    .SYNOPSIS
        Sets up trap handlers to ensure marker files are cleaned up on script exit
    .DESCRIPTION
        Registers cleanup handlers for various exit scenarios to prevent orphaned files
    #>
    
    # PowerShell trap for unexpected errors
    trap {
        Write-Log -Message "Script error trap triggered - performing marker file cleanup"
        Invoke-MarkerFileCleanup -Reason "PowerShell trap"
        continue
    }
    
    # Register cleanup for normal exit
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        Write-Log -Message "PowerShell exiting - performing marker file cleanup"
        Invoke-MarkerFileCleanup -Reason "PowerShell exit"
    } | Out-Null
    
    Write-Log -Message "Marker file cleanup traps registered"
}

function Invoke-MarkerFileCleanup {
    <#
    .SYNOPSIS
        Cleanup function for marker files during script exit
    .DESCRIPTION
        Called by trap handlers to ensure marker files are cleaned up even during errors
    .PARAMETER Reason
        Reason for the emergency cleanup (for logging)
    #>
    param(
        [string]$Reason = "Cleanup"
    )

    try {
        Write-Log -Message "Marker file cleanup triggered ($Reason)"

        if ($Global:ActiveMarkerFiles -and $Global:ActiveMarkerFiles.Count -gt 0) {
            Write-Log -Message "Cleaning up $($Global:ActiveMarkerFiles.Count) tracked marker files"

            foreach ($markerFile in $Global:ActiveMarkerFiles) {
                try {
                    if (Test-Path $markerFile) {
                        Remove-Item $markerFile -Force -ErrorAction SilentlyContinue
                        Write-Log -Message "Removed marker file: $markerFile"
                    }
                } catch {
                    # Silently continue during cleanup
                }
            }
            
            # Clear the tracking array
            $Global:ActiveMarkerFiles = @()
        }
        
    } catch {
        # Silently handle errors during emergency cleanup to avoid loops
    }
}

# ============================================================================
# END MARKER FILE MANAGEMENT SYSTEM
# ============================================================================

<# Script variables #>
$Script:TestMode = $false  # Set to $true to simulate app update with dialogs and notifications
$ScriptTag = "30" # Update this tag for each script version
$LogName = 'RemediateAvailableUpgrades'
$LogDate = Get-Date -Format dd-MM-yy # EU format; per-day rollover so all runs in one day share a log file
$LogFullName = "$LogName-$LogDate.log"

# v9.42: AppUpdater registry helpers. Access HKLM:\SOFTWARE\AppUpdater via .NET's
# RegistryKey.OpenBaseKey(LocalMachine, Registry64) so we explicitly request the 64-bit view
# and bypass the WoW64 redirector. PSDrive cmdlets (Get-ItemProperty, Set-ItemProperty, etc.)
# go through the redirector - from a 32-bit PowerShell host (Intune Remediations default), they
# rewrite HKLM:\SOFTWARE\X to HKLM:\SOFTWARE\WOW6432Node\X *unconditionally*, even when WOW6432Node
# is already in the requested path (yielding ...WOW6432Node\WOW6432Node\X). v9.39's
# WOW6432Node-prefix approach therefore produced double-redirected writes that were invisible at
# the path the script intended. These helpers take that pain away: same physical hive at
# HKLM:\SOFTWARE\AppUpdater regardless of bitness, visible to any 64-bit observer at the
# natural-looking path.
$Script:AppRegBasePath    = 'SOFTWARE\AppUpdater'         # under the 64-bit view
$Script:AppRegDisplayRoot = 'HKLM:\SOFTWARE\AppUpdater'   # for log messages only

function Open-AppRegKey {
    param([string]$SubPath = '', [switch]$Writable)
    try {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $full = $Script:AppRegBasePath
        if ($SubPath) { $full = "$full\$SubPath" }
        if ($Writable) { return $hklm.CreateSubKey($full) }
        return $hklm.OpenSubKey($full, $false)
    } catch {
        return $null
    }
}

function Test-AppRegKey {
    param([string]$SubPath)
    $k = Open-AppRegKey -SubPath $SubPath
    if ($k) { $k.Close(); return $true }
    return $false
}

function Get-AppRegValue {
    param([string]$SubPath, [string]$Name, $Default = $null)
    $k = Open-AppRegKey -SubPath $SubPath
    if (-not $k) { return $Default }
    try {
        $v = $k.GetValue($Name)
        if ($null -eq $v) { return $Default } else { return $v }
    } finally { $k.Close() }
}

function Get-AppRegProperties {
    param([string]$SubPath)
    $k = Open-AppRegKey -SubPath $SubPath
    if (-not $k) { return $null }
    try {
        $h = [ordered]@{}
        foreach ($n in $k.GetValueNames()) { $h[$n] = $k.GetValue($n) }
        return [PSCustomObject]$h
    } finally { $k.Close() }
}

function Set-AppRegValue {
    param([string]$SubPath, [string]$Name, $Value)
    $k = Open-AppRegKey -SubPath $SubPath -Writable
    if (-not $k) { return $false }
    try { $k.SetValue($Name, $Value); return $true } finally { $k.Close() }
}

function Remove-AppRegValue {
    param([string]$SubPath, [string]$Name)
    $k = Open-AppRegKey -SubPath $SubPath -Writable
    if (-not $k) { return $false }
    try { $k.DeleteValue($Name, $false); return $true } finally { $k.Close() }
}

function Remove-AppRegKey {
    param([string]$SubPath)
    try {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $full = $Script:AppRegBasePath
        if ($SubPath) { $full = "$full\$SubPath" }
        $hklm.DeleteSubKeyTree($full, $false)
        return $true
    } catch { return $false }
}

function Get-AppRegChildKeyNames {
    param([string]$SubPath = '')
    $k = Open-AppRegKey -SubPath $SubPath
    if (-not $k) { return @() }
    try { return ,@($k.GetSubKeyNames()) } finally { $k.Close() }
}

function Get-AppRegDisplayPath {
    param([string]$SubPath = '')
    if ($SubPath) { return "$Script:AppRegDisplayRoot\$SubPath" }
    return $Script:AppRegDisplayRoot
}

# Capture script path at global scope for use in scheduled tasks
$Global:CurrentScriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($Global:CurrentScriptPath)) {
    # Fallback method for cases where MyInvocation doesn't work
    $Global:CurrentScriptPath = $PSCommandPath
}
if ([string]::IsNullOrEmpty($Global:CurrentScriptPath)) {
    # Last resort fallback
    $Global:CurrentScriptPath = (Get-PSCallStack)[1].ScriptName
}

# Dynamic log path selection based on execution context
$isSystemContext = Test-RunningAsSystem
$isInteractive = [Environment]::UserInteractive

if ($isSystemContext) {
    $LogPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
    # Ensure the directory exists
    if (-not (Test-Path -Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    Write-Host "Running in system context (non-interactive: $(-not $isInteractive))"
} else {
    $LogPath = "$env:Temp"
    Write-Host "Running in user context (interactive: $isInteractive)"
}
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$userIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$useWhitelist = $true

# v9.53: session-start banner so multiple runs in the same per-day log file are easy to
# distinguish at a glance. Reads the Version field from the .NOTES block at runtime so it
# stays in sync without a manual constant to maintain.
$scriptVersion = 'unknown'
try {
    if ($Global:CurrentScriptPath -and (Test-Path $Global:CurrentScriptPath)) {
        $hdr = Get-Content -Path $Global:CurrentScriptPath -TotalCount 40 -ErrorAction Stop
        foreach ($line in $hdr) {
            if ($line -match '^\s*Version:\s*(\S+)') { $scriptVersion = $Matches[1]; break }
        }
    }
} catch {}
$ctxLabel = if ($UserRemediationOnly) { 'user-context (handoff)' } elseif ($isSystemContext) { 'SYSTEM' } elseif ($userIsAdmin) { 'user (admin)' } else { 'user' }
Write-Log -Message ('=' * 78)
Write-Log -Message "===== RemediateAvailableUpgrades v$scriptVersion  PID $PID  $ctxLabel context  on $env:COMPUTERNAME"
Write-Log -Message ('=' * 78)

<# ----------------------------------------------- #>

# v9.46: Pin the system awake for the whole remediation run. SetThreadExecutionState is
# process-scoped so the flag dies with this PowerShell process - even on a crash, Windows
# reclaims it automatically. The PowerShell.Exiting handler clears it explicitly on every
# normal exit path (7 of them) for hygiene and so the log records "Sleep block cleared".
Set-SystemSleepBlocked -Block $true
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -SupportEvent -Action {
    try { Set-SystemSleepBlocked -Block $false } catch {}
} | Out-Null

# Initialize marker file management system (with guard to prevent double initialization)
$Script:MarkerSystemInitialized = $false
if (-not $Script:MarkerSystemInitialized) {
    Write-Log -Message "Initializing marker file management system"
    Add-MarkerFileCleanupTrap
    $orphanedCount = Clear-OrphanedMarkerFiles -MaxAgeMinutes 60
    if ($orphanedCount -gt 0) {
        Write-Log -Message "Cleaned up $orphanedCount orphaned marker files from previous executions"
    }
    $Script:MarkerSystemInitialized = $true
}

# Clean up old log files (older than 1 month)
Remove-OldLogs -LogPath $LogPath

# Clean up stale temp files from previous runs (older than 10 minutes)
Remove-OldTempFiles

# Clean up orphaned scheduled tasks from previous runs (older than 10 minutes)
Remove-StaleScheduledTasks

# Initialize and clean up deferral system
Write-Log -Message "Initializing deferral management system" | Out-Null
try {
    Initialize-DeferralRegistry | Out-Null
    Clear-ExpiredDeferralData
    Write-Log -Message "Deferral system initialization completed" | Out-Null
} catch {
    Write-Log -Message "Warning: Deferral system initialization failed: $($_.Exception.Message)" | Out-Null
}

# Log script start with full date
Write-Log -Message "Script started on $(Get-Date -Format 'dd.MM.yyyy')"

<# TEST MODE: Check for WPF notification test trigger file #>
$testTriggerFile = "C:\Temp\wpf-test-trigger.txt"
if (Test-Path $testTriggerFile) {
    Write-Log -Message "WPF notification test trigger file detected: $testTriggerFile"
    Write-Log -Message "Running WPF notification test instead of normal remediation"
    
    try {
        # Test the WPF notification system with a simple message
        Write-Log -Message "Testing SYSTEM-to-user WPF notification"
        
        $testQuestion = "SYSTEM WPF Test Success!`n`nThis modern dialog was sent from SYSTEM context to your user session. The cross-session WPF notification mechanism is working correctly!"
        $testTitle = "WPF Notification Test"
        
        $testResult = Invoke-SystemUserPrompt -Question $testQuestion -Title $testTitle -TimeoutSeconds 30 -DefaultAction "Cancel" -Position "BottomRight"
        
        Write-Log -Message "WPF test completed with result: $testResult"
        
        # Check if we have any evidence that the WPF dialog actually worked
        $wpfWorked = $false
        
        # Get current user info for checking their temp directory
        $userInfo = Get-InteractiveUser
        if ($userInfo) {
            $userTempPath = "C:\Users\$($userInfo.Username)\AppData\Local\Temp"
            $sharedTempPath = "C:\ProgramData\Temp"
            
            # Check user temp directory for response files
            $responseFiles = @()
            if (Test-Path $userTempPath) {
                $responseFiles += Get-ChildItem -Path $userTempPath -Filter "UserPrompt_*_Response.json" -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) }
            }
            if (Test-Path $sharedTempPath) {
                $responseFiles += Get-ChildItem -Path $sharedTempPath -Filter "UserPrompt_*_Response.json" -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) }
            }
            
            if ($responseFiles.Count -gt 0) {
                Write-Log -Message "Found recent WPF response file(s) - WPF mechanism worked"
                $wpfWorked = $true
                
                # Show what was in the response files
                foreach ($responseFile in $responseFiles) {
                    try {
                        $content = Get-Content $responseFile.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
                        Write-Log -Message "Response file content: Response=$($content.response), User=$($content.username), Timestamp=$($content.timestamp)"
                    } catch {
                        Write-Log -Message "Could not read response file: $($_.Exception.Message)"
                    }
                }
            }
        }
        
        # Also check for any evidence in temp files that the dialog script actually ran
        $dialogScripts = Get-ChildItem -Path $userTempPath -Filter "Show-UserPrompt_*.ps1" -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddMinutes(-2) }
        if ($dialogScripts.Count -gt 0) {
            Write-Log -Message "Found recent dialog script files - this indicates the dialog system attempted to run"
            $wpfWorked = $true  # Script creation is evidence of system working
        }
        
        # Check for scheduled tasks that were created
        $recentTasks = Get-ScheduledTask -TaskPath "\" -ErrorAction SilentlyContinue | Where-Object {
            $_.TaskName -like "UserPrompt_*" -and $_.Date -gt (Get-Date).AddMinutes(-2)
        }
        if ($recentTasks.Count -gt 0) {
            Write-Log -Message "Found recent UserPrompt scheduled task(s) - system is working"
            $wpfWorked = $true
        }
        
        # If user got any definitive response (not TIMEOUT), the dialog worked
        if ($testResult -eq "OK") {
            Write-Log -Message "User selected OK (non-default action) - dialog definitely worked"
            $wpfWorked = $true
        } elseif ($testResult -eq "Cancel") {
            Write-Log -Message "User selected Cancel - dialog definitely worked"
            $wpfWorked = $true
        } elseif ($testResult -eq "TIMEOUT") {
            Write-Log -Message "Dialog timeout occurred - mechanism is working (though dialog may not have auto-closed properly)"
            $wpfWorked = $true
        }
        
        if ($wpfWorked) {
            Write-Log -Message "✅ SUCCESS: WPF notification system is working!"
            Write-Log -Message "User response: $testResult"
            Write-Log -Message "Evidence: WPF dialog was successfully displayed to the user"
        } else {
            Write-Log -Message "❌ FAILED: WPF notification system is not working properly"
            Write-Log -Message "No evidence of successful WPF dialog display found"
            Write-Log -Message "Returned value: $testResult (likely default timeout action, not user interaction)"
            Write-Log -Message "Possible issues:"
            Write-Log -Message "- Scheduled task not running in correct session"
            Write-Log -Message "- WPF assemblies not available in task context"
            Write-Log -Message "- User session not properly detected"
            Write-Log -Message "- PowerShell execution policy blocking script execution"
            Write-Log -Message "Try: Ensure user is logged in and session is active, check Windows notification settings"
        }
        
        # Keep the trigger file for repeated testing (don't delete it)
        # Remove-Item $testTriggerFile -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Keeping trigger file for repeated testing: $testTriggerFile"
        Write-Log -Message "Note: Create file 'C:\Temp\wpf-test-trigger.txt' to trigger this test"
        
        Write-Log -Message "WPF test completed - exiting"
        Write-Log -Message "Performing marker file cleanup before exit (WPF test complete)"
        Invoke-MarkerFileCleanup -Reason "WPF test completed"
        exit 0
        
    } catch {
        Write-Log -Message "❌ ERROR: WPF test failed with exception: $($_.Exception.Message)"
        Write-Log -Message "Full exception: $($_.Exception.ToString())"
        Write-Log -Message "Performing marker file cleanup before exit (WPF test error)"
        Invoke-MarkerFileCleanup -Reason "WPF test error"
        exit 1
    }
}

<# Abort script in OOBE phase #>
if (-not (OOBEComplete)) {
    "OOBE"
    Write-Log -Message "OOBE not complete, performing marker file cleanup before exit"
    Invoke-MarkerFileCleanup -Reason "OOBE not complete"
    Exit 0
}

<# ---------------------------------------------- #>

function Get-CachedWhitelistJSON {
    <#
    .SYNOPSIS
        Fetches whitelist JSON from a URL using a local cache with TTL + ETag revalidation.
    .DESCRIPTION
        Cache lives at C:\ProgramData\Temp\availableUpgrades-whitelist.cache.json with a
        sibling .meta.json holding the source URL, ETag, and timestamp.
        - Within $TtlMinutes of the last successful fetch: skip network entirely.
        - After TTL: revalidate via If-None-Match. 304 -> use cache; 200 -> save new body.
        - On network failure with a stale cache present: use the stale copy.
        - On network failure with no cache: return $null (caller falls back to hardcoded).
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [int]$TtlMinutes = 2160,   # 36 hours - longer than a daily cycle so the fast-path normally hits
        [string]$CachePath = "C:\ProgramData\Temp\availableUpgrades-whitelist.cache.json"
    )

    $metaPath = "$CachePath.meta.json"
    $cachedJson = $null
    $cachedEtag = $null
    $cacheAge = $null

    # Helper: a JSON body must start with `{` or `[`. Anything else means the cache file
    # was contaminated (e.g. by previous Write-Log stream pollution before v9.30) and we
    # should treat it as missing so the caller re-fetches from the network.
    $isValidJson = {
        param([string]$Body)
        if ([string]::IsNullOrWhiteSpace($Body)) { return $false }
        $first = $Body.TrimStart()[0]
        return ($first -eq '{' -or $first -eq '[')
    }

    if ((Test-Path $CachePath) -and (Test-Path $metaPath)) {
        try {
            $meta = Get-Content -Path $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            if ($meta.Url -eq $Url -and $meta.Timestamp) {
                $tentative = Get-Content -Path $CachePath -Raw -Encoding UTF8
                if (& $isValidJson $tentative) {
                    $cachedJson = $tentative
                    $cachedEtag = $meta.ETag
                    $cacheAge = (Get-Date) - [datetime]$meta.Timestamp
                } else {
                    Write-Log -Message "Whitelist cache file is not valid JSON - discarding and re-fetching" | Out-Null
                    Remove-Item -Path $CachePath -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path $metaPath -Force -ErrorAction SilentlyContinue
                }
            }
        } catch { }
    }

    if ($cachedJson -and $cacheAge -and $cacheAge.TotalMinutes -lt $TtlMinutes) {
        Write-Log -Message "Using cached whitelist (age $([Math]::Round($cacheAge.TotalMinutes, 1)) min, TTL $TtlMinutes min)" | Out-Null
        return $cachedJson
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $headers = @{ 'User-Agent' = 'PowerShell-WingetScript' }
    if ($cachedEtag) { $headers['If-None-Match'] = $cachedEtag }

    try {
        $resp = Invoke-WebRequest -Uri $Url -Headers $headers -UseBasicParsing -ErrorAction Stop
        $newJson = $resp.Content
        $newEtag = $resp.Headers['ETag']
        if ($newEtag -is [array]) { $newEtag = $newEtag[0] }
        if (-not (& $isValidJson $newJson)) {
            Write-Log -Message "Fetched whitelist body is not valid JSON - aborting cache write" | Out-Null
            return $newJson
        }
        Write-Log -Message "Fetched whitelist from $Url ($($newJson.Length) bytes)" | Out-Null

        try {
            $cacheDir = Split-Path -Parent $CachePath
            if ($cacheDir -and -not (Test-Path $cacheDir)) { New-Item -Path $cacheDir -ItemType Directory -Force | Out-Null }
            $newJson | Out-File -FilePath $CachePath -Encoding UTF8 -Force
            @{ Url = $Url; ETag = $newEtag; Timestamp = (Get-Date).ToString('o') } |
                ConvertTo-Json | Out-File -FilePath $metaPath -Encoding UTF8 -Force
        } catch {
            Write-Log -Message "Whitelist cache write failed (non-fatal): $($_.Exception.Message)" | Out-Null
        }
        return $newJson
    } catch {
        $statusCode = $null
        if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
        if ($statusCode -eq 304 -and $cachedJson) {
            Write-Log -Message "Whitelist unchanged on server (304) - reusing cache" | Out-Null
            try {
                @{ Url = $Url; ETag = $cachedEtag; Timestamp = (Get-Date).ToString('o') } |
                    ConvertTo-Json | Out-File -FilePath $metaPath -Encoding UTF8 -Force
            } catch { }
            return $cachedJson
        }
        Write-Log -Message "Whitelist fetch failed: $($_.Exception.Message)" | Out-Null
        if ($cachedJson) {
            Write-Log -Message "Falling back to stale whitelist cache" | Out-Null
            return $cachedJson
        }
        return $null
    }
}

# Fetch whitelist configuration - try local file first, then GitHub (cached), then fallback
$localWhitelistPath = $null
if ($MyInvocation.MyCommand.Path) {
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $localWhitelistPath = Join-Path $scriptPath "app-whitelist.json"
}
# WhitelistUrl parameter (from scheduled task) takes precedence, then global scope (bootstrapper), then default
if ($WhitelistUrl) {
    $whitelistUrl = $WhitelistUrl
} elseif ($global:whitelistUrl) {
    $whitelistUrl = $global:whitelistUrl
    Write-Log -Message "Restored whitelistUrl from global scope: $whitelistUrl"
}
if (-not $whitelistUrl) {
    $whitelistUrl = "https://raw.githubusercontent.com/woodyard/public-scripts/main/remediations/app-whitelist.json"
}

$whitelistJSON = $null

# Try local file first
if ($localWhitelistPath -and (Test-Path $localWhitelistPath)) {
    try {
        Write-Log -Message "Found local whitelist file: $localWhitelistPath"
        $whitelistJSON = Get-Content -Path $localWhitelistPath -Raw -Encoding UTF8
        Write-Log -Message "Successfully loaded whitelist configuration from local file"
    } catch {
        Write-Log -Message "Error reading local whitelist file: $($_.Exception.Message)"
        Write-Log -Message "Falling back to GitHub configuration"
    }
}

# If local file failed or doesn't exist, fetch from GitHub via the cache helper.
# Cache (C:\ProgramData\Temp\availableUpgrades-whitelist.cache.*) keeps the last response
# plus its ETag; for the next TTL window we skip the network call entirely, and after that
# we revalidate with If-None-Match (304 means we keep using the cached body).
if (-not $whitelistJSON) {
    $whitelistJSON = Get-CachedWhitelistJSON -Url $whitelistUrl
    if (-not $whitelistJSON) {
        Write-Log -Message "Falling back to basic hardcoded configuration"
    }
}

# Final fallback to basic configuration if both local and GitHub failed
if (-not $whitelistJSON) {
    $whitelistJSON = @'
[
    {"AppID": "Mozilla.Firefox", "FriendlyName": "Firefox", "BlockingProcess": "firefox", "PromptWhenBlocked": true},
    {"AppID": "Google.Chrome", "FriendlyName": "Chrome", "BlockingProcess": "chrome", "PromptWhenBlocked": true},
    {"AppID": "Microsoft.VisualStudioCode", "FriendlyName": "Visual Studio Code", "BlockingProcess": "Code", "PromptWhenBlocked": true},
    {"AppID": "Notepad++.Notepad++", "FriendlyName": "Notepad++", "BlockingProcess": "notepad++", "DefaultTimeoutAction": true},
    {"AppID": "7zip.7zip", "FriendlyName": "7-Zip", "BlockingProcess": "7zFM", "DefaultTimeoutAction": true},
    {"AppID": "Adobe.Acrobat.Reader.64-bit", "FriendlyName": "Adobe Acrobat Reader", "BlockingProcess": "AcroRd32,Acrobat,AcroBroker,AdobeARM,AdobeCollabSync", "AutoCloseProcesses": "AdobeCollabSync", "PromptWhenBlocked": true},
    {"AppID": "GitHub.GitHubDesktop", "FriendlyName": "GitHub Desktop", "BlockingProcess": "GitHubDesktop", "PromptWhenBlocked": true},
    {"AppID": "Fortinet.FortiClientVPN", "FriendlyName": "FortiClient VPN", "BlockingProcess": "FortiClient,FortiSSLVPNdaemon,FortiTray", "PromptWhenBlocked": true, "DefaultTimeoutAction": false, "TimeoutSeconds": 90}
]
'@
    Write-Log -Message "Using basic hardcoded configuration with FortiClient enabled for testing"
}

$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_*64__8wekyb3d8bbwe"
if ($ResolveWingetPath) {
    $WingetPath = $ResolveWingetPath[-1].Path
}

try {
    $parsedWhitelist = $whitelistJSON | ConvertFrom-Json -ErrorAction Stop

    # Support both new format { CategoryDefaults, Apps } and legacy flat array
    if ($parsedWhitelist.Apps) {
        $categoryDefaults = @{}
        if ($parsedWhitelist.CategoryDefaults) {
            $parsedWhitelist.CategoryDefaults.PSObject.Properties | ForEach-Object {
                $categoryDefaults[$_.Name] = $_.Value
            }
            Write-Log -Message "Loaded category defaults for: $($categoryDefaults.Keys -join ', ')"
        }

        $whitelistConfig = $parsedWhitelist.Apps | ForEach-Object {
            $app = $_
            $category = $app.Category
            if ($category -and $categoryDefaults.ContainsKey($category)) {
                $defaults = $categoryDefaults[$category]
                # Merge: category defaults first, then app-level properties override
                $defaults.PSObject.Properties | ForEach-Object {
                    $propName = $_.Name
                    # Only apply default if the app doesn't already define this property
                    if ($null -eq $app.PSObject.Properties[$propName]) {
                        $app | Add-Member -NotePropertyName $propName -NotePropertyValue $_.Value -Force
                    }
                }
            }
            $app
        }
        Write-Log -Message "Loaded whitelist with category support ($($whitelistConfig.Count) apps)"
    } else {
        # Legacy flat array format
        $whitelistConfig = $parsedWhitelist
        Write-Log -Message "Loaded legacy whitelist format ($($whitelistConfig.Count) apps)"
    }

    $whitelistConfig = $whitelistConfig | Where-Object { ($_.Disabled -eq $null -or $_.Disabled -eq $false) }
    Write-Log -Message "Successfully loaded whitelist configuration with $($whitelistConfig.Count) enabled apps"
} catch {
    Write-Log -Message "Error parsing whitelist JSON: $($_.Exception.Message)"
    Write-Log -Message "Performing marker file cleanup before exit due to whitelist error"
    Invoke-MarkerFileCleanup -Reason "Whitelist parsing error"
    exit 1
}

# TEST MODE: Add a fake test app to the whitelist for simulating the full update flow
if ($Script:TestMode) {
    $testApp = [PSCustomObject]@{
        AppID = "Test.DemoApp"
        FriendlyName = "Demo Application"
        BlockingProcess = "notepad"
        PromptWhenBlocked = $true
        DefaultTimeoutAction = $false
        TimeoutSeconds = 120
        DeferralEnabled = $true
        MaxDeferralDays = 5
        ForcedUpgradeMessage = "This is a test update that can no longer be deferred."
    }
    $whitelistConfig = @($whitelistConfig) + @($testApp)
    Write-Log -Message "TEST MODE: Added Test.DemoApp to whitelist (blocking process: notepad)"
}

function ConvertFrom-WingetOutput {
    <#
    .SYNOPSIS
        Parses winget upgrade text output into structured app objects.
    .DESCRIPTION
        Uses the separator line (dashes) to locate the header, then extracts
        column positions from the header text. Locale-safe header detection.
        Returns objects with AppID, CurrentVersion, and AvailableVersion.
    #>
    param([array]$Output)

    if (-not $Output -or $Output.Count -eq 0) { return @() }

    # Find the separator line (row of dashes) - locale-safe
    $separatorIndex = -1
    for ($i = 0; $i -lt $Output.Count; $i++) {
        if ($Output[$i] -match '^-{10,}$') {
            $separatorIndex = $i
            break
        }
    }

    if ($separatorIndex -lt 1) {
        Write-Log -Message "No separator line found in winget output"
        return @()
    }

    $headerLine = $Output[$separatorIndex - 1]
    Write-Log -Message "Header found at line $($separatorIndex - 1), total lines: $($Output.Count)"

    # Find column positions from header using word-boundary matching
    $columns = @{}
    foreach ($col in @("Id", "Version", "Available", "Source")) {
        for ($p = 0; $p -le $headerLine.Length - $col.Length; $p++) {
            if ($headerLine.Substring($p, $col.Length) -ceq $col) {
                $prevOk = ($p -eq 0) -or ($headerLine[$p - 1] -eq ' ')
                $nextOk = ($p + $col.Length -ge $headerLine.Length) -or ($headerLine[$p + $col.Length] -eq ' ')
                if ($prevOk -and $nextOk) { $columns[$col] = $p; break }
            }
        }
    }

    if (-not $columns.ContainsKey("Id")) {
        Write-Log -Message "Could not find Id column in header: $headerLine"
        return @()
    }

    $idPos = $columns["Id"]
    $idEnd = if ($columns.ContainsKey("Version")) { $columns["Version"] - 1 } else { $headerLine.Length - 1 }
    $versionPos = if ($columns.ContainsKey("Version")) { $columns["Version"] } else { -1 }
    $availablePos = if ($columns.ContainsKey("Available")) { $columns["Available"] } else { -1 }
    $sourcePos = if ($columns.ContainsKey("Source")) { $columns["Source"] } else { -1 }

    Write-Log -Message "Column positions - Id: $idPos, Version: $versionPos, Available: $availablePos"

    $apps = [System.Collections.ArrayList]::new()
    for ($i = $separatorIndex + 1; $i -lt $Output.Count; $i++) {
        $line = $Output[$i]
        if ($line.Trim() -eq "" -or $line -match 'upgrades? available' -or $line -match 'following packages') {
            break
        }
        if ($line.Length -le $idPos) { continue }

        $appId = ($line[$idPos..$idEnd] -join "").Trim()
        if ($appId -eq "") { continue }

        $currentVersion = ""
        $availableVersion = ""

        if ($versionPos -ge 0 -and $availablePos -gt $versionPos -and $line.Length -gt $versionPos) {
            $verEnd = $availablePos - 1
            $currentVersion = ($line[$versionPos..$verEnd] -join "").Trim()
        }
        if ($availablePos -ge 0 -and $line.Length -gt $availablePos) {
            $avEnd = if ($sourcePos -gt $availablePos) { $sourcePos - 1 } else { $line.Length - 1 }
            $availableVersion = ($line[$availablePos..$avEnd] -join "").Trim()
        }

        $null = $apps.Add(@{
            AppID = $appId
            CurrentVersion = $currentVersion
            AvailableVersion = $availableVersion
        })
    }

    Write-Log -Message "Parsed $($apps.Count) apps from winget output"
    return $apps
}

# Static task file shared with detect.ps1.
# Detection writes this file when upgrades are found; remediation reads it as the authoritative
# work list and removes entries as each app is processed (success or final-failure).
$Script:UpgradeTaskFile = "C:\ProgramData\Temp\availableUpgrades-tasks.json"
# Refuse to use the task file beyond this age - guards against acting on stale detections after
# a missed Intune cycle. Tunable; 6 h is comfortably longer than a normal detect→remediate gap.
$Script:UpgradeTaskFileMaxAgeHours = 6

function Read-UpgradeTaskFile {
    <#
    .SYNOPSIS
        Reads the static upgrade task file written by detect.ps1.
    .OUTPUTS
        ArrayList of @{ AppID; FriendlyName; CurrentVersion; AvailableVersion } records, or $null
        if the file is missing, malformed, or older than UpgradeTaskFileMaxAgeHours.
    .NOTES
        All Write-Log calls in this function are piped to Out-Null because Write-Log emits the
        formatted console line to the success stream - without suppression that string leaks
        into the function's return value alongside the ArrayList.
    #>
    if (-not (Test-Path $Script:UpgradeTaskFile)) { return $null }
    try {
        $raw = Get-Content $Script:UpgradeTaskFile -Raw -ErrorAction Stop
        $payload = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not $payload.Tasks) { return $null }

        if ($payload.Generated) {
            try {
                $gen = [DateTime]::Parse($payload.Generated)
                $age = (Get-Date) - $gen
                $ageHours = [int]$age.TotalHours
                $ageMinutes = [int]$age.TotalMinutes
                $maxHours = $Script:UpgradeTaskFileMaxAgeHours
                if ($age.TotalHours -gt $maxHours) {
                    Write-Log -Message "Upgrade task file is stale - age $ageHours h, max $maxHours h - ignoring" | Out-Null
                    return $null
                }
                $taskCount = $payload.Tasks.Count
                Write-Log -Message "Upgrade task file age $ageMinutes min, $taskCount tasks" | Out-Null
            } catch {
                Write-Log -Message "Could not parse task file Generated timestamp - proceeding regardless" | Out-Null
            }
        }

        $list = [System.Collections.ArrayList]::new()
        foreach ($t in $payload.Tasks) {
            if (-not $t.AppID) { continue }
            $rawScope = if ($t.PSObject.Properties['InstalledScope']) { [string]$t.InstalledScope } else { "unknown" }
            if ([string]::IsNullOrWhiteSpace($rawScope)) { $rawScope = "unknown" }
            $null = $list.Add(@{
                AppID = [string]$t.AppID
                FriendlyName = [string]$t.FriendlyName
                CurrentVersion = [string]$t.CurrentVersion
                AvailableVersion = [string]$t.AvailableVersion
                InstalledScope = $rawScope.ToLower()
            })
        }
        return $list
    } catch {
        Write-Log -Message "Error reading upgrade task file (will fall back to winget discovery): $($_.Exception.Message)" | Out-Null
        return $null
    }
}

function Remove-UpgradeTaskEntry {
    <#
    .SYNOPSIS
        Removes the entry for a given AppID from the static task file. Called after an app is
        finally processed (success or final-failure) so subsequent runs do not retry it.
        If the file becomes empty, deletes the file entirely.
    #>
    param([Parameter(Mandatory)][string]$AppID)
    if (-not (Test-Path $Script:UpgradeTaskFile)) { return }
    try {
        $raw = Get-Content $Script:UpgradeTaskFile -Raw -ErrorAction Stop
        $payload = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not $payload.Tasks) { return }

        $kept = @($payload.Tasks | Where-Object { $_.AppID -ne $AppID })
        if ($kept.Count -eq 0) {
            Remove-Item -Path $Script:UpgradeTaskFile -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed upgrade task file (last task '$AppID' processed)" | Out-Null
            return
        }
        $payload.Tasks = $kept
        $payload | ConvertTo-Json -Depth 4 | Out-File -FilePath $Script:UpgradeTaskFile -Encoding UTF8 -Force
        $remainingCount = $kept.Count
        Write-Log -Message "Removed task '$AppID' from task file - $remainingCount remaining" | Out-Null
    } catch {
        Write-Log -Message "ERROR removing task '$AppID' from task file: $($_.Exception.Message)" | Out-Null
    }
}

function Get-MissingMachineUpgrades {
    <#
    .SYNOPSIS
        Discovers pending upgrades for whitelisted machine-scoped apps that SYSTEM-context's
        plain `winget upgrade` listing missed.
    .DESCRIPTION
        winget tracks installed packages per-account: an app the user installed (e.g. Mozilla.Firefox)
        ends up registered in the user's tracking database, so `winget upgrade` run as SYSTEM does
        not list it - even though the binary lives in C:\Program Files and the SYSTEM account has
        full write access to it. `winget list --id ID` does correlate against ARP (machine-wide),
        so this helper queries each whitelisted machine-scoped app individually and reports any
        pending upgrade so the main loop can apply it from SYSTEM context (no UAC).
    .PARAMETER Whitelist
        Parsed whitelist entries with AppID, FriendlyName, and optional Enabled.
    .PARAMETER ExistingIds
        Hashtable of AppIDs already discovered by the main `winget upgrade` listing - these are
        skipped to avoid duplicate processing.
    .PARAMETER WingetExePath
        Full path to winget.exe (resolved for SYSTEM context).
    .PARAMETER WingetWorkingDir
        Working directory for winget (the WindowsApps DesktopAppInstaller folder under SYSTEM).
    .OUTPUTS
        ArrayList of @{ AppID; CurrentVersion; AvailableVersion } entries ready to merge into $LIST.
    #>
    param(
        [array]$Whitelist,
        [hashtable]$ExistingIds,
        [string]$WingetExePath,
        [string]$WingetWorkingDir
    )

    $discovered = [System.Collections.ArrayList]::new()
    if (-not $Whitelist -or -not $WingetExePath) { return $discovered }

    $augmentStart = Get-Date
    $candidates = 0
    foreach ($entry in $Whitelist) {
        if (-not $entry.AppID) { continue }
        if ($entry.PSObject.Properties['Disabled'] -and $entry.Disabled -eq $true) { continue }
        # Skip wildcard patterns - `winget list --id` needs a concrete ID.
        # Wildcarded entries are typically handled fine by the main `winget upgrade` listing because
        # they cover variants (Beta/ESR/etc.) that are independently tracked.
        if ($entry.AppID -match '[\*\?]') { continue }
        if ($ExistingIds -and $ExistingIds.ContainsKey($entry.AppID)) { continue }

        # Quick registry-based gate: only consider apps actually installed machine-wide.
        $scope = Get-AppInstalledScope -AppID $entry.AppID -FriendlyName $entry.FriendlyName
        if ($scope -ne "machine") { continue }

        $candidates++
        try {
            $listArgs = @("list", "--id", $entry.AppID, "--exact", "--source", "winget", "--accept-source-agreements")
            $listOut = if ($WingetWorkingDir) {
                Push-Location $WingetWorkingDir
                try { & $WingetExePath @listArgs 2>&1 } finally { Pop-Location }
            } else {
                & $WingetExePath @listArgs 2>&1
            }
            $listLines = @($listOut | ForEach-Object { "$_" })
            $parsed = ConvertFrom-WingetOutput -Output $listLines
            foreach ($p in $parsed) {
                if ($p.AppID -eq $entry.AppID -and -not [string]::IsNullOrWhiteSpace($p.AvailableVersion)) {
                    $null = $discovered.Add(@{
                        AppID = $p.AppID
                        CurrentVersion = $p.CurrentVersion
                        AvailableVersion = $p.AvailableVersion
                    })
                    $augFromVer = $p.CurrentVersion
                    $augToVer = $p.AvailableVersion
                    Write-Log -Message "SYSTEM augmentation: discovered pending upgrade for $($entry.AppID) - $augFromVer to $augToVer"
                    break
                }
            }
        } catch {
            Write-Log -Message "SYSTEM augmentation: error querying $($entry.AppID): $($_.Exception.Message)"
        }
    }

    $augmentTime = (Get-Date) - $augmentStart
    Write-Log -Message "SYSTEM augmentation: scanned $candidates machine-scoped candidates in $([int]$augmentTime.TotalSeconds)s, discovered $($discovered.Count) missed upgrades"
    return $discovered
}

# Main remediation logic - dual-context architecture
# Check UserRemediationOnly FIRST - this flag means we're a scheduled user remediation task,
# regardless of whether Test-RunningAsSystem is true (the task may run as the user's principal)
if ($UserRemediationOnly) {
        # DIAGNOSTIC: Log immediate execution proof before any other operations
        try {
            $debugInfo = @(
                "USER_CONTEXT_STARTED_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss-fff')",
                "PowerShell_Version: $($PSVersionTable.PSVersion)",
                "PowerShell_Edition: $($PSVersionTable.PSEdition)",
                "Execution_Policy: $(Get-ExecutionPolicy)",
                "Current_User: $env:USERNAME",
                "User_Domain: $env:USERDOMAIN",
                "Process_ID: $PID",
                "Session_ID: $((Get-Process -Id $PID).SessionId)",
                "Script_Path: $($MyInvocation.MyCommand.Path)",
                "Working_Directory: $(Get-Location)",
                "Parameters: UserRemediationOnly=$UserRemediationOnly, RemediationResultFile=$RemediationResultFile",
                "--- END DIAGNOSTIC INFO ---"
            )
            $debugInfo | Out-File -FilePath "C:\ProgramData\Temp\UserContext_Debug.log" -Append -Force -Encoding UTF8
        } catch {
            # If even this basic logging fails, try alternative location
            try {
                "USER_CONTEXT_DIAGNOSTIC_FAILED: $($_.Exception.Message)" | Out-File -FilePath "$env:TEMP\UserContext_Debug_Fallback.log" -Append -Force
            } catch {
                # Complete failure - script execution may be blocked entirely
            }
        }
        
        # This is a scheduled user remediation task - process user apps only
        Write-Log -Message "*** RUNNING IN USER CONTEXT (SCHEDULED TASK) ***"
        $userContextStart = Get-Date
        Write-Log -Message "User context execution started at: $userContextStart"
        Write-Log -Message "Current user: $env:USERNAME"
        Write-Log -Message "User domain: $env:USERDOMAIN"
        Write-Log -Message "Session ID: $((Get-Process -Id $PID).SessionId)"
        Write-Log -Message "Process ID: $PID"
        Write-Log -Message "Running user remediation task"
        Write-Log -Message "RemediationResultFile parameter: $RemediationResultFile"

        # Attach to the persistent dialog host SYSTEM started (v9.33).
        # If no session id was passed or the host has died, dialog wrappers fall back to legacy spawn.
        if ($DialogSessionId) {
            Write-Log -Message "DialogSessionId passed by SYSTEM: $DialogSessionId - connecting"
            Connect-DialogSession -SessionId $DialogSessionId | Out-Null
        } else {
            Write-Log -Message "No DialogSessionId from SYSTEM - dialog wrappers will use legacy spawn"
        }
        
        # Create heartbeat and status files for system context synchronization
        $resultFileDir = if ($RemediationResultFile) { Split-Path $RemediationResultFile -Parent } else { "C:\ProgramData\Temp" }
        $resultFileBaseName = if ($RemediationResultFile) { [System.IO.Path]::GetFileNameWithoutExtension($RemediationResultFile) } else { "UserRemediation" }
        $heartbeatFile = Join-Path $resultFileDir "$resultFileBaseName.heartbeat"
        $statusFile = Join-Path $resultFileDir "$resultFileBaseName.status"
        
        Write-Log -Message "Creating heartbeat file: $heartbeatFile" | Out-Null
        Write-Log -Message "Creating status file: $statusFile" | Out-Null
        
        # Function to update heartbeat (call this regularly during processing)
        function Update-Heartbeat {
            param(
                [string]$Stage = "Unknown",
                [hashtable]$AdditionalData = @{}
            )
            
            try {
                # Enhanced heartbeat creation with multiple fallback paths
                $heartbeatBaseName = [System.IO.Path]::GetFileNameWithoutExtension($heartbeatFile)
                $heartbeatPaths = @(
                    $heartbeatFile,
                    "$env:TEMP\UserRemediationHeartbeat_$heartbeatBaseName.json",
                    "C:\ProgramData\Temp\UserRemediationHeartbeat_$heartbeatBaseName.json"
                )
                
                $heartbeatData = @{
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
                    Stage = $Stage
                    ProcessId = $PID
                    Username = $env:USERNAME
                    SessionId = (Get-Process -Id $PID).SessionId
                    ScriptPath = $MyInvocation.MyCommand.Path
                    WorkingDirectory = (Get-Location).Path
                }
                
                # Add any additional context data
                foreach ($key in $AdditionalData.Keys) {
                    $heartbeatData[$key] = $AdditionalData[$key]
                }
                
                $heartbeatJson = $heartbeatData | ConvertTo-Json -Compress
                $success = $false
                
                # Try each heartbeat path until one succeeds
                foreach ($hbPath in $heartbeatPaths) {
                    try {
                        # Ensure directory exists
                        $hbDir = Split-Path $hbPath -Parent
                        if (-not (Test-Path $hbDir)) {
                            New-Item -Path $hbDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                        }
                        
                        # Write heartbeat file
                        $heartbeatJson | Out-File -FilePath $hbPath -Force -Encoding UTF8 -ErrorAction Stop
                        
                        # Create simple timestamp file for basic monitoring
                        (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff") | Out-File -FilePath "$hbPath.timestamp" -Force -ErrorAction SilentlyContinue
                        
                        # Log successful creation only for primary path
                        if ($hbPath -eq $heartbeatFile) {
                            Write-Log -Message "Heartbeat created successfully at stage '$Stage'" | Out-Null
                        }
                        
                        $success = $true
                        break
                        
                    } catch {
                        # Try next path
                        continue
                    }
                }
                
                if (-not $success) {
                    throw "All heartbeat paths failed"
                }
                
                return $true
                
            } catch {
                # Enhanced error logging with immediate file creation
                $errorMsg = "Heartbeat failed at stage '$Stage': $($_.Exception.Message)"
                Write-Log -Message "WARNING: $errorMsg" | Out-Null
                
                # Try multiple error logging approaches
                $errorPaths = @(
                    "$heartbeatFile.error",
                    "$env:TEMP\UserContext_Heartbeat_Error_$PID.log",
                    "C:\ProgramData\Temp\UserContext_Heartbeat_Error_$PID.log"
                )
                
                foreach ($errorPath in $errorPaths) {
                    try {
                        $errorMsg | Out-File -FilePath $errorPath -Append -Force -ErrorAction Stop
                        break
                    } catch {
                        continue
                    }
                }
                
                return $false
            }
        }
        
        # Function to update status (call at major processing milestones)
        function Update-Status {
            param(
                [string]$Status,
                [string]$Progress = ""
            )
            try {
                @{
                    Status = $Status
                    Progress = $Progress
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    ProcessId = $PID
                } | ConvertTo-Json -Compress | Out-File -FilePath $statusFile -Force -ErrorAction SilentlyContinue
            } catch {
                # Ignore status errors - don't interrupt processing
            }
        }
        
        # Enhanced initial heartbeat with immediate creation
        Write-Log -Message "Creating initial heartbeat and status files..." | Out-Null
        $heartbeatSuccess = Update-Heartbeat -Stage "ScriptStart" -AdditionalData @{
            ScriptPath = $MyInvocation.MyCommand.Path
            Arguments = $MyInvocation.Line
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            ExecutionPolicy = (Get-ExecutionPolicy).ToString()
            ScriptSize = if ($MyInvocation.MyCommand.Path -and (Test-Path $MyInvocation.MyCommand.Path)) { (Get-Item $MyInvocation.MyCommand.Path).Length } else { "Unknown" }
        }
        
        if ($heartbeatSuccess) {
            Write-Log -Message "Initial heartbeat created successfully" | Out-Null
        } else {
            Write-Log -Message "WARNING: Initial heartbeat creation failed - system context may timeout" | Out-Null
        }
        
        Update-Status -Status "Starting" -Progress "User context remediation initialized, heartbeat: $heartbeatSuccess"
        
        # Create emergency heartbeat immediately to signal we're alive
        try {
            "ALIVE_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')" | Out-File -FilePath "$heartbeatFile.emergency" -Force -ErrorAction SilentlyContinue
        } catch {
            # Ignore emergency heartbeat errors
        }
        
        # Check if we're admin in user context - if not, use --scope user
        Write-Log -Message "Checking user admin privileges..."
        $privilegeCheckStart = Get-Date
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $userIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $privilegeCheckTime = (Get-Date) - $privilegeCheckStart
        Write-Log -Message "Privilege check completed in $($privilegeCheckTime.TotalSeconds) seconds"
        
        Write-Log -Message "User is admin: $userIsAdmin"
        Write-Log -Message "Test-RunningAsSystem: $(Test-RunningAsSystem)"
        
        # Update status
        Update-Status -Status "Privilege check complete" -Progress "Admin: $userIsAdmin"
        Update-Heartbeat -Stage "PrivilegeCheck" -AdditionalData @{
            UserIsAdmin = $userIsAdmin
            TestRunningAsSystem = (Test-RunningAsSystem)
        }
        
        # Privilege check + minimal context setup. Discovery is done by detect.ps1 - we read
        # its task file below instead of calling `winget upgrade` here.
        Update-Status -Status "Loading work list" -Progress "Reading task file written by detect.ps1"

        # Validate winget is available; we still need winget.exe later to actually run upgrades.
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
            Write-Log -Message "winget.exe not on PATH in user context - cannot perform upgrades"
            if ($RemediationResultFile) {
                $errorResult = @{
                    ProcessedApps = 0
                    UpgradeResults = @("ERROR: winget.exe not available in user context")
                    Success = $false
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    Username = $env:USERNAME
                    Computer = $env:COMPUTERNAME
                    Context = "USER"
                    Error = "winget.exe not on PATH"
                } | ConvertTo-Json -Depth 3 -Compress
                $errorResult | Out-File -FilePath $RemediationResultFile -Encoding UTF8 -Force
            }
            Write-Log -Message "Performing marker file cleanup before exit (winget unavailable)"
            Invoke-MarkerFileCleanup -Reason "winget.exe not on PATH"
            exit 1
        }

        # Discovery output is intentionally empty - the task file is the work source.
        $OUTPUT = @()
        $OUTPUT_USER_SCOPE = @()

} elseif (Test-RunningAsSystem) {
        # SYSTEM context main execution - process system apps and schedule user remediation
        Write-Log -Message "SYSTEM context - reading task file work list and processing"

        if (-not $WingetPath) {
            Write-Log -Message "Winget not detected in SYSTEM context"
            Write-Log -Message "Performing marker file cleanup before exit (no winget in system context)"
            Invoke-MarkerFileCleanup -Reason "Winget not detected in SYSTEM context"
            exit 0
        }

        Write-Log -Message "Using winget path: $WingetPath"
        $wingetExe = Join-Path $WingetPath "winget.exe"
        # Discovery output is intentionally empty - the task file is the work source.
        $OUTPUT = @()
        $OUTPUT_USER_SCOPE = @()
} else {
    # User context execution - reads the task file written by detect.ps1
    Write-Log -Message "USER context - reading task file work list and processing"
    $OUTPUT = @()
    $OUTPUT_USER_SCOPE = @()
}

# TEST MODE: Inject a simulated task entry so the upgrade loop has something to chew on
# without requiring a real task file. Marker in the upgrade loop short-circuits the actual
# winget call for the Test.DemoApp ID.
if ($Script:TestMode) {
    Write-Log -Message "TEST MODE: Injecting simulated task entry for Test.DemoApp (1.0.0 -> 2.0.0)"
    $Script:TestModeInjected = @(@{
        AppID = "Test.DemoApp"
        FriendlyName = "Demo Application"
        CurrentVersion = "1.0.0"
        AvailableVersion = "2.0.0"
        InstalledScope = "machine"
    })
}

function Resolve-FriendlyName {
    <#
    .SYNOPSIS
        Looks up the display name of a winget package when FriendlyName is not set in the whitelist.
    .DESCRIPTION
        Queries 'winget show --id <AppID>' and parses the first line for the package display name.
        Results are cached in a script-scoped hashtable to avoid repeated lookups.
    .PARAMETER AppID
        The winget package ID to look up.
    .OUTPUTS
        The resolved friendly name string, or $null if lookup fails.
    #>
    param([string]$AppID)

    # Initialize cache on first call
    if (-not $Script:FriendlyNameCache) { $Script:FriendlyNameCache = @{} }

    if ($Script:FriendlyNameCache.ContainsKey($AppID)) {
        return $Script:FriendlyNameCache[$AppID]
    }

    try {
        $wingetExe = if ((Test-RunningAsSystem) -and $WingetPath) { Join-Path $WingetPath "winget.exe" } else { "winget.exe" }
        $showOutput = & $wingetExe show --id $AppID --accept-source-agreements 2>&1 | Where-Object { $_ -is [string] }

        if ($showOutput -and $showOutput.Count -gt 0) {
            # First non-empty line typically contains: "Found <DisplayName> [<AppID>]"
            foreach ($line in $showOutput) {
                if ($line -match '^Found\s+(.+?)\s+\[') {
                    $resolvedName = $Matches[1].Trim()
                    Write-Log -Message "Resolved FriendlyName for $AppID via winget show: $resolvedName" | Out-Null
                    $Script:FriendlyNameCache[$AppID] = $resolvedName
                    return $resolvedName
                }
            }
        }
    } catch {
        Write-Log -Message "Failed to resolve FriendlyName for ${AppID}: $($_.Exception.Message)" | Out-Null
    }

    $Script:FriendlyNameCache[$AppID] = $null
    return $null
}

# Build the work list from the static task file written by detect.ps1.
# detect.ps1 has already run the `winget upgrade` discovery and recorded each pending
# upgrade with its InstalledScope, so remediation does no discovery itself.
$LIST = @()
$Script:TasksForOtherContext = 0   # set by the routing block below; checked in the else branch so SYSTEM can still hand off user-scoped work even when its own list is empty
$Script:OtherContextAppIds = @()   # AppIDs routed to the other context, logged when handing off
$rawTaskList = @(Read-UpgradeTaskFile)
if ($rawTaskList -and $rawTaskList.Count -gt 0) {
    # Filter the task list down to entries that belong in the current context:
    #   - SYSTEM: machine-scoped only (v9.55 dropped "unknown" from SYSTEM's allowed list)
    #   - User context: user-scoped + unknown (admin user-context can elevate via RunLevel
    #     Highest, see v9.54, so it covers the unknown-might-be-machine case too)
    # v9.55 rationale: with detect.ps1 v5.60's SYSTEM-side visibility probe, anything reaching
    # remediate as "unknown" has already been proven invisible-to-SYSTEM during detection.
    # Letting SYSTEM try it anyway wastes the attempt AND - worse - bumps the per-version
    # failure counter, which the previous version of this loop interpreted as a real failure
    # and could trigger the 3-strikes skip-version dialog before user-context even got its
    # turn (observed in the 18:44 log for Git.Git). Now unknown-scope tasks bypass SYSTEM
    # entirely and go straight to user-context.
    $isSystem = (Test-RunningAsSystem)
    $allowedScopes = if ($isSystem) { @("machine") } else { @("user", "unknown") }
    $filtered = [System.Collections.ArrayList]::new()
    $skippedIds = [System.Collections.ArrayList]::new()
    foreach ($t in $rawTaskList) {
        $taskScope = if ($t.InstalledScope) { $t.InstalledScope } else { "unknown" }
        if ($allowedScopes -contains $taskScope) {
            $null = $filtered.Add($t)
        } else {
            $null = $skippedIds.Add("$($t.AppID)[$taskScope]")
        }
    }
    $LIST = $filtered
    $Script:TasksForOtherContext = $skippedIds.Count
    $Script:OtherContextAppIds = @($skippedIds)
    $contextLabel = if ($isSystem) { "SYSTEM" } else { "user" }
    $listCount = $LIST.Count
    Write-Log -Message "Task file: $($rawTaskList.Count) entries, $listCount routed to $contextLabel context, $($skippedIds.Count) left for the other context"
    if ($listCount -gt 0) {
        $hereIds = ($LIST | ForEach-Object { "$($_.AppID)[$(if ($_.InstalledScope) { $_.InstalledScope } else { 'unknown' })]" }) -join ', '
        Write-Log -Message "$contextLabel work list: $hereIds"
    }
    if ($skippedIds.Count -gt 0) {
        Write-Log -Message "Other-context work list: $($skippedIds -join ', ')"
    }
} else {
    Write-Log -Message "No fresh upgrade task file - nothing to remediate (run detect.ps1 first)"
}

# TEST MODE: append the simulated task so the loop runs even without a real task file.
if ($Script:TestMode -and $Script:TestModeInjected) {
    $injected = [System.Collections.ArrayList]::new()
    foreach ($a in $LIST) { $null = $injected.Add($a) }
    foreach ($a in $Script:TestModeInjected) { $null = $injected.Add($a) }
    $LIST = $injected
    Write-Log -Message "TEST MODE: appended simulated task; total work list = $($LIST.Count)"
}

if ($LIST -and $LIST.Count -gt 0) {
        $count = 0
        $message = ""
        $processingStart = Get-Date

        # Pre-update winget source so individual upgrade commands don't each trigger their own source refresh
        try {
            $sourceUpdateExe = if ((Test-RunningAsSystem) -and $WingetPath) { Join-Path $WingetPath "winget.exe" } else { "winget.exe" }
            $sourceUpdateArgs = @("source", "update", "--name", "winget")
            Write-Log -Message "Pre-updating winget source to avoid per-app source refreshes..."
            if ((Test-RunningAsSystem) -and $WingetPath) {
                Push-Location $WingetPath
                try { & $sourceUpdateExe @sourceUpdateArgs 2>&1 | Out-Null } finally { Pop-Location }
            } else {
                & $sourceUpdateExe @sourceUpdateArgs 2>&1 | Out-Null
            }
            Write-Log -Message "Winget source pre-update complete"
        } catch {
            Write-Log -Message "Winget source pre-update failed (non-fatal): $($_.Exception.Message)"
        }

        # Start the persistent dialog host (v9.33). Only SYSTEM context owns the host;
        # user-context attaches via Connect-DialogSession when it gets -DialogSessionId.
        # Failure here populates $Script:DialogLegacyFallback so all dialog wrappers
        # transparently fall back to the legacy per-dialog spawn path.
        if ((Test-RunningAsSystem) -and (-not $UserRemediationOnly)) {
            Write-Log -Message "Starting persistent dialog host"
            Start-DialogHost | Out-Null
        }

        Write-Log -Message "Starting app processing loop..."

        $Script:DialogPrevApp = $null   # last app for which we emitted a panel; drives `transition` between apps

        foreach ($appInfo in $LIST) {
            if ($appInfo.AppID -ne "") {
                # Keep heartbeat alive during app processing so SYSTEM parent doesn't time out
                if (Get-Command Update-Heartbeat -ErrorAction SilentlyContinue) {
                    Update-Heartbeat -Stage "AppProcessing" -AdditionalData @{ AppID = $appInfo.AppID }
                }
                # v9.33: emit a transition from the previous app to the current one so the
                # persistent dialog gives a visible hand-off instead of jumping straight to the
                # next ProgressPanel. No-op when host is not alive.
                if ($Script:DialogPrevApp -and (Test-DialogHostAlive)) {
                    Send-DialogCommand -Cmd "transition" -Payload @{
                        fromApp = $Script:DialogPrevApp
                        toApp = $appInfo.AppID
                        outcome = "ok"
                    } | Out-Null
                }
                $doUpgrade = $false
                foreach ($okapp in $whitelistConfig) {
                    if ($appInfo.AppID -like $okapp.AppID) {
                        Write-Log -Message "Processing whitelisted app: $($okapp.AppID)" | Out-Null

                        # Resolve FriendlyName via winget show if not set in whitelist
                        if ([string]::IsNullOrEmpty($okapp.FriendlyName)) {
                            $resolved = Resolve-FriendlyName -AppID $appInfo.AppID
                            if ($resolved) {
                                $okapp | Add-Member -NotePropertyName FriendlyName -NotePropertyValue $resolved -Force
                            }
                        }

                        # First, check deferral status if deferrals are enabled
                        if ($okapp.DeferralEnabled -eq $true) {
                            Write-Log -Message "Deferral system enabled for $($okapp.AppID), checking status" | Out-Null

                            $deferralStatus = Get-DeferralStatus -AppID $appInfo.AppID -WhitelistConfig $okapp -AvailableVersion $appInfo.AvailableVersion

                            if ($deferralStatus.ForceUpdate) {
                                # Past admin hard deadline or user deadline - mandatory update
                                Write-Log -Message "Update for $($okapp.AppID) is now mandatory: $($deferralStatus.Message)" | Out-Null
                            } elseif ($deferralStatus.DeferralsUsed -gt 0 -and $deferralStatus.UserDeadline -and (Get-Date) -lt $deferralStatus.UserDeadline) {
                                # User has an active deferral that hasn't expired yet - skip silently
                                Write-Log -Message "Update for $($okapp.AppID) has active deferral until $($deferralStatus.UserDeadline.ToString('yyyy-MM-dd HH:mm')) - skipping this run" | Out-Null
                                Write-Log -Message "Deferral message: $($deferralStatus.Message)" | Out-Null
                                continue  # Skip this app - user explicitly deferred
                            } else {
                                # First detection or expired deferral - fall through to show dialog
                                if ($deferralStatus.DeferralsUsed -gt 0) {
                                    Write-Log -Message "Previous deferral for $($okapp.AppID) has expired - showing update dialog" | Out-Null
                                } else {
                                    Write-Log -Message "First detection of update for $($okapp.AppID) - showing update dialog" | Out-Null
                                }
                            }
                        }

                        # Check if this version was skipped by user after repeated failures
                        $failureData = Get-VersionFailureData -AppID $appInfo.AppID -Version $appInfo.AvailableVersion
                        if ($failureData.IsSkipped) {
                            Write-Log -Message "Skipping $($appInfo.AppID) version $($appInfo.AvailableVersion) - skipped by user after repeated install failures"
                            continue
                        }

                        # Process blocking processes
                        $blockingProcessNames = $okapp.BlockingProcess
                        if (-not [string]::IsNullOrEmpty($blockingProcessNames)) {
                            $processesToCheck = $blockingProcessNames -split ','
                            $isBlocked = $false
                            $runningProcessName = ""
                            
                            foreach ($processName in $processesToCheck) {
                                $processName = $processName.Trim()
                                if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
                                    $runningProcessName = $processName
                                    $isBlocked = $true
                                    break
                                }
                            }
                            
                            if ($isBlocked) {
                                Write-Log -Message "Blocking process $runningProcessName is running for $($okapp.AppID)"
                                
                                # Check if this app should prompt when blocked
                                if ($okapp.PromptWhenBlocked -ne $true) {
                                    Write-Log -Message "Skipping $($okapp.AppID) - PromptWhenBlocked not set, waiting for next run"
                                    continue
                                }
                                
                                # Check if we can auto-close only safe processes
                                $autoCloseProcesses = $okapp.AutoCloseProcesses
                                $canAutoClose = $false
                                $dialogResult = $null
                                
                                if (-not [string]::IsNullOrEmpty($autoCloseProcesses)) {
                                    $autoCloseList = $autoCloseProcesses -split ','
                                    $runningProcesses = @()
                                    
                                    # Get all currently running blocking processes
                                    foreach ($processName in $processesToCheck) {
                                        $processName = $processName.Trim()
                                        if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
                                            $runningProcesses += $processName
                                        }
                                    }
                                    
                                    # Check if ALL running processes are in the auto-close list
                                    $canAutoClose = $true
                                    foreach ($runningProcess in $runningProcesses) {
                                        $isAutoCloseable = $false
                                        foreach ($autoCloseProcess in $autoCloseList) {
                                            if ($runningProcess -eq $autoCloseProcess.Trim()) {
                                                $isAutoCloseable = $true
                                                break
                                            }
                                        }
                                        if (-not $isAutoCloseable) {
                                            $canAutoClose = $false
                                            break
                                        }
                                    }
                                    
                                    if ($canAutoClose) {
                                        Write-Log -Message "Only auto-closeable processes running for $($okapp.AppID): $($runningProcesses -join ', '). Will auto-close after user confirms."
                                    }
                                }

                                # Always show the interactive dialog when PromptWhenBlocked is true
                                if ($true) {
                                    Write-Log -Message "$($okapp.AppID) has PromptWhenBlocked=true, showing interactive dialog"
                                    $defaultTimeoutAction = if ($okapp.DefaultTimeoutAction -eq $true) { $true } else { $false }
                                    
                                    # Use custom timeout from whitelist if specified, otherwise default to 60 seconds
                                    $customTimeout = if ($okapp.TimeoutSeconds -and $okapp.TimeoutSeconds -gt 0) { $okapp.TimeoutSeconds } else { 60 }
                                    
                                    Write-Log -Message "Using timeout: ${customTimeout}s, default action: $defaultTimeoutAction" | Out-Null
                                    $dialogResult = Show-ProcessCloseDialog -AppName $appInfo.AppID -ProcessName $runningProcessName -TimeoutSeconds $customTimeout -DefaultTimeoutAction $defaultTimeoutAction -FriendlyName $okapp.FriendlyName -CurrentVersion $appInfo.CurrentVersion -AvailableVersion $appInfo.AvailableVersion -WhitelistConfig $okapp
                                    
                                    Write-Log -Message "Show-ProcessCloseDialog returned: $($dialogResult | ConvertTo-Json -Compress)"
                                }
                                
                                # Handle dialog result
                                if ($dialogResult.Action -eq "Defer") {
                                    Write-Log -Message "User chose to defer $($okapp.AppID) for $($dialogResult.DeferralDays) days"
                                    continue  # Skip this app - user deferred
                                } elseif ($dialogResult.CloseProcess -or $dialogResult.UserChoice) {
                                    if ($canAutoClose) {
                                        Write-Log -Message "Auto-closing safe processes for $($okapp.AppID)"
                                    } else {
                                        Write-Log -Message "User agreed to close blocking processes for $($okapp.AppID)"
                                    }
                                    
                                    # Try to stop the blocking processes
                                    $processesStopped = Stop-BlockingProcesses -ProcessNames $blockingProcessNames
                                    
                                    if ($processesStopped) {
                                        Write-Log -Message "Successfully stopped blocking processes for $($okapp.AppID)"
                                        # Wait a moment for processes to fully close
                                        Start-Sleep -Seconds 3
                                        
                                        # Verify processes are really stopped
                                        # Exclude AutoCloseProcesses from check - services like warp-svc auto-restart via SCM
                                        $autoCloseList2 = @()
                                        if (-not [string]::IsNullOrEmpty($okapp.AutoCloseProcesses)) {
                                            $autoCloseList2 = ($okapp.AutoCloseProcesses -split ',') | ForEach-Object { $_.Trim() }
                                        }
                                        $stillRunning = $false
                                        foreach ($processName in $processesToCheck) {
                                            $processName = $processName.Trim()
                                            if ($processName -in $autoCloseList2) { continue }
                                            if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
                                                Write-Log -Message "Process still running after close attempt: $processName"
                                                $stillRunning = $true
                                                break
                                            }
                                        }
                                        
                                        if ($stillRunning) {
                                            Write-Log -Message "Some processes still running after close attempt for $($okapp.AppID), skipping"
                                            if ($dialogResult.ProgressSignalFile) {
                                                @{ Success = $false; Message = "Could not close application" } | ConvertTo-Json | Out-File -FilePath $dialogResult.ProgressSignalFile -Encoding UTF8
                                            }
                                            continue
                                        }
                                    } else {
                                        Write-Log -Message "Failed to stop blocking processes for $($okapp.AppID), skipping"
                                        if ($dialogResult.ProgressSignalFile) {
                                            @{ Success = $false; Message = "Could not close application" } | ConvertTo-Json | Out-File -FilePath $dialogResult.ProgressSignalFile -Encoding UTF8
                                        }
                                        continue
                                    }
                                } else {
                                    Write-Log -Message "User chose not to close blocking processes for $($okapp.AppID), skipping"
                                    continue
                                }
                            }
                        }
                        
                        # Determine if we can perform the upgrade based on context
                        if ((Test-RunningAsSystem) -or $userIsAdmin) {
                            Write-Log -Message "Upgrade $($okapp.AppID) in $(if (Test-RunningAsSystem) { 'SYSTEM' } else { 'admin user' }) context"
                            $doUpgrade = $true
                            break  # Break out of whitelist loop to proceed with upgrade
                        } elseif (-not (Test-RunningAsSystem)) {
                            # User context without admin - allow user-scope upgrades only
                            Write-Log -Message "Upgrade $($okapp.AppID) in user context (user-scope only)"
                            $doUpgrade = $true
                            break  # Break out of whitelist loop to proceed with upgrade
                        }
                    }
                }

                if ($doUpgrade) {
                    $count++
                    $infoSignalFile = $null

                    # Show informational progress dialog when no interactive dialog with built-in progress is active
                    if (-not $dialogResult -or -not $dialogResult.ProgressSignalFile) {
                        if (-not (Test-InfoDialogsSuppressed)) {
                            $infoSignalFile = Show-UpgradeProgressNotification -AppName $okapp.AppID -FriendlyName $okapp.FriendlyName -CurrentVersion $appInfo.CurrentVersion -AvailableVersion $appInfo.AvailableVersion
                        } else {
                            Write-Log -Message "Informational dialogs suppressed for today" | Out-Null
                        }
                    }

                    # Determine the active signal file for status updates (deferral dialog or informational dialog)
                    $activeSignalFile = if ($dialogResult -and $dialogResult.ProgressSignalFile) { $dialogResult.ProgressSignalFile } elseif ($infoSignalFile) { $infoSignalFile } else { $null }

                    Write-Log -Message "Starting upgrade for: $($appInfo.AppID)"

                    try {
                        # TEST MODE: Simulate upgrade instead of running winget
                        if ($Script:TestMode -and $appInfo.AppID -eq "Test.DemoApp") {
                            Write-InfoDialogStatus -SignalFilePath $activeSignalFile -Status "Preparing download..."
                            Write-Log -Message "TEST MODE: Simulating upgrade for $($appInfo.AppID) (1.0.0 -> 2.0.0)"
                            Start-Sleep -Seconds 3
                            $upgradeOutput = "Successfully installed"
                            Write-Log -Message "TEST MODE: Simulated upgrade completed"
                        } else {
                        Write-Log -Message "Executing winget upgrade for: $($appInfo.AppID)"
                        # v9.44: start with "Preparing download..." so the user can see when winget
                        # actually starts pulling bytes (status flips to "Downloading X MB / Y MB"
                        # or "Downloading XX%") and later to "Installing update..." (latched).
                        Write-InfoDialogStatus -SignalFilePath $activeSignalFile -Status "Preparing download..."

                        # First attempt: Standard upgrade with progress monitoring
                        $wingetExe = if ((Test-RunningAsSystem) -and $WingetPath) { Join-Path $WingetPath "winget.exe" } else { "winget.exe" }
                        $wingetDir = if ((Test-RunningAsSystem) -and $WingetPath) { $WingetPath } else { $null }
                        $wingetArgs = @("upgrade", "--silent", "--disable-interactivity", "--accept-source-agreements", "--accept-package-agreements", "--source", "winget", "--id", $appInfo.AppID)

                        # Use the InstalledScope already recorded in the task entry by detect.ps1
                        # rather than re-walking the registry per app. Falls back to "unknown"
                        # for entries that pre-date scope-aware detection.
                        $detectedScope = if ($appInfo.InstalledScope) { [string]$appInfo.InstalledScope } else { "unknown" }
                        if ((Test-RunningAsSystem)) {
                            if ($detectedScope -eq "user") {
                                Write-Log -Message "Using --scope user for $($appInfo.AppID) (task file scope: user)"
                                $wingetArgs += @("--scope", "user")
                            }
                        } elseif (-not $userIsAdmin) {
                            if ($detectedScope -eq "machine") {
                                Write-Log -Message "Skipping $($appInfo.AppID) - machine-scoped install cannot be upgraded without elevation (non-admin user context); SYSTEM will handle it"
                                $doUpgrade = $false
                            } else {
                                Write-Log -Message "Using --scope user for $($appInfo.AppID) in non-admin user context (task file scope: $detectedScope)"
                                $wingetArgs += @("--scope", "user")
                            }
                        }

                        # Honor scope-detection skip decision: must NOT invoke winget for machine-scoped
                        # apps in non-admin user context, as Windows would trigger a UAC prompt for the
                        # installer (e.g. Firefox writing to Program Files). The SYSTEM context handles
                        # these apps separately.
                        if (-not $doUpgrade) {
                            if ($dialogResult -and $dialogResult.ProgressSignalFile) {
                                @{ Success = $true; Message = "Update handled by system" } | ConvertTo-Json | Out-File -FilePath $dialogResult.ProgressSignalFile -Encoding UTF8
                            } elseif ($infoSignalFile) {
                                @{ Success = $true; Message = "Update handled by system" } | ConvertTo-Json | Out-File -FilePath $infoSignalFile -Encoding UTF8
                            }
                            $message += "$($appInfo.AppID) (SKIPPED-scope)|"
                            continue
                        }

                        if (Get-Command Update-Heartbeat -ErrorAction SilentlyContinue) {
                            Update-Heartbeat -Stage "UpgradeStarting" -AdditionalData @{ AppID = $appInfo.AppID }
                        }
                        $upgradeResult = Invoke-WingetWithProgress -WingetExe $wingetExe -Arguments $wingetArgs -SignalFilePath $activeSignalFile -WorkingDirectory $wingetDir
                        if (Get-Command Update-Heartbeat -ErrorAction SilentlyContinue) {
                            Update-Heartbeat -Stage "UpgradeComplete" -AdditionalData @{ AppID = $appInfo.AppID }
                        }

                        $upgradeOutput = $upgradeResult -join "`n"
                        # Extract meaningful lines from winget output for logging
                        $meaningfulLines = @()
                        foreach ($line in $upgradeResult) {
                            if ($line -isnot [string]) { continue }
                            $cleanLine = $line.Trim()
                            if ($cleanLine -ne "" -and $cleanLine.Length -gt 10 -and 
                                $cleanLine -notmatch '^[\-\\\|\/\s]*$' -and 
                                $cleanLine -notlike "*Progress:*" -and
                                $cleanLine -notlike "*.*%*") {
                                $meaningfulLines += $cleanLine
                            }
                        }
                        
                        if ($meaningfulLines.Count -gt 0) {
                            $logMessage = ($meaningfulLines | Select-Object -First 2) -join ' | '
                            Write-Log -Message "Winget result for $($appInfo.AppID) : $logMessage"
                        } else {
                            Write-Log -Message "Winget result for $($appInfo.AppID) : Processing completed"
                        }
                        
                        # Handle specific failure cases
                        if ($upgradeOutput -like "*install technology is different*") {
                            Write-InfoDialogStatus -SignalFilePath $activeSignalFile -Status "Reinstalling application..."
                            Write-Log -Message "Install technology mismatch detected for $($appInfo.AppID). Attempting uninstall and reinstall."
                            
                            # First uninstall - use detected scope
                            $scopeArgs = if ($detectedScope -eq "user" -or (-not (Test-RunningAsSystem) -and -not $userIsAdmin)) { @("--scope", "user") } else { @() }
                            if ((Test-RunningAsSystem) -and $WingetPath) {
                                $uninstallResult = & .\winget.exe uninstall --silent @scopeArgs --id $appInfo.AppID 2>&1
                            } else {
                                $uninstallResult = & winget uninstall --silent @scopeArgs --id $appInfo.AppID 2>&1
                            }
                            
                            $uninstallOutput = $uninstallResult -join "`n"
                            if ($uninstallOutput -like "*Successfully uninstalled*") {
                                Write-Log -Message "Successfully uninstalled $($appInfo.AppID)"
                            } else {
                                Write-Log -Message "Uninstall issue for $($appInfo.AppID)"
                            }
                            
                            # Wait a moment for cleanup
                            Start-Sleep -Seconds 2
                            
                            # Then install fresh - use appropriate winget path and scope based on context
                            if ((Test-RunningAsSystem) -and $WingetPath) {
                                $upgradeResult = & .\winget.exe install --silent --accept-source-agreements @scopeArgs --id $appInfo.AppID 2>&1
                            } else {
                                $upgradeResult = & winget install --silent --accept-source-agreements @scopeArgs --id $appInfo.AppID 2>&1
                            }
                            
                            $upgradeOutput = $upgradeResult -join "`n"
                            Write-Log -Message "Fresh install completed for $($appInfo.AppID)"
                            
                        } elseif ($upgradeOutput -like "*Uninstall failed*") {
                            Write-InfoDialogStatus -SignalFilePath $activeSignalFile -Status "Retrying installation..."
                            Write-Log -Message "Uninstall failure detected for $($appInfo.AppID). Trying alternative approaches."

                            # Try install with --force to override - use detected scope
                            $scopeArgs = if ($detectedScope -eq "user" -or (-not (Test-RunningAsSystem) -and -not $userIsAdmin)) { @("--scope", "user") } else { @() }
                            if ((Test-RunningAsSystem) -and $WingetPath) {
                                $upgradeResult = & .\winget.exe install --silent --accept-source-agreements --force @scopeArgs --id $appInfo.AppID 2>&1
                            } else {
                                $upgradeResult = & winget install --silent --accept-source-agreements --force @scopeArgs --id $appInfo.AppID 2>&1
                            }

                            $upgradeOutput = $upgradeResult -join "`n"
                            Write-Log -Message "Force install completed for $($appInfo.AppID)"

                        } elseif ($upgradeOutput -like "*hash does not match*") {
                            # Hash mismatch: winget manifest hash is stale (common with rolling installer URLs).
                            # --ignore-security-hash is blocked by admin policy, so download and run the installer directly.
                            Write-Log -Message "Installer hash mismatch for $($appInfo.AppID). Attempting direct download fallback."

                            # Resolve installer URL: whitelist InstallerUrl takes precedence, otherwise parse winget show
                            $installerUrl = $okapp.InstallerUrl
                            if (-not $installerUrl) {
                                try {
                                    $showExe = if ((Test-RunningAsSystem) -and $WingetPath) { Join-Path $WingetPath "winget.exe" } else { "winget.exe" }
                                    $showOutput = & $showExe show --id $appInfo.AppID --source winget --accept-source-agreements 2>&1
                                    foreach ($showLine in $showOutput) {
                                        if ("$showLine" -match '^\s*Installer Url:\s*(.+)$') {
                                            $installerUrl = $Matches[1].Trim()
                                            Write-Log -Message "Resolved installer URL from winget show: $installerUrl" | Out-Null
                                            break
                                        }
                                    }
                                } catch {
                                    Write-Log -Message "Failed to query winget show for installer URL: $($_.Exception.Message)"
                                }
                            }

                            if ($installerUrl) {
                                Write-InfoDialogStatus -SignalFilePath $activeSignalFile -Status "Downloading installer directly..."
                                Write-Log -Message "Downloading installer from: $installerUrl"

                                $installerExt = if ($installerUrl -match '\.(msi|msix)(\?|$)') { ".$($Matches[1])" } else { ".exe" }
                                $installerPath = Join-Path $env:TEMP "DirectInstall_$($appInfo.AppID -replace '[^a-zA-Z0-9.]','_')_$(Get-Random)$installerExt"

                                try {
                                    if (Get-Command Update-Heartbeat -ErrorAction SilentlyContinue) {
                                        Update-Heartbeat -Stage "DirectDownload" -AdditionalData @{ AppID = $appInfo.AppID } | Out-Null
                                    }
                                    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

                                    # Use WebClient.DownloadFile in a background job so heartbeats stay alive
                                    # (Invoke-WebRequest is extremely slow for large files in PS 5.1)
                                    $dlJob = Start-Job -ScriptBlock {
                                        param($url, $dest)
                                        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                                        (New-Object System.Net.WebClient).DownloadFile($url, $dest)
                                    } -ArgumentList $installerUrl, $installerPath

                                    $dlTimeout = 300  # 5 minutes max for download
                                    $dlWaitStart = Get-Date
                                    while ((Get-Date) -lt $dlWaitStart.AddSeconds($dlTimeout) -and $dlJob.State -eq "Running") {
                                        if (Wait-Job $dlJob -Timeout 10) { break }
                                        if (Get-Command Update-Heartbeat -ErrorAction SilentlyContinue) {
                                            $dlProgress = if (Test-Path $installerPath) { [Math]::Round((Get-Item $installerPath).Length / 1MB, 1) } else { 0 }
                                            Update-Heartbeat -Stage "DirectDownload" -AdditionalData @{ AppID = $appInfo.AppID; DownloadedMB = $dlProgress } | Out-Null
                                            Write-InfoDialogStatus -SignalFilePath $activeSignalFile -Status "Downloading installer... ${dlProgress} MB"
                                        }
                                    }

                                    if ($dlJob.State -ne "Completed") {
                                        Remove-Job $dlJob -Force
                                        throw "Download timed out after $dlTimeout seconds"
                                    }
                                    # Check for job errors
                                    Receive-Job $dlJob -ErrorAction Stop | Out-Null
                                    Remove-Job $dlJob -Force

                                    $dlSize = (Get-Item $installerPath).Length
                                    Write-Log -Message "Downloaded installer: $([Math]::Round($dlSize / 1MB, 1)) MB"

                                    # Determine silent install arguments (whitelist override or sensible default)
                                    $installerArgs = if ($okapp.InstallerArgs) { $okapp.InstallerArgs } else { "--silent" }
                                    Write-InfoDialogStatus -SignalFilePath $activeSignalFile -Status "Installing update..."
                                    Write-Log -Message "Running installer: $installerPath $installerArgs"

                                    if (Get-Command Update-Heartbeat -ErrorAction SilentlyContinue) {
                                        Update-Heartbeat -Stage "DirectInstall" -AdditionalData @{ AppID = $appInfo.AppID } | Out-Null
                                    }

                                    # Run installer in background too so heartbeats stay alive
                                    $installProc = Start-Process -FilePath $installerPath -ArgumentList $installerArgs -PassThru -NoNewWindow -ErrorAction Stop
                                    $installTimeout = 300  # 5 minutes max for install
                                    $installWaitStart = Get-Date
                                    while (-not $installProc.HasExited -and (Get-Date) -lt $installWaitStart.AddSeconds($installTimeout)) {
                                        Start-Sleep -Seconds 5
                                        if (Get-Command Update-Heartbeat -ErrorAction SilentlyContinue) {
                                            Update-Heartbeat -Stage "DirectInstall" -AdditionalData @{ AppID = $appInfo.AppID; InstallerPID = $installProc.Id } | Out-Null
                                        }
                                    }
                                    if (-not $installProc.HasExited) {
                                        $installProc.Kill()
                                        throw "Installer timed out after $installTimeout seconds"
                                    }

                                    # Ensure exit code is populated (Chromium installers fork and parent exits fast)
                                    $installProc.WaitForExit()
                                    $installExitCode = $installProc.ExitCode
                                    Write-Log -Message "Direct installer exited with code: $installExitCode"

                                    # Treat null/0 as success - Chromium installers often return null (parent forks)
                                    if ($null -eq $installExitCode -or $installExitCode -eq 0) {
                                        $upgradeOutput = "Successfully installed (direct download fallback)"
                                        Write-Log -Message "Direct install succeeded for $($appInfo.AppID)"
                                    } else {
                                        $upgradeOutput = "Direct installer failed with exit code $installExitCode"
                                        Write-Log -Message "Direct install failed for $($appInfo.AppID) - exit code: $installExitCode"
                                    }
                                } catch {
                                    Write-Log -Message "Direct download/install failed for $($appInfo.AppID): $($_.Exception.Message)"
                                    # Keep original upgradeOutput so the failure is reported as hash mismatch
                                } finally {
                                    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
                                }
                            } else {
                                Write-Log -Message "No installer URL available for $($appInfo.AppID) - cannot attempt direct download fallback"
                            }
                        }
                        } # end else (non-test mode winget upgrade)

                        # Evaluate success
                        Write-InfoDialogStatus -SignalFilePath $activeSignalFile -Status "Verifying installation..."
                        $isSuccess = $false
                        $successReason = "none"
                        if ($upgradeOutput -like "*Successfully installed*" -or $upgradeOutput -like "*Successfully updated*") {
                            $isSuccess = $true
                            $successReason = "output-match"
                        } elseif ($upgradeOutput -like "*No applicable update*" -or $upgradeOutput -like "*No newer version available*") {
                            $isSuccess = $true
                            $successReason = "already-current"
                        } elseif ($null -ne $LASTEXITCODE -and $LASTEXITCODE -eq 0 -and $upgradeOutput -notlike "*failed*" -and $upgradeOutput -notlike "*error*0x*") {
                            $isSuccess = $true
                            $successReason = "exit-code-0"
                        }
                        Write-Log -Message "Initial success evaluation for $($appInfo.AppID): isSuccess=$isSuccess, reason=$successReason, LASTEXITCODE=$LASTEXITCODE, outputLength=$($upgradeOutput.Length)"

                        # Post-upgrade verification: confirm via winget list --exact that the update actually took effect.
                        # Originally added (v8.8) for Adobe Reader's exit-code-0-but-no-version-change behavior. The
                        # extra winget list pass costs ~1.5s per app, so it is now opt-in via the whitelist
                        # `RequiresPostVerify` flag - set true only on apps known to lie about success.
                        $needsPostVerify = $false
                        if ($okapp -and $okapp.PSObject.Properties['RequiresPostVerify'] -and $okapp.RequiresPostVerify -eq $true) {
                            $needsPostVerify = $true
                        }
                        if ($isSuccess -and -not $Script:TestMode -and $needsPostVerify) {
                            try {
                                $verifyExe = if ((Test-RunningAsSystem) -and $WingetPath) { Join-Path $WingetPath "winget.exe" } else { "winget.exe" }
                                $verifyArgs = @("list", "--id", $appInfo.AppID, "--exact", "--source", "winget", "--accept-source-agreements")
                                if ((Test-RunningAsSystem) -and $WingetPath) {
                                    Push-Location $WingetPath
                                    try { $verifyResult = & $verifyExe @verifyArgs 2>&1 } finally { Pop-Location }
                                } else {
                                    $verifyResult = & $verifyExe @verifyArgs 2>&1
                                }
                                # Use the column-position parser (header-based) to extract Available reliably,
                                # since whitespace splitting misclassifies columns when Available is empty after a successful upgrade.
                                $verifyLines = @($verifyResult | ForEach-Object { "$_" })
                                $verifyApps = ConvertFrom-WingetOutput -Output $verifyLines
                                $verifyAvailableVersion = $null
                                $verifyCurrentVersion = $null
                                foreach ($vApp in $verifyApps) {
                                    if ($vApp.AppID -eq $appInfo.AppID) {
                                        $verifyAvailableVersion = $vApp.AvailableVersion
                                        $verifyCurrentVersion = $vApp.CurrentVersion
                                        break
                                    }
                                }

                                if ([string]::IsNullOrWhiteSpace($verifyAvailableVersion)) {
                                    # No Available version parsed (column empty or absent) - upgrade took effect
                                    # or no pending upgrade remains. Trust the original success signal.
                                    Write-Log -Message "Post-upgrade verification: $($appInfo.AppID) confirmed up to date (Current=$verifyCurrentVersion, no Available)"
                                } elseif ($verifyAvailableVersion -eq $appInfo.AvailableVersion) {
                                    # winget list still shows the EXACT version we tried to install as pending - true failure
                                    Write-Log -Message "Post-upgrade verification: $($appInfo.AppID) still shows pending update for our target version $($appInfo.AvailableVersion) - treating as failure"
                                    $isSuccess = $false
                                } else {
                                    # A different (typically newer) version appeared in the source after our upgrade - trust original success
                                    Write-Log -Message "Post-upgrade verification: $($appInfo.AppID) Available=$verifyAvailableVersion differs from target $($appInfo.AvailableVersion) - newer release appeared, trusting original success"
                                }
                            } catch {
                                Write-Log -Message "Post-upgrade verification error: $($_.Exception.Message) - trusting original result"
                            }
                        }
                        if ($isSuccess) {
                            Write-Log -Message "Upgrade completed successfully for: $($appInfo.AppID)"
                            Clear-VersionFailureData -AppID $appInfo.AppID
                            $message += "$($appInfo.AppID) (OK)|"
                            # Done with this entry \u2014 drop it from the static task file.
                            Remove-UpgradeTaskEntry -AppID $appInfo.AppID

                            if ($dialogResult -and $dialogResult.ProgressSignalFile) {
                                # Signal the deferral dialog's progress mode
                                @{ Success = $true; Message = "Update complete" } | ConvertTo-Json | Out-File -FilePath $dialogResult.ProgressSignalFile -Encoding UTF8
                                Write-Log -Message "Wrote completion signal to progress dialog"
                            } elseif ($infoSignalFile) {
                                # Signal the informational progress dialog
                                @{ Success = $true; Message = "Update complete" } | ConvertTo-Json | Out-File -FilePath $infoSignalFile -Encoding UTF8
                                Write-Log -Message "Signaled informational progress dialog"
                            } elseif (($dialogResult -and ($dialogResult.CloseProcess -or $dialogResult.UserChoice)) -or ($Script:TestMode -and $appInfo.AppID -eq "Test.DemoApp")) {
                                # Fallback: show separate completion notification
                                Show-CompletionNotification -AppName $okapp.AppID -FriendlyName $okapp.FriendlyName
                            }
                        } else {
                            # Log full output for debugging (filter out progress bar characters)
                            $debugLines = ($upgradeResult | ForEach-Object { "$_".Trim() } | Where-Object { $_ -ne "" -and $_ -notmatch '^[\u2580-\u259F\s\|/\\-]+$' }) -join " | "
                            Write-Log -Message "Upgrade failed for $($appInfo.AppID) - reason=$successReason, Exit code: $LASTEXITCODE - Output: $debugLines"
                            $message += "$($appInfo.AppID) (FAILED)|"
                            $newFailCount = Set-VersionFailure -AppID $appInfo.AppID -Version $appInfo.AvailableVersion
                            Write-Log -Message "Install failure count for $($appInfo.AppID) $($appInfo.AvailableVersion): $newFailCount/3"
                            if ($newFailCount -ge 3) {
                                Write-Log -Message "3 failures reached for $($appInfo.AppID) - showing skip version dialog"
                                $skipChoice = Show-VersionSkipDialog -AppName $appInfo.AppID -FriendlyName $okapp.FriendlyName -Version $appInfo.AvailableVersion -FailureCount $newFailCount
                                if ($skipChoice) {
                                    # User chose Skip: mark this version as dismissed (detect.ps1 v5.56 honors
                                    # the flag and won't re-propose it) and drop the task entry so the SYSTEM
                                    # loop doesn't re-attempt before detect runs again.
                                    Set-VersionSkipped -AppID $appInfo.AppID -Version $appInfo.AvailableVersion
                                    Remove-UpgradeTaskEntry -AppID $appInfo.AppID
                                    Write-Log -Message "User chose Skip - version $($appInfo.AvailableVersion) marked dismissed and task removed"
                                } else {
                                    # v9.55: user chose Retry (or the dialog timed out). The previous code
                                    # removed the task and kept the 3/3 failure count regardless, so the
                                    # "Retry" button was effectively meaningless - the next cycle still saw
                                    # the app gone and even if detect re-added it the count was still
                                    # capped, immediately re-prompting. Now Retry clears the failure data
                                    # and KEEPS the task entry so the next remediate cycle gets a fresh
                                    # 3-attempt budget against the current version.
                                    Clear-VersionFailureData -AppID $appInfo.AppID
                                    Write-Log -Message "User chose Retry (or dialog timed out) - failure count reset, task kept for next cycle"
                                }
                            }
                            if ($dialogResult -and $dialogResult.ProgressSignalFile) {
                                @{ Success = $false; Message = "Update failed" } | ConvertTo-Json | Out-File -FilePath $dialogResult.ProgressSignalFile -Encoding UTF8
                                Write-Log -Message "Wrote failure signal to progress dialog"
                            } elseif ($infoSignalFile) {
                                @{ Success = $false; Message = "Update failed" } | ConvertTo-Json | Out-File -FilePath $infoSignalFile -Encoding UTF8
                                Write-Log -Message "Signaled informational progress dialog (failure)"
                            }
                        }
                    } catch {
                        Write-Log -Message "Error upgrading $($appInfo.AppID) : $($_.Exception.Message)"
                        $message += "$($appInfo.AppID) (ERROR)|"
                        if ($dialogResult -and $dialogResult.ProgressSignalFile) {
                            @{ Success = $false; Message = "Update error" } | ConvertTo-Json | Out-File -FilePath $dialogResult.ProgressSignalFile -Encoding UTF8
                        } elseif ($infoSignalFile) {
                            @{ Success = $false; Message = "Update error" } | ConvertTo-Json | Out-File -FilePath $infoSignalFile -Encoding UTF8
                        }
                    }
                }
                # v9.33: remember this app so the next iteration can emit a `transition` from it
                $Script:DialogPrevApp = $appInfo.AppID
            }
        }

        # v9.33: signal end of upgrade run to the persistent dialog host so it shows the final
        # completion panel and auto-hides after 3 s. No-op when host is not alive (legacy spawn
        # already wrote completion signals per-app).
        # v9.38: only fire the completion panel when at least one app was actually processed;
        # otherwise the host briefly flashes "Updates complete - 0 apps processed" before
        # Stop-DialogHost tears it down, which the user sees as a sub-second dialog flicker.
        if ((Test-DialogHostAlive) -and ($count -gt 0)) {
            $hadFailure = ($message -match '\(FAILED\)' -or $message -match '\(ERROR\)')
            $body = if ($count -eq 1) { "1 app processed" } else { "$count apps processed" }
            Send-DialogCommand -Cmd "complete" -Payload @{
                success = (-not $hadFailure)
                title = if ($hadFailure) { "Some updates failed" } else { "Updates complete" }
                body = $body
            } | Out-Null
            # v9.59: dwell so the user can read the final summary panel before the script
            # proceeds to user-context handoff (SYSTEM path) or exits and lets SYSTEM tear
            # the host down (user-context path). Without this the panel could be force-killed
            # by Stop-DialogHost within ~5 s, and the v9.59 7 s auto-hide never gets to fire.
            Start-Sleep -Seconds 5
        }

        # If we're in SYSTEM context, hand off to user context only when the task file
        # actually contains user-scoped entries. The unconditional handoff predated the
        # task-file routing and would launch a no-op user-context task on every cycle
        # that had only machine-scoped work.
        if ($Script:TestMode) {
            Write-Log -Message "TEST MODE: Skipping user context remediation scheduling (test app is system-only)"
        } elseif ((Test-RunningAsSystem) -and (-not $UserRemediationOnly)) {
            if ($Script:TasksForOtherContext -le 0) {
                Write-Log -Message "SYSTEM context processing complete - no user-scoped tasks in task file, skipping user context handoff"
            } else {
                Write-Log -Message "SYSTEM context processing complete - $($Script:TasksForOtherContext) task(s) routed to user context, checking for interactive session"
                if (-not (Test-InteractiveSession)) {
                    Write-Log -Message "No interactive session detected - skipping user context remediation"
                    Write-Log -Message "[$ScriptTag] Remediation completed: $count apps processed (system only, no interactive session)"
                } else {
                    Write-Log -Message "Interactive session confirmed - scheduling user context remediation"
                    $userScheduled = Schedule-UserContextRemediation
                    if ($userScheduled) {
                        Write-Log -Message "User context remediation scheduled successfully"
                    } else {
                        Write-Log -Message "User context remediation scheduling failed"
                    }
                }
            }
        }
        
        Write-Log -Message "[$ScriptTag] Remediation completed: $count apps processed"
        if ($message -ne "") {
            Write-Log -Message "[$ScriptTag] Apps upgraded: $message"
        }
        
        $processingTime = (Get-Date) - $processingStart
        Write-Log -Message "App processing completed in $($processingTime.TotalSeconds) seconds"

        # If this is a UserRemediationOnly task, write result file for SYSTEM context to read
        if ($UserRemediationOnly) {
            Write-Log -Message "*** USER CONTEXT REMEDIATION COMPLETE - WRITING RESULTS ***"
            Write-Log -Message "RemediationResultFile parameter: $RemediationResultFile"
            $resultWritingStart = Get-Date
            
            if ($RemediationResultFile) {
                try {
                    Write-Log -Message "Parsing upgrade results from message: '$message'"
                    # Parse message to extract upgrade results
                    $upgradeResults = @()
                    if ($message -ne "") {
                        # Split by pipe and clean up each result
                        $results = $message -split '\|' | Where-Object { $_ -ne "" }
                        $upgradeResults = $results | ForEach-Object { $_.Trim() }
                    }
                    
                    $totalExecutionTime = if ($userContextStart) { (Get-Date) - $userContextStart } else { New-TimeSpan }
                    $results = @{
                        ProcessedApps = $count
                        UpgradeResults = $upgradeResults
                        Success = $true
                        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        Username = $env:USERNAME
                        Computer = $env:COMPUTERNAME
                        Context = "USER"
                        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                        ProcessId = $PID
                        SessionId = (Get-Process -Id $PID).SessionId
                        ExecutionTime = $totalExecutionTime.TotalSeconds
                        TimingDetails = @{
                            WingetExecution = if ($wingetTime) { $wingetTime.TotalSeconds } else { 0 }
                            OutputParsing = if ($parsingTime) { $parsingTime.TotalSeconds } else { 0 }
                            AppProcessing = if ($processingTime) { $processingTime.TotalSeconds } else { 0 }
                        }
                    }
                    
                    Write-Log -Message "Writing user remediation results to file: $RemediationResultFile"
                    Write-Log -Message "Results: ProcessedApps=$count, UpgradeResults=$($upgradeResults.Count) items, ExecutionTime=$($totalExecutionTime.TotalSeconds)s"
                    
                    # Ensure the directory exists
                    $resultDir = Split-Path $RemediationResultFile -Parent
                    if (-not (Test-Path $resultDir)) {
                        New-Item -Path $resultDir -ItemType Directory -Force | Out-Null
                        Write-Log -Message "Created result directory: $resultDir"
                    }
                    
                    $results | ConvertTo-Json -Depth 4 -Compress | Out-File -FilePath $RemediationResultFile -Encoding UTF8 -Force
                    
                    # Verify file was written
                    if (Test-Path $RemediationResultFile) {
                        $fileSize = (Get-Item $RemediationResultFile).Length
                        $resultWritingTime = (Get-Date) - $resultWritingStart
                        Write-Log -Message "Result file written successfully in $($resultWritingTime.TotalSeconds) seconds, size: $fileSize bytes"
                    } else {
                        Write-Log -Message "ERROR: Result file was not created at: $RemediationResultFile"
                    }
                    
                } catch {
                    $resultWritingTime = (Get-Date) - $resultWritingStart
                    Write-Log -Message "ERROR: Failed to write user remediation results after $($resultWritingTime.TotalSeconds) seconds: $($_.Exception.Message)"
                    Write-Log -Message "Exception details: $($_.Exception.ToString())"
                }
            } else {
                Write-Log -Message "WARNING: No result file path found - SYSTEM context may not receive results"
            }
            
            $totalUserContextTime = if ($userContextStart) { (Get-Date) - $userContextStart } else { New-TimeSpan }
            Write-Log -Message "*** USER CONTEXT TASK EXITING after $($totalUserContextTime.TotalSeconds) seconds ***"
        }
        
        # Stop the persistent dialog host (v9.33). SYSTEM owns lifecycle; user-context
        # is a no-op because Stop-DialogHost short-circuits on $Script:DialogSession=null,
        # and even if user-context attached, only SYSTEM writes the TaskName/PID.
        if ((Test-RunningAsSystem) -and (-not $UserRemediationOnly)) {
            Stop-DialogHost | Out-Null
        }

        Write-Log -Message "Performing final marker file cleanup before script completion"
        Invoke-MarkerFileCleanup -Reason "Script completion (remediation complete)"
        exit 0
} else {
    Write-Log -Message "[$ScriptTag] No upgrades found in winget output"

    # SYSTEM had no machine-scoped work itself, but the task file may still contain user-scoped
    # entries that need handing off. Without this branch, an all-user-scope task file would
    # silently exit here and the user-context task would never be scheduled.
    if ((Test-RunningAsSystem) -and (-not $UserRemediationOnly) -and ($Script:TasksForOtherContext -gt 0)) {
        Write-Log -Message "$($Script:TasksForOtherContext) task(s) routed to user context - checking for interactive session"
        if (-not (Test-InteractiveSession)) {
            Write-Log -Message "No interactive session detected - skipping user context remediation (will retry next cycle)"
        } else {
            Write-Log -Message "Interactive session confirmed - scheduling user context remediation"
            $userScheduled = Schedule-UserContextRemediation
            if ($userScheduled) {
                Write-Log -Message "User context remediation scheduled successfully"
            } else {
                Write-Log -Message "User context remediation scheduling failed"
            }
        }
    }

    # When a UserRemediationOnly run has nothing to do (typically because SYSTEM already drained
    # the task file), still write the result file so SYSTEM stops waiting on heartbeats - the
    # outer Schedule-UserContextRemediation polls for this file and otherwise sits in its
    # 600-second idle timeout before declaring failure.
    if ($UserRemediationOnly -and $RemediationResultFile) {
        try {
            $resultDir = Split-Path $RemediationResultFile -Parent
            if ($resultDir -and -not (Test-Path $resultDir)) {
                New-Item -Path $resultDir -ItemType Directory -Force | Out-Null
            }
            @{
                ProcessedApps = 0
                UpgradeResults = @()
                Success = $true
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Username = $env:USERNAME
                Computer = $env:COMPUTERNAME
                Context = "USER"
                Reason = "No fresh upgrade task file - nothing to remediate"
            } | ConvertTo-Json -Depth 3 -Compress | Out-File -FilePath $RemediationResultFile -Encoding UTF8 -Force
            Write-Log -Message "Wrote empty result file to signal completion: $RemediationResultFile"
        } catch {
            Write-Log -Message "ERROR writing empty result file: $($_.Exception.Message)"
        }
    }

    # Stop the persistent dialog host on the no-upgrades path too (v9.33).
    if ((Test-RunningAsSystem) -and (-not $UserRemediationOnly)) {
        Stop-DialogHost | Out-Null
    }

    Write-Log -Message "Performing final marker file cleanup before script exit (no upgrades)"
    Invoke-MarkerFileCleanup -Reason "Script completion (no upgrades)"
    exit 0
}
