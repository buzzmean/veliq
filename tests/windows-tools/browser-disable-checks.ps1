Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$global:VeliqDisableFixtureEmpty=$true
function Get-CimInstance {param($ClassName,$Filter,$ErrorAction)
 if($ClassName -eq 'Win32_Service'){return [pscustomobject]@{State='Stopped';ProcessId=0;StartMode='Auto';ExitCode=0}}
 if($global:VeliqDisableFixtureEmpty){return @()}
 @([pscustomobject]@{ProcessId=10;ParentProcessId=1;CreationDate=(Get-Date);ExecutablePath='C:\fixture\veliq-service.exe';CommandLine='C:\fixture\veliq-service.exe --chrome-recovery --recovery-port=50165 secret-marker'},[pscustomobject]@{ProcessId=11;ParentProcessId=1;CreationDate=(Get-Date);ExecutablePath='C:\fixture\veliq-service.exe';CommandLine='C:\fixture\veliq-service.exe -browser-policy-watchdog secret-marker'})
}
function Get-NetTCPConnection {param($State,$ErrorAction);@()}
function Get-WinEvent {param($FilterHashtable,$MaxEvents,$ErrorAction);throw 'empty fixture log'}
$path=Join-Path $repo 'tools\windows\diagnose-browser-processes.ps1'
& $path |Out-Null
$global:VeliqDisableFixtureEmpty=$false
$output=(& $path|Out-String)
if($output -notmatch 'OWNER_RECOVERY' -or $output -notmatch 'POLICY_WATCHDOG' -or $output -match 'secret-marker'){throw 'PROCESS_DIAGNOSTIC_ROLE_OR_REDACTION_FAILED'}
foreach($file in @('check-browser-disable.ps1','diagnose-browser-processes.ps1')){
 $t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repo ('tools\windows\'+$file)),[ref]$t,[ref]$e);if($e.Count){throw 'BROWSER_DISABLE_PARSE_FAILED'}
}
'PASS local read-only process roles, empty process list, redaction and acceptance parse; no SCM/registry/browser/VPS mutations'
