# Execute the actual resume function with inert task/process stubs. No tasks,
# registry, service, GUI or network changes on this test host.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$source=Join-Path $PSScriptRoot '../../installer/transaction.ps1'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'BACKGROUND_TRANSACTION_PARSE_FAILED'}
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Resume-OwnedGui'},$true)
if(!$function){throw 'BACKGROUND_RESUME_FUNCTION_MISSING'}
Invoke-Expression $function.Extent.Text
$app=$PSScriptRoot
$script:observed=$null;$script:started=0;$script:removed=0
function Test-Path {param($LiteralPath) return $true}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel) if($UserId -cne 'fixture-owner' -or $LogonType -cne 'Interactive' -or $RunLevel -cne 'Limited'){throw 'BACKGROUND_OWNER_MISMATCH'};return @{}}
function New-ScheduledTaskSettingsSet {param([switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries,$ExecutionTimeLimit) return @{}}
function New-ScheduledTaskAction {param($Execute,$Argument) $script:observed=$Argument;return @{}}
function Register-ScheduledTask {param($TaskName,$Action,$Principal,$Settings) }
function Start-ScheduledTask {param($TaskName) $script:started++}
function Unregister-ScheduledTask {param($TaskName,[switch]$Confirm,$ErrorAction) $script:removed++}
function Get-CimInstance {param($ClassName,$Filter) return [pscustomobject]@{ExecutablePath=(Join-Path $app 'VELIQ.exe');SessionId=42}}
function Write-VeliqInstallDiagnostic {param($Stage,$Details) }
$record=[pscustomobject]@{gui=@([pscustomobject]@{sid='fixture-owner';session=42;path=(Join-Path $app 'VELIQ.exe')})}
foreach($tray in @($false,$true)){
 $ResumeGuiInTray=$tray;$script:observed=$null
 Resume-OwnedGui $record
 if($tray -and $script:observed -cne '--autostart'){throw 'BACKGROUND_GUI_NOT_IN_TRAY'}
 if(!$tray -and $script:observed){throw 'MANUAL_GUI_RESUME_CHANGED'}
}
if($script:started -ne 2 -or $script:removed -ne 2){throw 'BACKGROUND_TASK_COUNT_MISMATCH'}
Write-Output 'PASS actual resume function: owner/interactive/limited, managed tray, manual unchanged, one temporary task cleaned per resume'
