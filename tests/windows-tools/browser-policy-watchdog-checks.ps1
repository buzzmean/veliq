# Pure ScheduledTasks command fixtures. No real task, browser, registry or service.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function sc.exe {param($Command,$Service,$Flag)if($Command -ne 'failureflag' -or $Service -ne 'VELIQ' -or $Flag -ne '1'){throw 'unexpected SCM command'};$global:LASTEXITCODE=0}
$script:fixtureTask=$null;$script:starts=0;$script:stops=0;$script:removes=0
function Get-ScheduledTask {param($TaskName,$ErrorAction)return $script:fixtureTask}
function New-ScheduledTaskAction {param($Execute,$Argument)return [pscustomobject]@{Execute=$Execute;Arguments=$Argument}}
function New-ScheduledTaskTrigger {param([switch]$AtStartup,[switch]$AtLogOn)return [pscustomobject]@{Boot=[bool]$AtStartup;Logon=[bool]$AtLogOn}}
function New-ScheduledTaskSettingsSet {param($ExecutionTimeLimit,$RestartCount,$RestartInterval,[switch]$StartWhenAvailable,$MultipleInstances)return [pscustomobject]@{ExecutionTimeLimit=$ExecutionTimeLimit;MultipleInstances=$MultipleInstances}}
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel)if($UserId -ne 'SYSTEM'){throw 'wrong principal'};return $UserId}
function Register-ScheduledTask {param($TaskName,$Description,$Action,$Trigger,$Settings,$Principal,[switch]$Force)
 if(@($Trigger).Count -ne 2 -or !$Trigger[0].Boot -or !$Trigger[1].Logon){throw 'missing boot/logon repair'}
 $script:fixtureTask=[pscustomobject]@{Description=$Description;Actions=@($Action);State='Running'}
}
function Start-ScheduledTask {param($TaskName)$script:starts++}
function Stop-ScheduledTask {param($TaskName,$ErrorAction)$script:stops++}
function Unregister-ScheduledTask {param($TaskName,[switch]$Confirm,$ErrorAction)$script:removes++;$script:fixtureTask=$null}
. (Join-Path $PSScriptRoot '../../tools/windows/browser-policy-watchdog.ps1')
$directory=Join-Path ([IO.Path]::GetTempPath()) 'veliq-watchdog-fixture'
Install-VeliqPolicyWatchdog $directory
Install-VeliqPolicyWatchdog $directory
if($script:starts -ne 2){throw 'idempotent watchdog start missing'}
Remove-VeliqPolicyWatchdog $directory
if($script:stops -ne 1 -or $script:removes -ne 1){throw 'owned task not removed'}
$script:fixtureTask=[pscustomobject]@{Description='foreign';Actions=@();State='Ready'}
$rejected=$false;try{Remove-VeliqPolicyWatchdog $directory}catch{$rejected=$_.ToString().Contains('WATCHDOG_FOREIGN_TASK_PRESERVED')}
if(!$rejected -or $script:removes -ne 1){throw 'foreign task modified'}
Write-Host 'PASS isolated watchdog task contracts; no system mutation'
