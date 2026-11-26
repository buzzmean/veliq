$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$script:startup='Manual';$script:fail=$false
function Set-Service {param($Name,$StartupType)if($Name -ne 'VELIQ'){throw 'wrong SCM name'};$script:startup=[string]$StartupType}
function Get-CimInstance {param($ClassName,$Filter,$OperationTimeoutSec)if($script:fail){return $null};return [pscustomobject]@{StartMode=$(if($script:startup -eq 'Automatic'){'Auto'}else{$script:startup})}}
. (Join-Path $PSScriptRoot '../../tools/windows/service-startup.ps1')
Set-VeliqServiceAutomatic
if($script:startup -ne 'Automatic'){throw 'Manual update did not restore Automatic'}
Restore-VeliqServiceStartup 'Manual'
if($script:startup -ne 'Manual'){throw 'rollback did not preserve original startup'}
$script:fail=$true;$refused=$false;try{Set-VeliqServiceAutomatic}catch{$refused=$_.Exception.Message -eq 'SERVICE_AUTOSTART_NOT_CONFIRMED'}
if(!$refused){throw 'unverified SCM state accepted'}
$script:scCalls=@();$script:scFailure=''
function sc.exe {
 $script:scCalls+=,@($args)
 $global:LASTEXITCODE=if($args[0] -ceq $script:scFailure){5}else{0}
}
Set-VeliqServiceRecovery
if($script:scCalls.Count -ne 2 -or ($script:scCalls[0] -join '|') -cne 'failure|VELIQ|reset=|86400|actions=|restart/5000/restart/5000/restart/5000' -or ($script:scCalls[1] -join '|') -cne 'failureflag|VELIQ|1'){throw 'service recovery policy was not configured'}
$script:scCalls=@();$script:scFailure='failure';$refused=$false
try{Set-VeliqServiceRecovery}catch{$refused=$_.Exception.Message -ceq 'SERVICE_RECOVERY_ACTIONS_FAILED'}
if(!$refused -or $script:scCalls.Count -ne 1){throw 'failed recovery actions were accepted or failure flag changed afterward'}
$script:scCalls=@();$script:scFailure='failureflag';$refused=$false
try{Set-VeliqServiceRecovery}catch{$refused=$_.Exception.Message -ceq 'SERVICE_RECOVERY_FLAG_FAILED'}
if(!$refused -or $script:scCalls.Count -ne 2){throw 'failed recovery flag was accepted'}
$global:LASTEXITCODE=0
Write-Host 'PASS isolated Automatic startup, rollback and checked recovery actions/flag; no SCM mutation'
