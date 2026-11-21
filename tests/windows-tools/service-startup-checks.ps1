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
Write-Host 'PASS isolated Automatic startup and rollback; no SCM mutation'
