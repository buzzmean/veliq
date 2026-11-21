# Product installation/update restores boot start; rollback preserves old mode.
function Set-VeliqServiceAutomatic {
 Set-Service -Name VELIQ -StartupType Automatic
 $state=Get-CimInstance -ClassName Win32_Service -Filter "Name='VELIQ'" -OperationTimeoutSec 5
 if($null -eq $state -or [string]$state.StartMode -ne 'Auto'){throw 'SERVICE_AUTOSTART_NOT_CONFIRMED'}
}
function Restore-VeliqServiceStartup([string]$StartMode){
 $startup=switch($StartMode){'Auto'{'Automatic'} 'Manual'{'Manual'} 'Disabled'{'Disabled'} default {throw 'SERVICE_STARTUP_BACKUP_INVALID'}}
 Set-Service -Name VELIQ -StartupType $startup
}
