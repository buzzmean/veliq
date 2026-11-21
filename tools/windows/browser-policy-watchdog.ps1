# Independent local-only SYSTEM watchdog. No browser termination, enrollment or SSH.
Set-StrictMode -Version Latest
function Get-VeliqPolicyWatchdog([string]$InstallDirectory){
 $name='VELIQ-BrowserPolicyWatchdog';$task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
 if($task){
  $expected=[IO.Path]::GetFullPath((Join-Path $InstallDirectory 'veliq-service.exe'))
  if($task.Description -cne 'VELIQ_OWNED_POLICY_WATCHDOG_V1' -or @($task.Actions).Count -ne 1 -or [IO.Path]::GetFullPath([string]$task.Actions[0].Execute) -ine $expected -or [string]$task.Actions[0].Arguments -cne ('-browser-policy-watchdog -config "'+[IO.Path]::GetFullPath((Join-Path $InstallDirectory 'service.json'))+'"')){
   throw 'WATCHDOG_FOREIGN_TASK_PRESERVED'
  }
 }
 return $task
}
function Install-VeliqPolicyWatchdog([string]$InstallDirectory){
 $old=Get-VeliqPolicyWatchdog $InstallDirectory
 & sc.exe failureflag VELIQ 1|Out-Null
 if($LASTEXITCODE){throw 'WATCHDOG_SCM_RECOVERY_FLAG_FAILED'}
 $binary=[IO.Path]::GetFullPath((Join-Path $InstallDirectory 'veliq-service.exe'))
 $manifest=[IO.Path]::GetFullPath((Join-Path $InstallDirectory 'service.json'))
 $action=New-ScheduledTaskAction -Execute $binary -Argument ('-browser-policy-watchdog -config "'+$manifest+'"')
 $triggers=@((New-ScheduledTaskTrigger -AtStartup),(New-ScheduledTaskTrigger -AtLogOn))
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval ([TimeSpan]::FromMinutes(1)) -StartWhenAvailable -MultipleInstances IgnoreNew
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 try {
  Register-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog' -Description 'VELIQ_OWNED_POLICY_WATCHDOG_V1' -Action $action -Trigger $triggers -Settings $settings -Principal $principal -Force|Out-Null
  Start-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog'
 }catch{
  if(!$old){Unregister-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog' -Confirm:$false -ErrorAction SilentlyContinue}
  throw 'WATCHDOG_INSTALL_FAILED'
 }
}
function Remove-VeliqPolicyWatchdog([string]$InstallDirectory){
 if(Get-VeliqPolicyWatchdog $InstallDirectory){
  Stop-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog' -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog' -Confirm:$false
 }
}
