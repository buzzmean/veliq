[CmdletBinding()]
param(
 [string]$ServiceExecutable=(Join-Path $PSScriptRoot '..\..\bin\windows-e2e\veliq-service.exe'),
 [string]$InstallDirectory="$env:ProgramData\VELIQ",
 [switch]$NativeTcpFirewall=$true
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'service-startup.ps1')
Assert-Administrator
. (Join-Path $PSScriptRoot 'native-tcp-firewall.ps1')
. (Join-Path $PSScriptRoot 'migrate-legacy-install.ps1')
[void](Move-VeliqLegacyInstall -Start)
function Assert-ServiceUpdateScmTarget([string]$CommandLine,[string]$ExpectedPath){
 $match=[regex]::Match($CommandLine,'^\s*"([^"]+)"(?:\s|$)')
 if(!$match.Success -or [IO.Path]::GetFullPath($match.Groups[1].Value) -ine [IO.Path]::GetFullPath($ExpectedPath)){throw 'SCM executable does not match the requested installation; update refused'}
}
$source=(Get-Item -LiteralPath $ServiceExecutable -Force).FullName
$root=(Get-Item -LiteralPath $InstallDirectory -Force).FullName
$target=Join-Path $root 'veliq-service.exe';$manifestFile=Join-Path $root 'service.json'
foreach($path in @($source,$root,$target,$manifestFile)){
 if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Service update refuses reparse points'}
}
if($source -ieq $target){throw 'Build source must differ from installed executable'}
$manifest=Get-Content -Raw -LiteralPath $manifestFile|ConvertFrom-Json
$owner=[Security.Principal.SecurityIdentifier]::new([string]$manifest.owner_sid)
$service=Get-Service -Name VELIQ -ErrorAction Stop
$scm=Get-CimInstance -ClassName Win32_Service -Filter "Name='VELIQ'" -OperationTimeoutSec 5
if($null -eq $scm){throw 'Installed SCM service not found'}
Assert-ServiceUpdateScmTarget ([string]$scm.PathName) $target
$oldStartMode=[string]$scm.StartMode
. (Join-Path $PSScriptRoot 'browser-policy-watchdog.ps1')
$ownedWatchdog=Get-VeliqPolicyWatchdog $InstallDirectory
$watchdogWasRunning=$null -ne $ownedWatchdog -and [string]$ownedWatchdog.State -eq 'Running'
$oldDisplayName=[string]$scm.DisplayName
$serviceProcess=[int]$scm.ProcessId
$watchdogProcessIds=@()
foreach($process in @(Get-Process -Name veliq-service -ErrorAction SilentlyContinue)){
 if($process.Path -ieq $target -and $process.Id -ne $serviceProcess){
  $watchdogProcess=Get-CimInstance Win32_Process -Filter ('ProcessId='+$process.Id) -OperationTimeoutSec 5
  $isOwnedWatchdog=$false
  if($watchdogWasRunning -and $null -ne $watchdogProcess -and [string]$watchdogProcess.CommandLine -like '* -browser-policy-watchdog -config *'){
   $principal=Invoke-CimMethod -InputObject $watchdogProcess -MethodName GetOwnerSid
   $isOwnedWatchdog=$principal.ReturnValue -eq 0 -and $principal.Sid -eq 'S-1-5-18'
  }
  if(!$isOwnedWatchdog){throw 'Close VELIQ (or legacy NeExitLag) GUI first: its owner-scoped recovery process still uses the installed binary'}
  $watchdogProcessIds+=$process.Id
 }
}
$backupRoot=Join-Path $root 'backups'
if(Test-Path -LiteralPath $backupRoot){if((Get-Item -LiteralPath $backupRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Backup directory is a reparse point'}}else{New-Item -ItemType Directory -Path $backupRoot|Out-Null}
$backup=Join-Path $backupRoot ('service-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $backup|Out-Null
$oldAcl=Get-Acl -LiteralPath $target
$oldAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)|Set-Content -LiteralPath (Join-Path $backup 'binary.sddl') -Encoding ASCII
Copy-Item -LiteralPath $target -Destination (Join-Path $backup 'veliq-service.exe')
function Set-BinaryOwnerReadExecute([string]$Path,[string]$OwnerSid){
 $binaryOwner=[Security.Principal.SecurityIdentifier]::new($OwnerSid)
 $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){[void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))}
 [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($binaryOwner,[Security.AccessControl.FileSystemRights]::ReadAndExecute,[Security.AccessControl.AccessControlType]::Allow))
 Set-Acl -LiteralPath $Path -AclObject $acl
}
$pending=Join-Path $root ('.service-update-'+[Guid]::NewGuid().ToString('N')+'.exe')
$stopped=$false;$replaced=$false;$nativeFirewallCreated=$false
try{
 if($watchdogWasRunning){
  Disable-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog'|Out-Null
  Stop-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog'
  foreach($watchdogId in $watchdogProcessIds){
   try{
    $process=[Diagnostics.Process]::GetProcessById($watchdogId)
    try{if($process.Path -ieq $target -and !$process.WaitForExit(30000)){throw 'INSTALL_WATCHDOG_CLOSE_TIMEOUT'}}finally{$process.Dispose()}
   }catch [ArgumentException]{}
  }
 }
 Copy-Item -LiteralPath $source -Destination $pending
 Set-BinaryOwnerReadExecute $pending $owner.Value
 Set-Service VELIQ -StartupType Disabled
 Stop-Service VELIQ
 $stopped=$true
 $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
 if($serviceProcess -gt 0){try{$process=[Diagnostics.Process]::GetProcessById($serviceProcess);if(!$process.WaitForExit(30000)){throw 'Stopped service process did not exit; executable not replaced'}}catch [ArgumentException]{} }
 [IO.File]::Replace($pending,$target,[NullString]::Value)
 $replaced=$true
 Set-BinaryOwnerReadExecute $target $owner.Value
 if((Get-FileHash -LiteralPath $target).Hash -ne (Get-FileHash -LiteralPath $source).Hash){throw 'Installed binary hash mismatch'}
 if($NativeTcpFirewall){$nativeFirewallCreated=Add-NativeTcpFirewallAdmission $target}
 Set-Service VELIQ -StartupType Manual
 Start-Service VELIQ
 $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
 $deadline=[DateTime]::UtcNow.AddSeconds(30);$ready=$false
 do{
  try{$status=Invoke-ServiceIPC 'status' $null (Join-Path $root 'ipc.token');$ready=$null -ne $status.PSObject.Properties['backend']}catch{$ready=$false}
  if(!$ready -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 300}
 }while(!$ready -and [DateTime]::UtcNow -lt $deadline)
 if(!$ready){throw 'Updated service IPC readiness failed'}
 Set-VeliqServiceAutomatic
 Set-Service -Name VELIQ -DisplayName 'VELIQ Routing Service'
 if($NativeTcpFirewall){Write-Host 'Native TCP firewall admission verified: this service executable only; no global firewall or VPS changes.'}
 foreach($lane in @('browser','edge')){try{$view=Invoke-ServiceIPC ($lane+'.status') $null (Join-Path $root 'ipc.token');$silent=$view.PSObject.Properties['silent_activation'];if($null -ne $silent){$state=[string]$silent.Value.state;if($state -notin @('NOT_CONFIGURED','POLICY_PENDING_BROWSER_REFRESH','PAC_REQUEST_OBSERVED','POLICY_OR_LISTENER_UNAVAILABLE','POLICY_SUSPENDED')){$state='UNKNOWN'};Write-Host ($lane+' silent PAC: '+$state+'; browser processes untouched; effective uptake separate from update success')}}catch{Write-Host ($lane+' silent PAC: STATUS_UNAVAILABLE; no website PASS claimed')}}
 Install-VeliqPolicyWatchdog $InstallDirectory
 Write-Host "VELIQ Windows service and independent policy watchdog updated. Backup: $backup"
 Write-Host 'Only service executable ACL changed: owner RX, SYSTEM/admins F. Identity, credentials, driver and state ACLs preserved.'
}catch{
 $failure=$_.Exception.Message
 if(Get-Command Write-VeliqInstallDiagnostic -ErrorAction SilentlyContinue){
  try{
   $failedState=Get-CimInstance Win32_Service -Filter "Name='VELIQ'" -OperationTimeoutSec 5
   Write-VeliqInstallDiagnostic 'SERVICE_UPDATE_ERROR' @{scm_state=[string]$failedState.State;scm_exit_code=[int]$failedState.ExitCode;binary_replaced=$replaced}
  }catch{Write-Host 'INSTALL_SERVICE_ERROR_DIAGNOSTICS_UNAVAILABLE; rollback continues'}
 }
 try{if($null -eq $ownedWatchdog){Remove-VeliqPolicyWatchdog $InstallDirectory}else{Stop-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog' -ErrorAction SilentlyContinue}}catch{Write-Host 'WATCHDOG_ROLLBACK_CLEANUP_FAILED; task/backup preserved for review'}
 $firewallRollbackError=$false
 if($nativeFirewallCreated){try{Remove-NativeTcpFirewallAdmission $target}catch{$firewallRollbackError=$true}}
 if(!$replaced){
  Restore-VeliqServiceStartup $oldStartMode
  if($stopped){try{if($oldStartMode -eq 'Disabled'){Set-Service VELIQ -StartupType Manual};Start-Service VELIQ;$service.WaitForStatus('Running',[TimeSpan]::FromSeconds(30));Restore-VeliqServiceStartup $oldStartMode}catch{throw "Executable was not replaced; previous service could not restart. Backup: $backup"}}
  throw "Windows update refused before replacement; previous binary/ACL retained: $failure. Backup: $backup"
 }
 try{
  $failedService=Get-CimInstance -ClassName Win32_Service -Filter "Name='VELIQ'" -OperationTimeoutSec 5
  Stop-Service VELIQ -ErrorAction SilentlyContinue
  $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
  if($null -ne $failedService -and $failedService.ProcessId -gt 0){try{$failedProcess=[Diagnostics.Process]::GetProcessById([int]$failedService.ProcessId);if(!$failedProcess.WaitForExit(30000)){throw 'Failed service image still running; backup retained'}}catch [ArgumentException]{} }
  Copy-Item -LiteralPath (Join-Path $backup 'veliq-service.exe') -Destination $target -Force
  Set-Acl -LiteralPath $target -AclObject $oldAcl
  Restore-VeliqServiceStartup $oldStartMode
  Set-Service -Name VELIQ -DisplayName $oldDisplayName
  Start-Service VELIQ
  $service.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
 }catch{throw "Windows update failed ($failure); automatic binary rollback failed. Backup retained: $backup"}
 if($firewallRollbackError){throw "Windows update failed; previous binary/ACL restored, but owned native firewall rule cleanup failed. Backup: $backup"}
 throw "Windows update failed; previous binary/ACL restored: $failure. Backup: $backup"
}finally{if(Test-Path -LiteralPath $pending){Remove-Item -LiteralPath $pending -Force};if($watchdogWasRunning){Enable-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog'|Out-Null;Start-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog'}}
