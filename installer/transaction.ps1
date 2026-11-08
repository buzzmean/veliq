[CmdletBinding()]
param([ValidateSet('Prepare','Rollback','Commit')][string]$Action,
 [string]$AppDirectory,[string]$TransactionDirectory,[string]$DiagnosticFile)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'install-safety.ps1') -DiagnosticFile $DiagnosticFile -AppDirectory $AppDirectory
$app=[IO.Path]::GetFullPath($AppDirectory).TrimEnd('\')
$transaction=[IO.Path]::GetFullPath($TransactionDirectory).TrimEnd('\')
$serviceRoot=Join-Path $env:ProgramData 'VELIQ'
$recordPath=Join-Path $transaction 'transaction.json'
$names=@('VELIQ.exe','package.json','service','gui','tools','installer','public','driver','unins000.exe','unins000.dat','unins000.msg')
$uninstallKey='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{E18D91DB-2E64-4405-A05E-AB15A4192318}_is1'
$regKey='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{E18D91DB-2E64-4405-A05E-AB15A4192318}_is1'
$shortcuts=@((Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'VELIQ.lnk'),(Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'VELIQ.lnk'))
function Assert-TransactionParents([string]$Path) {
 $current=$Path
 while($current){
  if(Test-Path -LiteralPath $current){
   if((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'INSTALL_REPARSE_POINT_REJECTED'}
  }
  $current=[IO.Path]::GetDirectoryName($current)
 }
}
function Assert-TransactionTree([string]$Path) {
 if(!(Test-Path -LiteralPath $Path)){return}
 $item=Get-Item -LiteralPath $Path -Force
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'INSTALL_REPARSE_POINT_REJECTED'}
 if($item.PSIsContainer){foreach($child in Get-ChildItem -LiteralPath $Path -Force){Assert-TransactionTree $child.FullName}}
}
function Protect-TransactionDirectory([string]$Path) {
 [void][IO.Directory]::CreateDirectory($Path)
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 foreach($sid in @('S-1-5-18','S-1-5-32-544')){
  $identity=[Security.Principal.SecurityIdentifier]::new($sid)
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
 }
 Set-Acl -LiteralPath $Path -AclObject $acl
}
function Get-OwnedService {
 $scm=Get-CimInstance Win32_Service -Filter "Name='VELIQ'" -OperationTimeoutSec 5
 if(!$scm){return $null}
 $target=Join-Path $serviceRoot 'veliq-service.exe'
 if([string]$scm.PathName -notmatch '^"([^"]+)"' -or $Matches[1] -ine $target){throw 'INSTALL_FOREIGN_SERVICE_REFUSED'}
 return $scm
}
function Stop-OwnedGui {
 $paths=@((Join-Path $app 'VELIQ.exe'))
 if($env:LOCALAPPDATA){$paths+=Join-Path $env:LOCALAPPDATA 'Programs\VELIQ\VELIQ.exe'}
 $owners=@{}
 foreach($process in @(Get-CimInstance Win32_Process -Filter "Name='VELIQ.exe' OR Name='NeExitLag.exe'" -OperationTimeoutSec 5)){
  if([string]$process.ExecutablePath -notin $paths){continue}
  $owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
  if($owner.ReturnValue -ne 0 -or !$owner.Sid){throw 'INSTALL_GUI_OWNER_UNAVAILABLE'}
  $key=$owner.Sid+'-'+$process.SessionId
  $owners[$key]=@{sid=$owner.Sid;session=$process.SessionId;path=$process.ExecutablePath}
  if($Action -eq 'Prepare'){$record.gui=@($owners.Values);$record|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $recordPath -Encoding UTF8}
  $pipe=[IO.Pipes.NamedPipeClientStream]::new('.','NeExitLag-activate-'+$key,[IO.Pipes.PipeDirection]::Out)
  try{$pipe.Connect(1500);$pipe.WriteByte(2)}catch{throw 'INSTALL_GUI_GRACEFUL_CLOSE_FAILED'}finally{$pipe.Dispose()}
  try{
   $native=[Diagnostics.Process]::GetProcessById([int]$process.ProcessId)
   try{if(!$native.WaitForExit(15000)){throw 'INSTALL_GUI_CLOSE_TIMEOUT'}}finally{$native.Dispose()}
  }catch [ArgumentException]{}
  Write-VeliqInstallDiagnostic 'GUI_STOPPED' @{pid=$process.ProcessId;path=$process.ExecutablePath}
 }
 # Owner-scoped recovery helpers should leave after their GUI. Never kill by name.
 foreach($process in @(Get-Process -Name veliq-service -ErrorAction SilentlyContinue)){
  try{
   if($process.Path -ieq (Join-Path $serviceRoot 'veliq-service.exe')){
    $scm=Get-OwnedService
    if($scm -and $process.Id -eq $scm.ProcessId){continue}
    $details=Get-CimInstance Win32_Process -Filter ('ProcessId='+$process.Id)
    if([string]$details.CommandLine -like '* -browser-policy-watchdog -config *'){continue}
    if(!$process.WaitForExit(15000)){throw 'INSTALL_RECOVERY_HELPER_CLOSE_TIMEOUT'}
   }
  }finally{$process.Dispose()}
 }
 return @($owners.Values)
}
function Resume-OwnedGui($Record) {
 foreach($gui in @($Record.gui)){
  $path=Join-Path $app 'VELIQ.exe';if(!(Test-Path -LiteralPath $path)){$path=[string]$gui.path}
  if(!(Test-Path -LiteralPath $path)){throw 'INSTALL_GUI_RESTORE_MISSING'}
  $name='VELIQ-Setup-Resume-'+[guid]::NewGuid().ToString('N')
  $principal=New-ScheduledTaskPrincipal -UserId $gui.sid -LogonType Interactive -RunLevel Limited
  $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
  $action=New-ScheduledTaskAction -Execute $path
  try{
   Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings|Out-Null
   Start-ScheduledTask -TaskName $name
   $deadline=[DateTime]::UtcNow.AddSeconds(15);$ready=$false
   do{
    foreach($p in @(Get-CimInstance Win32_Process -Filter "Name='VELIQ.exe'")){
     if($p.ExecutablePath -ieq $path -and $p.SessionId -eq $gui.session){$ready=$true}
    }
    if(!$ready){Start-Sleep -Milliseconds 300}
   }while(!$ready -and [DateTime]::UtcNow -lt $deadline)
   if(!$ready){throw 'INSTALL_GUI_RESTORE_FAILED'}
   Write-VeliqInstallDiagnostic 'GUI_RESUMED' @{path=$path;session=$gui.session}
  }finally{Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue}
 }
}
try{
 Assert-TransactionParents $transaction
 Assert-TransactionParents $app
 Assert-TransactionParents $serviceRoot
 if($Action -eq 'Prepare'){
  Assert-VeliqNoPendingReboot (Get-VeliqInstallRebootState $app)
  foreach($name in $names){Assert-TransactionTree (Join-Path $app $name)}
  $scm=Get-OwnedService
  Assert-TransactionTree $serviceRoot
  if(Test-Path -LiteralPath $recordPath){throw 'INSTALL_TRANSACTION_ALREADY_PREPARED'}
  Protect-TransactionDirectory $transaction
  $snapshot=Join-Path $transaction 'payload';[void][IO.Directory]::CreateDirectory($snapshot)
  $record=@{app=$app;service_existed=($null -ne $scm);service_running=($null -ne $scm -and $scm.State -eq 'Running');start_mode=if($scm){$scm.StartMode}else{''};gui=@();phase='PREPARING';uninstall_key_existed=(Test-Path -LiteralPath $uninstallKey)}
  $record|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $recordPath -Encoding UTF8
  $record.gui=@(Stop-OwnedGui)
  $record|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $recordPath -Encoding UTF8
  Assert-VeliqInstallPreflight $app
  if($record.uninstall_key_existed){
   $registered=Get-ItemProperty -LiteralPath $uninstallKey
   if($registered.DisplayName -notlike 'VELIQ*' -or [string]$registered.InstallLocation -ine ($app+'\')){throw 'INSTALL_FOREIGN_UNINSTALL_KEY'}
   & reg.exe export $regKey (Join-Path $transaction 'uninstall.reg') /y|Out-Null
   if($LASTEXITCODE){throw 'INSTALL_REGISTRY_BACKUP_FAILED'}
  }
  for($i=0;$i -lt $shortcuts.Count;$i++){if(Test-Path -LiteralPath $shortcuts[$i]){Copy-Item -LiteralPath $shortcuts[$i] -Destination (Join-Path $transaction ('shortcut-'+$i+'.lnk'))}}
  foreach($name in $names){$path=Join-Path $app $name;if(Test-Path -LiteralPath $path){Copy-Item -LiteralPath $path -Destination $snapshot -Recurse}}
  if($scm){
   $binary=Join-Path $serviceRoot 'veliq-service.exe'
   Copy-Item -LiteralPath $binary -Destination (Join-Path $transaction 'service.exe')
   (Get-Acl -LiteralPath $binary).Sddl|Set-Content (Join-Path $transaction 'service.sddl') -Encoding ASCII
  }
  $record.phase='PREPARED';$record|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $recordPath -Encoding UTF8
  Write-VeliqInstallDiagnostic 'TRANSACTION_PREPARED' @{service_existed=$record.service_existed;gui_count=$record.gui.Count}
 }elseif($Action -eq 'Rollback'){
  if(!(Test-Path -LiteralPath $recordPath)){exit 0}
  $record=Get-Content -Raw -LiteralPath $recordPath|ConvertFrom-Json
  if($record.app -ine $app){throw 'INSTALL_TRANSACTION_TARGET_MISMATCH'}
  if($record.phase -eq 'PREPARED'){
   $null=Stop-OwnedGui
   $scm=Get-OwnedService
   if(!$record.service_existed -and $scm){
    & (Join-Path $app 'tools\windows\uninstall.ps1') -InstallDirectory $serviceRoot
    . (Join-Path $app 'tools\windows\native-tcp-firewall.ps1')
    Remove-NativeTcpFirewallAdmission (Join-Path $serviceRoot 'veliq-service.exe')
    $scm=$null
   }
   if($scm){
    Set-Service VELIQ -StartupType Disabled
    Stop-Service VELIQ -ErrorAction Stop
    (Get-Service VELIQ).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    if($scm.ProcessId -gt 0){try{$p=[Diagnostics.Process]::GetProcessById([int]$scm.ProcessId);try{if(!$p.WaitForExit(30000)){throw 'INSTALL_ROLLBACK_SERVICE_BUSY'}}finally{$p.Dispose()}}catch [ArgumentException]{}}
   }
   foreach($name in $names){
    $path=Join-Path $app $name
    if(!$path.StartsWith($app+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'INSTALL_TRANSACTION_TARGET_MISMATCH'}
    Assert-TransactionTree $path
    if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force}
    $old=Join-Path (Join-Path $transaction 'payload') $name
    if(Test-Path -LiteralPath $old){Copy-Item -LiteralPath $old -Destination $app -Recurse -Force}
   }
   if($record.uninstall_key_existed){
    & reg.exe import (Join-Path $transaction 'uninstall.reg')|Out-Null
    if($LASTEXITCODE){throw 'INSTALL_REGISTRY_RESTORE_FAILED'}
   }elseif(Test-Path -LiteralPath $uninstallKey){
    $registered=Get-ItemProperty -LiteralPath $uninstallKey
    if($registered.DisplayName -notlike 'VELIQ*' -or [string]$registered.InstallLocation -ine ($app+'\')){throw 'INSTALL_FOREIGN_UNINSTALL_KEY'}
    Remove-Item -LiteralPath $uninstallKey -Recurse -Force
   }
   for($i=0;$i -lt $shortcuts.Count;$i++){
    $backup=Join-Path $transaction ('shortcut-'+$i+'.lnk')
    if(Test-Path -LiteralPath $backup){Copy-Item -LiteralPath $backup -Destination $shortcuts[$i] -Force}
    elseif(Test-Path -LiteralPath $shortcuts[$i]){
     $shell=New-Object -ComObject WScript.Shell
     if($shell.CreateShortcut($shortcuts[$i]).TargetPath -ieq (Join-Path $app 'VELIQ.exe')){Remove-Item -LiteralPath $shortcuts[$i] -Force}
    }
   }
   if($record.service_existed){
    $binary=Join-Path $serviceRoot 'veliq-service.exe';Copy-Item -LiteralPath (Join-Path $transaction 'service.exe') -Destination $binary -Force
    $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm([IO.File]::ReadAllText((Join-Path $transaction 'service.sddl')).Trim());Set-Acl -LiteralPath $binary -AclObject $acl
    $mode=switch($record.start_mode){'Auto'{'Automatic'}'Manual'{'Manual'}'Disabled'{'Disabled'}default{throw 'INSTALL_ROLLBACK_START_MODE_INVALID'}}
    Set-Service VELIQ -StartupType $mode
    if($record.service_running){
     Set-Service VELIQ -StartupType Manual;Start-Service VELIQ;(Get-Service VELIQ).WaitForStatus('Running',[TimeSpan]::FromSeconds(30));Set-Service VELIQ -StartupType $mode
     . (Join-Path $app 'tools\windows\common.ps1')
     $status=Invoke-ServiceIPC 'status' $null (Join-Path $serviceRoot 'ipc.token')
     if(!$status.PSObject.Properties['backend']){throw 'INSTALL_ROLLBACK_IPC_FAILED'}
    }
   }elseif($scm){
    & sc.exe delete VELIQ|Out-Null;if($LASTEXITCODE){throw 'INSTALL_ROLLBACK_SCM_FAILED'}
   }
  }
  Remove-Item -LiteralPath (Join-Path $app 'install-success.json') -Force -ErrorAction SilentlyContinue
  Resume-OwnedGui $record
  Write-VeliqInstallDiagnostic 'TRANSACTION_ROLLED_BACK' @{payload_restored=($record.phase -eq 'PREPARED');service_restored=[bool]$record.service_existed}
 }elseif($Action -eq 'Commit'){
  if(!(Test-Path -LiteralPath (Join-Path $app 'install-success.json'))){throw 'INSTALL_TRANSACTION_SUCCESS_MISSING'}
  $record=Get-Content -Raw -LiteralPath $recordPath|ConvertFrom-Json
  Resume-OwnedGui $record
  $record.phase='COMMITTED';$record|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $recordPath -Encoding UTF8
  Write-VeliqInstallDiagnostic 'TRANSACTION_COMMITTED' @{result='COMPLETED'}
 }
 exit 0
}catch{
 $code='INSTALL_TRANSACTION_FAILED';if($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]{3,80}$'){$code=$_.Exception.Message}
 Write-VeliqInstallDiagnostic 'TRANSACTION_ERROR' @{action=$Action;code=$code}
 Write-Output $code
 if($code -eq 'INSTALL_REBOOT_REQUIRED'){exit 20}
 exit 1
}
