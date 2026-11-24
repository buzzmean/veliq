# Native, read-only regressions. Registry inputs are replaced in this scope.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../installer/install-safety.ps1')
$script:values=@{};$script:denied=$false
function Read-VeliqRebootRegistry([string]$Path,[string]$Name=''){
 if($script:denied){throw 'fixture denied'}
 return $script:values[$Path+'|'+$Name]
}
function Check($Condition,[string]$Message){if(!$Condition){throw $Message}}
$app=Join-Path $env:ProgramFiles 'VELIQ';$key='SYSTEM\CurrentControlSet\Control\Session Manager|PendingFileRenameOperations'
$queue=@('*1\??\C:\Windows\Temp\INS_b057091b.TMP','',('*1\??\'+$env:LOCALAPPDATA+'\Temp\nsxA794.tmp\nsProcess.dll'),'',('*1\??\'+$env:LOCALAPPDATA+'\Temp\nsxA794.tmp'),'')
$script:values[$key]=$queue
$before=$queue -join "`0"
$state=Get-VeliqInstallRebootState $app
Check ($state.known -and !$state.required -and $state.windows_reboot_pending) 'observed unrelated queue must not block'
Check (($script:values[$key] -join "`0") -ceq $before) 'classifier changed queue'
# EdgeUpdate's combined destination prefix must classify as unrelated without
# clearing the queue. The same spelling targeting VELIQ must still block.
foreach($prefix in @('\??\','!\??\','*1\??\','*2\??\','*1!\??\','*2!\??\','!*1\??\','!*2\??\')){
 foreach($destination in @((Join-Path $env:ProgramData 'Microsoft\EdgeUpdate\Log\MicrosoftEdgeUpdate.log.bak'),(Join-Path $app 'VELIQ.exe'))){
  $script:values=@{};$script:values[$key]=@(('\??\'+(Join-Path $env:ProgramData 'Microsoft\EdgeUpdate\Log\MicrosoftEdgeUpdate.log')),($prefix+$destination))
  $before=$script:values[$key] -join "`0"
  $state=Get-VeliqInstallRebootState $app
  Check ($state.known -and $state.required -eq ($destination -like ($app+'\*'))) 'combined prefix lost pending-operation scope'
  Check ($state.pending_operations[0].destination -ieq $destination) 'combined prefix resolved to a different destination'
  Check (($script:values[$key] -join "`0") -ceq $before) 'combined prefix classification changed queue'
 }
}
foreach($pair in @(
 @((Join-Path $app 'VELIQ.exe'),''),
 @('C:\Windows\Temp\new.exe',(Join-Path $app 'VELIQ.exe')),
 @((Join-Path $env:ProgramData 'VELIQ\veliq-service.exe'),''),
 @((Join-Path $env:ProgramData 'neexitlag\driver\WinDivert64.sys'),''),
 @('C:\Windows\System32\drivers\WinDivert64.sys',''),
 @($env:ProgramFiles,'')
)){
 $script:values=@{};$script:values[$key]=$pair
 $state=Get-VeliqInstallRebootState $app
 Check ($state.known -and $state.required) 'related source/destination/ancestor or driver accepted'
}
foreach($pair in @(@('C:\Windows\Temp\external.tmp',''),@('C:\Windows\Temp\source.tmp','C:\Windows\Temp\dest.tmp'))){
 $script:values=@{};$script:values[$key]=$pair
 Check (!(Get-VeliqInstallRebootState $app).required) 'external operation blocked'
}
foreach($bad in @(@('C:\only-source'),@('*3\??\C:\unknown',''),@('relative',''),@('C:\bad:stream',''),
 @('*3!\??\C:\unknown',''),@('*1!!\??\C:\unknown',''),@('!!\??\C:\unknown',''),@('*1\??\*1\??\C:\unknown',''),
 @('*1!\??\relative',''),@('*1!\??\UNC\server\share',''),@('*1!\??\C:\bad:stream',''),
 @('*1!\??\C:\bad?name',''),@('*1!\??\C:\bad\..\name',''),@('*1C:\unknown',''))){
 $script:values=@{};$script:values[$key]=$bad
 Check (!(Get-VeliqInstallRebootState $app).known) 'unresolved queue accepted'
}
$script:values=@{'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired|'=$true}
$state=Get-VeliqInstallRebootState $app
Check ($state.known -and !$state.required -and $state.windows_reboot_pending) 'Windows update incorrectly becomes VELIQ requirement'
$script:values=@{'SYSTEM\CurrentControlSet\Services\VELIQ|DeleteFlag'=1}
Check ((Get-VeliqInstallRebootState $app).required) 'service pending deletion accepted'
$script:denied=$true
Check (!(Get-VeliqInstallRebootState $app).known) 'unreadable registry accepted'
Write-Output 'PASS scoped pending operations: nsProcess cleanup, combined EdgeUpdate rename prefixes, VELIQ source/destination/ancestor, driver, service deletion, malformed/unknown queues; no registry mutation'
