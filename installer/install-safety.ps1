# Read-only preflight and verification. Dot-sourcing defines functions only.
[CmdletBinding()]
param([switch]$Preflight,[string]$AppDirectory='')

function Read-VeliqRebootRegistry([string]$Path,[string]$Name='') {
 $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
 try {
  $key=$base.OpenSubKey($Path,$false)
  if($null -eq $key){return $null}
  try {
   if(!$Name){return $true}
   return $key.GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  }finally{$key.Dispose()}
 }finally{$base.Dispose()}
}
function Get-VeliqRebootState {
 $reasons=@()
 try {
  foreach($pair in @(
   @('SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','CBS_REBOOT_PENDING'),
   @('SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired','WINDOWS_UPDATE_REBOOT_REQUIRED')
  )) {if(Read-VeliqRebootRegistry $pair[0]){$reasons+=,$pair[1]}}
  foreach($name in @('PendingFileRenameOperations','PendingFileRenameOperations2')){
   $value=Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\Session Manager' $name
   if(@($value | Where-Object {![string]::IsNullOrWhiteSpace([string]$_)}).Count){$reasons+=,$name.ToUpperInvariant()}
  }
  $volatile=Read-VeliqRebootRegistry 'SOFTWARE\Microsoft\Updates' 'UpdateExeVolatile'
  if($null -ne $volatile -and [int]$volatile -ne 0){$reasons+=,'UPDATE_EXE_VOLATILE'}
  $active=Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName'
  $pending=Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'
  if($active -and $pending -and $active -ine $pending){$reasons+=,'COMPUTER_RENAME_PENDING'}
  return [pscustomobject]@{known=$true;required=($reasons.Count -gt 0);reasons=$reasons}
 }catch{
  # Unknown is never reported as false; registry values/paths are not exported.
  return [pscustomobject]@{known=$false;required=$null;reasons=@('REBOOT_STATE_UNAVAILABLE')}
 }
}
function Assert-VeliqNoPendingReboot($State) {
 if(!$State.known){throw 'INSTALL_REBOOT_STATE_UNKNOWN'}
 if($State.required){throw 'INSTALL_REBOOT_REQUIRED'}
}
function Assert-VeliqReplaceableFile([string]$Path) {
 if(!(Test-Path -LiteralPath $Path)){return}
 $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'INSTALL_REPARSE_POINT_REJECTED'}
 try{
  # Opening existing bytes does not modify them. A mapped/running EXE or an
  # incompatible sharing handle must fail before Inno deletes/copies payload.
  $stream=[IO.File]::Open($item.FullName,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  $stream.Dispose()
 }catch{throw 'INSTALL_FILE_IN_USE_OR_NOT_WRITABLE'}
}
function Assert-VeliqInstallPreflight([string]$Directory) {
 Assert-VeliqNoPendingReboot (Get-VeliqRebootState)
 if(!$Directory -or ![IO.Path]::IsPathRooted($Directory)){throw 'INSTALL_PREFLIGHT_PATH_INVALID'}
 if(!(Test-Path -LiteralPath $Directory)){return}
 $root=Get-Item -LiteralPath $Directory -Force -ErrorAction Stop
 if(!$root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'INSTALL_REPARSE_POINT_REJECTED'}
 Assert-VeliqReplaceableFile (Join-Path $Directory 'VELIQ.exe')
 # Check exactly the directories replaced by Setup [InstallDelete]. Walk one
 # level at a time so a reparse point is rejected before following it.
 $queue=@(foreach($name in @('service','gui','tools','installer','public','driver')){Join-Path $Directory $name})
 while($queue.Count){
  $path=$queue[0];$queue=@($queue | Select-Object -Skip 1)
  if(!(Test-Path -LiteralPath $path)){continue}
  $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'INSTALL_REPARSE_POINT_REJECTED'}
  if($item.PSIsContainer){$queue+=@(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop | ForEach-Object {$_.FullName})}
  else{Assert-VeliqReplaceableFile $path}
 }
}
function Assert-VeliqInstalledBinaries([string]$Root,[string]$ServiceDirectory) {
 $hashes=@{}
 foreach($pair in @(@('gui','gui\VELIQ.exe',(Join-Path $Root 'VELIQ.exe')),@('service','service\veliq-service.exe',(Join-Path $ServiceDirectory 'veliq-service.exe')))){
  $failure='INSTALL_'+$pair[0].ToUpperInvariant()+'_HASH_MISMATCH'
  if(!(Test-Path -LiteralPath $pair[2] -PathType Leaf)){throw $failure}
  if((Get-Item -LiteralPath $pair[2] -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'INSTALL_REPARSE_POINT_REJECTED'}
  $expected=(Get-FileHash -LiteralPath (Join-Path $Root $pair[1]) -Algorithm SHA256).Hash
  $actual=(Get-FileHash -LiteralPath $pair[2] -Algorithm SHA256).Hash
  if($actual -ine $expected){throw $failure}
  $hashes[$pair[0]+'_sha256']=$actual.ToLowerInvariant()
 }
 return $hashes
}
function New-VeliqInstallResult([string]$Result,[string]$Step,$Reboot,[string]$Code='',$Hashes=$null) {
 if($Result -eq 'PASS'){Assert-VeliqNoPendingReboot $Reboot}
 $record=[ordered]@{result=$Result;step=$Step;reboot_required=$Reboot.required;reboot_check_known=$Reboot.known;reboot_reasons=@($Reboot.reasons);checked_at=[DateTime]::UtcNow.ToString('o');browser_processes='UNTOUCHED';credentials='PRESERVED'}
 if($Code){$record.code=$Code}
 if($null -ne $Hashes){foreach($name in @('gui_sha256','service_sha256')){$record[$name]=$Hashes[$name]}}
 return $record
}
if($Preflight){
 $ErrorActionPreference='Stop'
 try{Assert-VeliqInstallPreflight $AppDirectory;exit 0}
 catch{
  $safe='INSTALL_PREFLIGHT_FAILED'
  if($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]{3,80}$'){$safe=$_.Exception.Message}
  Write-Output $safe
  if($safe -eq 'INSTALL_REBOOT_REQUIRED'){exit 3010}
  exit 1
 }
}
