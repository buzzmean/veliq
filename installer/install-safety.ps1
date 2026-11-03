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
function Get-VeliqTemporaryRoots { @([IO.Path]::GetTempPath(),(Join-Path $env:SystemRoot 'Temp')) }
function Read-VeliqFileVersion([string]$Path) { [Diagnostics.FileVersionInfo]::GetVersionInfo($Path) }
function Test-VeliqInnoCleanupDirectory([string]$Directory,[string]$ApplicationDirectory) {
 # Inno 6.4.3 queues its own clone and directory BEFORE InitializeUninstall.
 # This is housekeeping, not a replacement of application/Windows files.
 # Never exempt arbitrary TEMP deletes or any rename/replacement operation.
 if([IO.Path]::GetFileName($Directory) -notmatch '^iu-[a-z0-9]+\.tmp$'){return $false}
 $parent=[IO.Path]::GetDirectoryName($Directory)
 if(!(Test-Path -LiteralPath $parent -PathType Container)){return $false}
 $canonicalParent=(Get-Item -LiteralPath $parent -Force -ErrorAction Stop).FullName.TrimEnd('\')
 $trusted=$false
 foreach($temp in Get-VeliqTemporaryRoots){
  if((Test-Path -LiteralPath $temp -PathType Container) -and $canonicalParent -ieq (Get-Item -LiteralPath $temp -Force -ErrorAction Stop).FullName.TrimEnd('\')){$trusted=$true}
 }
 if(!$trusted -or !(Test-Path -LiteralPath $Directory -PathType Container)){return $false}
 foreach($path in @($parent,$Directory)){
  if((Get-Item -LiteralPath $path -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint){return $false}
 }
 $children=@(Get-ChildItem -LiteralPath $Directory -Force -ErrorAction Stop)
 if($children.Count -ne 1 -or $children[0].PSIsContainer -or $children[0].Name -ine '_unins.tmp' -or ($children[0].Attributes -band [IO.FileAttributes]::ReparsePoint)){return $false}
 $clone=$children[0].FullName
 $version=Read-VeliqFileVersion $clone
 if($version.FileDescription.Trim() -cne 'Setup/Uninstall' -or $version.ProductName.Trim() -cne 'VELIQ' -or $version.CompanyName.Trim() -cne 'VELIQ'){return $false}
 if($ApplicationDirectory){
  $original=Join-Path $ApplicationDirectory 'unins000.exe'
  if(Test-Path -LiteralPath $original -PathType Leaf){
   if((Get-FileHash -LiteralPath $clone).Hash -cne (Get-FileHash -LiteralPath $original).Hash){return $false}
  }
 }
 return $true
}
function Get-VeliqPendingFileEvidence($Value,[string]$ApplicationDirectory) {
 $items=@($Value);$required=$false;$cleanup=0
 if(!$items.Count -or @($items | Where-Object {![string]::IsNullOrWhiteSpace([string]$_)}).Count -eq 0){return @{required=$false;cleanup=0}}
 if($items.Count % 2){return @{required=$true;cleanup=0}}
 $deletes=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 for($i=0;$i -lt $items.Count;$i+=2){
  $source=[string]$items[$i];$destination=[string]$items[$i+1]
  if($destination -ne ''){$required=$true;continue}
  # Current Windows records MoveFileEx deletes with *1/*2 before the NT path.
  # Accept only the observed forms; all other prefixes stay blocking.
  if($source.StartsWith('*1\??\') -or $source.StartsWith('*2\??\')){$source=$source.Substring(2)}
  if($source.StartsWith('\??\')){$source=$source.Substring(4)}
  if($source -notmatch '^[a-zA-Z]:\\' -or $source.Split('\') -contains '..'){$required=$true;continue}
  [void]$deletes.Add($source.TrimEnd('\'))
 }
 foreach($path in $deletes){
  $directory=$path
  if([IO.Path]::GetFileName($path) -ieq '_unins.tmp'){$directory=[IO.Path]::GetDirectoryName($path)}
  if($deletes.Contains($directory) -and $deletes.Contains((Join-Path $directory '_unins.tmp')) -and (Test-VeliqInnoCleanupDirectory $directory $ApplicationDirectory)){$cleanup++}
  else{$required=$true}
 }
 return @{required=$required;cleanup=$cleanup}
}
function Get-VeliqRebootState([string]$ApplicationDirectory='') {
 $reasons=@();$cleanup=0
 try {
  foreach($pair in @(
   @('SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','CBS_REBOOT_PENDING'),
   @('SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired','WINDOWS_UPDATE_REBOOT_REQUIRED')
  )) {if(Read-VeliqRebootRegistry $pair[0]){$reasons+=,$pair[1]}}
  foreach($name in @('PendingFileRenameOperations','PendingFileRenameOperations2')){
   $value=Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\Session Manager' $name
   $pending=Get-VeliqPendingFileEvidence $value $ApplicationDirectory
   $cleanup+=$pending.cleanup
   if($pending.required){$reasons+=,$name.ToUpperInvariant()}
  }
  $volatile=Read-VeliqRebootRegistry 'SOFTWARE\Microsoft\Updates' 'UpdateExeVolatile'
  if($null -ne $volatile -and [int]$volatile -ne 0){$reasons+=,'UPDATE_EXE_VOLATILE'}
  $active=Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName'
  $pending=Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'
  if($active -and $pending -and $active -ine $pending){$reasons+=,'COMPUTER_RENAME_PENDING'}
  return [pscustomobject]@{known=$true;required=($reasons.Count -gt 0);reasons=$reasons;deferred_cleanup_count=$cleanup}
 }catch{
  # Unknown is never reported as false; registry values/paths are not exported.
  return [pscustomobject]@{known=$false;required=$null;reasons=@('REBOOT_STATE_UNAVAILABLE');deferred_cleanup_count=$null}
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
 Assert-VeliqNoPendingReboot (Get-VeliqRebootState $Directory)
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
 $record.deferred_cleanup_count=$Reboot.deferred_cleanup_count
 if($Code){$record.code=$Code}
 if($null -ne $Hashes){foreach($name in @('gui_sha256','service_sha256')){$record[$name]=$Hashes[$name]}}
 return $record
}
if($Preflight){
 $ErrorActionPreference='Stop'
 # Inno may inherit PS7's module search path. Resolve PS5.1 cmdlets only from
 # Windows/machine modules, as install-package.ps1 does for its own process.
 if($PSVersionTable.PSEdition -eq 'Desktop'){
  $env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')+';'+[Environment]::GetEnvironmentVariable('PSModulePath','Machine')
 }
 try{Assert-VeliqInstallPreflight $AppDirectory;exit 0}
 catch{
  $safe='INSTALL_PREFLIGHT_FAILED'
  if($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]{3,80}$'){$safe=$_.Exception.Message}
  Write-Output $safe
  if($safe -eq 'INSTALL_REBOOT_REQUIRED'){exit 3010}
  exit 1
 }
}
