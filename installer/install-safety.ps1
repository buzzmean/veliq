# Read-only preflight and verification. Dot-sourcing defines functions only.
[CmdletBinding()]
param([switch]$Preflight,[string]$AppDirectory='',[string]$DiagnosticFile='')
$script:DiagnosticFile=$DiagnosticFile
. (Join-Path $PSScriptRoot 'install-scope.ps1')

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
function Get-VeliqGamingCleanupHash {
 # Exact bytes of the verified Microsoft Gaming Services Proxy 10.0.26100.8569.
 # The package, active System32 copy and retired copy matched this digest.
 # Never derive this trust anchor from the machine's current files or metadata.
 'AAA72D56250D5DC10C5E13FADEEE0D25BAD63A40F0285188C4C9C1A89CC6A3E2'
}
function Get-VeliqVendorCleanupRoots {
 @{
  temp=Join-Path ([Environment]::GetFolderPath('Windows')) 'Temp'
  usertemp=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Temp'
  nvidia=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'NVIDIA Corporation\Installer2\InstallerCore\NVI2.dll'
  edge=Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft\EdgeUpdate'
  gaming=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\gamingservicesproxy_11.dll'
 }
}
function Initialize-VeliqCleanupReader {
 if('VeliqCleanupReadHandle' -as [type]){return}
 # Read handles only: OPEN_EXISTING, no write/delete access or sharing.
 # Final DOS path and link count come from the opened object, not its name.
 Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public sealed class VeliqCleanupReadHandle : IDisposable {
 [StructLayout(LayoutKind.Sequential)]
 struct Info {
  public uint Attributes;
  public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
  public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
 }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
 [DllImport("kernel32.dll", SetLastError=true)]
 static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
 SafeFileHandle handle;
 FileStream stream;
 public string FinalPath {get; private set;}
 public uint Links {get; private set;}
 public uint Attributes {get; private set;}
 public VeliqCleanupReadHandle(string path, bool directory) {
  handle=CreateFileW(@"\\?\"+path,0x80000000,1,IntPtr.Zero,3,0x00200000U | (directory ? 0x02000000U : 0U),IntPtr.Zero);
  try {
   if(handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
   Info info;
   if(!GetFileInformationByHandle(handle,out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
   Attributes=info.Attributes; Links=info.Links;
   if((Attributes & 0x400)!=0 || ((Attributes & 0x10)!=0)!=directory || (!directory && Links!=1))
    throw new IOException("CLEANUP_OBJECT_TYPE_OR_LINK_REJECTED");
   var buffer=new StringBuilder(32768);
   uint count=GetFinalPathNameByHandleW(handle,buffer,(uint)buffer.Capacity,0);
   if(count==0 || count>=buffer.Capacity) throw new IOException("CLEANUP_FINAL_PATH_UNAVAILABLE");
   FinalPath=buffer.ToString();
   if(!FinalPath.StartsWith(@"\\?\",StringComparison.Ordinal)) throw new IOException("CLEANUP_FINAL_PATH_INVALID");
   FinalPath=FinalPath.Substring(4);
   if(!String.Equals(FinalPath,path,StringComparison.OrdinalIgnoreCase)) throw new IOException("CLEANUP_PATH_ALIAS_REJECTED");
   if(!directory) stream=new FileStream(handle,FileAccess.Read);
  } catch {Dispose();throw;}
 }
 public string Hash() {
  if(stream==null) throw new IOException("CLEANUP_NOT_A_FILE");
  stream.Position=0;
  using(var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","");
 }
 public void Dispose() {
  if(stream!=null){stream.Dispose();stream=null;}
  if(handle!=null){handle.Dispose();handle=null;}
 }
}
'@ -ErrorAction Stop
}
function Assert-VeliqCleanupPath([string]$Path) {
 # Reject ambiguous DOS syntax, streams, traversal, short aliases and links
 # before reading vendor identity. The handle independently verifies the path.
 if($Path -notmatch '^[a-zA-Z]:\\' -or $Path.Substring(2) -match '[:/*?]' -or $Path.EndsWith('\')){throw 'CLEANUP_PATH_INVALID'}
 foreach($part in $Path.Substring(3).Split('\')){
  if(!$part -or $part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')){throw 'CLEANUP_PATH_INVALID'}
 }
 $current=$Path
 while($current){
  $item=Get-Item -LiteralPath $current -Force -ErrorAction Stop
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'CLEANUP_REPARSE_POINT_REJECTED'}
  $current=[IO.Path]::GetDirectoryName($current)
 }
}
function Open-VeliqCleanupReadHandle([string]$Path,[bool]$Directory) {
 Assert-VeliqCleanupPath $Path
 Initialize-VeliqCleanupReader
 $handle=[VeliqCleanupReadHandle]::new($Path,$Directory)
 try{Assert-VeliqCleanupPath $Path;return $handle}catch{$handle.Dispose();throw}
}
function Test-VeliqVendorCleanup([string]$Path) {
 $roots=Get-VeliqVendorCleanupRoots
 $parent=[IO.Path]::GetDirectoryName($Path)
 $name=[IO.Path]::GetFileName($Path)
 if($roots['gaming'] -and [string]::Equals($Path,($roots['gaming']+'.0'),[StringComparison]::OrdinalIgnoreCase)){
  # Only the observed retired-copy name, never the active DLL or arbitrary
  # gamingservicesproxy*. A delete is eligible only while BOTH separate files
  # match the pinned, previously verified Microsoft binary. No online lookup.
  $copy=$null;$active=$null
  try{
   $copy=Open-VeliqCleanupReadHandle $Path $false
   $active=Open-VeliqCleanupReadHandle $roots['gaming'] $false
   foreach($file in @($Path,$roots['gaming'])){
    $version=Read-VeliqFileVersion $file
    if($version.CompanyName -cne 'Microsoft Corporation' -or
       $version.FileVersion -cne '10.0.26100.8569 (WinBuild.160101.0800)'){return $false}
   }
   $pinned=Get-VeliqGamingCleanupHash
   if($copy.Hash() -cne $pinned -or $active.Hash() -cne $pinned){return $false}
   Assert-VeliqCleanupPath $Path;Assert-VeliqCleanupPath $roots['gaming']
   return $true
  }finally{if($active){$active.Dispose()};if($copy){$copy.Dispose()}}
 }
 if(($parent -ieq $roots.temp -or $parent -ieq $roots.usertemp) -and $name -match '^INS_[a-f0-9]{8}\.TMP$'){
  $copy=$null;$original=$null
  try{
   $copy=Open-VeliqCleanupReadHandle $Path $false
   $original=Open-VeliqCleanupReadHandle $roots.nvidia $false
   $version=Read-VeliqFileVersion $Path
   $installed=Read-VeliqFileVersion $roots.nvidia
   foreach($v in @($version,$installed)){
    if($v.CompanyName -cne 'NVIDIA Corporation' -or $v.ProductName -cne 'NVIDIA Install Application' -or
       $v.FileDescription -cne 'NVIDIA Install Core' -or $v.OriginalFilename -cne 'NVI2.dll' -or !$v.FileVersion){return $false}
   }
   if($version.FileVersion -cne $installed.FileVersion -or $copy.Hash() -cne $original.Hash()){return $false}
   Assert-VeliqCleanupPath $Path;Assert-VeliqCleanupPath $roots.nvidia
   return $true
  }finally{if($original){$original.Dispose()};if($copy){$copy.Dispose()}}
 }
 if($parent -ieq $roots.edge -and $name -match '^\d+\.\d+\.\d+\.\d+$'){
  # A neighbouring version directory alone does not prove this one obsolete.
  # Require the registered updater version and its actual matching executable.
  $registration='SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}'
  $active=Read-VeliqRebootRegistry $registration 'pv'
  if($active -isnot [string] -or $active -notmatch '^\d+\.\d+\.\d+\.\d+$' -or [version]$active -le [version]$name){return $false}
  $directory=$null;$updater=$null
  try{
   $directory=Open-VeliqCleanupReadHandle $Path $true
   if(@(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop).Count){return $false}
   $exe=Join-Path (Join-Path $roots.edge $active) 'MicrosoftEdgeUpdate.exe'
   $updater=Open-VeliqCleanupReadHandle $exe $false
   $version=Read-VeliqFileVersion $exe
   if($version.CompanyName -cne 'Microsoft Corporation' -or $version.ProductName -cne 'Microsoft Edge Update' -or
      $version.OriginalFilename -cne 'MicrosoftEdgeUpdate.exe' -or $version.FileVersion -cne $active){return $false}
   if((Read-VeliqRebootRegistry $registration 'pv') -cne $active){throw 'CLEANUP_REGISTRATION_CHANGED'}
   Assert-VeliqCleanupPath $Path;Assert-VeliqCleanupPath $exe
   return (@(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop).Count -eq 0)
  }finally{if($updater){$updater.Dispose()};if($directory){$directory.Dispose()}}
 }
 return $false
}
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
 if($null -eq $Value -or !$items.Count){return @{required=$false;cleanup=0}}
 if($items.Count % 2){return @{required=$true;cleanup=0}}
 $deletes=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 for($i=0;$i -lt $items.Count;$i+=2){
  if($items[$i] -isnot [string] -or $items[$i+1] -isnot [string] -or [string]::IsNullOrWhiteSpace($items[$i])){$required=$true;continue}
  $source=$items[$i];$destination=$items[$i+1]
  if($destination -ne ''){$required=$true;continue}
  # Current Windows records MoveFileEx deletes with *1/*2 before the NT path.
  # Accept only the observed forms; all other prefixes stay blocking.
  if($source.StartsWith('*1\??\') -or $source.StartsWith('*2\??\')){$source=$source.Substring(2)}
  if($source.StartsWith('\??\')){$source=$source.Substring(4)}
  if($source -notmatch '^[a-zA-Z]:\\' -or $source.Substring(2) -match '[:/*?]' -or $source.Split('\') -contains '..'){$required=$true;continue}
  # A trailing separator denotes a directory. Never turn a malformed file
  # deletion into an allowed one by stripping that separator.
  if($source.EndsWith('\')){
   $source=$source.TrimEnd('\')
   if(!(Test-Path -LiteralPath $source -PathType Container -ErrorAction Stop)){$required=$true;continue}
  }
  # MoveFileEx can record the not-yet-created clone with a short parent name
  # and the existing directory with its long name. Match their actual paths.
  if($source -match '\\iu-[a-z0-9]+\.tmp(?:\\_unins\.tmp)?$' -and (Test-Path -LiteralPath $source)){
   $source=(Get-Item -LiteralPath $source -Force -ErrorAction Stop).FullName
  }
  [void]$deletes.Add($source)
 }
 foreach($path in $deletes){
  $directory=$path
  if([IO.Path]::GetFileName($path) -ieq '_unins.tmp'){$directory=[IO.Path]::GetDirectoryName($path)}
  if($deletes.Contains($directory) -and $deletes.Contains((Join-Path $directory '_unins.tmp')) -and (Test-VeliqInnoCleanupDirectory $directory $ApplicationDirectory)){$cleanup++}
  elseif(Test-VeliqVendorCleanup $path){$cleanup++}
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
 }catch{Write-VeliqInstallDiagnostic 'FILE_BLOCKED' @{path=$Path;code='INSTALL_FILE_IN_USE_OR_NOT_WRITABLE'};throw 'INSTALL_FILE_IN_USE_OR_NOT_WRITABLE'}
}
function Assert-VeliqInstallPreflight([string]$Directory) {
 Assert-VeliqNoPendingReboot (Get-VeliqInstallRebootState $Directory)
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
 $record.installation_state=if($Result -eq 'PASS'){'COMPLETED'}elseif($Reboot.required){'BLOCKED_REBOOT'}else{'FAILED'}
 if($Reboot.PSObject.Properties['windows_reboot_pending']){
  $record.windows_reboot_pending=$Reboot.windows_reboot_pending
  $record.windows_reboot_reasons=@($Reboot.windows_reboot_reasons)
 }
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
