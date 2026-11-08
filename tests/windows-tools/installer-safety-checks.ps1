# Pure regression checks. No installer/service/task/registry/network mutation.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
. (Join-Path $repo 'installer/install-safety.ps1')
function Check($Value,[string]$Message){if(!$Value){throw $Message}}
function Reject([scriptblock]$Action,[string]$Expected){
 $failure='';try{& $Action}catch{$failure=$_.Exception.Message}
 Check ($failure -ceq $Expected) ('Expected '+$Expected+', got '+$failure)
}
# Replace only the registry reader in this test scope, never the machine state.
$script:registry=@{};$script:denyRegistry=$false
function Read-VeliqRebootRegistry([string]$Path,[string]$Name=''){
 if($script:denyRegistry){throw 'fixture access denied'}
 return $script:registry[$Path+'|'+$Name]
}
$clean=Get-VeliqRebootState
Check ($clean.known -and !$clean.required -and $clean.reasons.Count -eq 0) 'clean snapshot'
foreach($entry in @(
 @('SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending|',$true),
 @('SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired|',$true),
 @('SYSTEM\CurrentControlSet\Control\Session Manager|PendingFileRenameOperations',@('\??\C:\fixture.tmp','')),
 @('SYSTEM\CurrentControlSet\Control\Session Manager|PendingFileRenameOperations2',@('\??\C:\fixture.tmp','\??\C:\fixture.exe')),
 @('SOFTWARE\Microsoft\Updates|UpdateExeVolatile',1)
)){
 $script:registry=@{};$script:registry[$entry[0]]=$entry[1]
 $state=Get-VeliqRebootState
 Check ($state.known -and $state.required -and $state.reasons.Count -eq 1) 'pending evidence lost'
 Reject {Assert-VeliqNoPendingReboot $state} 'INSTALL_REBOOT_REQUIRED'
 $record=New-VeliqInstallResult 'FAIL' 'VERIFY' $state -Code 'INSTALL_REBOOT_REQUIRED'
 Check ($record.reboot_required -eq $true -and $record.reboot_check_known) 'false reboot flag'
 Reject {New-VeliqInstallResult 'PASS' 'VERIFY' $state} 'INSTALL_REBOOT_REQUIRED'
}
$script:registry=@{
 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName|ComputerName'='before'
 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName|ComputerName'='after'
}
Check ((Get-VeliqRebootState).required) 'pending rename not detected'
$script:registry=@{'SYSTEM\CurrentControlSet\Control\Session Manager|PendingFileRenameOperations'=@();'SOFTWARE\Microsoft\Updates|UpdateExeVolatile'=0}
Check (!(Get-VeliqRebootState).required) 'empty pending evidence incorrectly blocks'
$script:denyRegistry=$true
$unknown=Get-VeliqRebootState
Check (!$unknown.known -and $null -eq $unknown.required) 'unknown must not be false'
Reject {Assert-VeliqNoPendingReboot $unknown} 'INSTALL_REBOOT_STATE_UNKNOWN'
$record=New-VeliqInstallResult 'FAIL' 'VERIFY' $unknown -Code 'INSTALL_REBOOT_STATE_UNKNOWN'
Check ($null -eq $record.reboot_required -and !$record.reboot_check_known) 'unknown result falsified'
Reject {New-VeliqInstallResult 'PASS' 'VERIFY' $unknown} 'INSTALL_REBOOT_STATE_UNKNOWN'
$script:denyRegistry=$false;$script:registry=@{}
$base=[IO.Path]::GetFullPath((Join-Path $repo 'bin'))
$root=Join-Path $base ('is-'+[guid]::NewGuid().ToString('N').Substring(0,12))
try{
 foreach($directory in @($root,(Join-Path $root 'gui'),(Join-Path $root 'service'),(Join-Path $root 'installed'))){[void][IO.Directory]::CreateDirectory($directory)}
 # Only paired deletion of VELIQ's verified Inno temp clone is housekeeping.
 # The registry remains synthetic; no pending operation is added or removed.
 function Get-VeliqTemporaryRoots { @($root) }
 $script:fixtureProduct='VELIQ'
 function Read-VeliqFileVersion([string]$Path){[pscustomobject]@{FileDescription='Setup/Uninstall';ProductName=$script:fixtureProduct;CompanyName='VELIQ'}}
 $cloneDir=Join-Path $root 'iu-fixture.tmp';[void][IO.Directory]::CreateDirectory($cloneDir)
 $clone=Join-Path $cloneDir '_unins.tmp';$original=Join-Path $root 'unins000.exe'
 foreach($path in @($clone,$original)){[IO.File]::WriteAllText($path,'same Inno clone')}
 $cleanup=@(('\??\'+$clone),'',('\??\'+$cloneDir),'')
 $evidence=Get-VeliqPendingFileEvidence $cleanup $root
 Check (!$evidence.required -and $evidence.cleanup -eq 2) 'verified Inno cleanup requires reboot'
 $directoryCleanup=Get-VeliqPendingFileEvidence @($clone,'',($cloneDir+'\'),'') $root
 Check (!$directoryCleanup.required -and $directoryCleanup.cleanup -eq 2) 'directory separator on actual Inno directory must remain valid'
 $modernCleanup=@(('*2\??\'+$clone),'',('*1\??\'+$cloneDir),'')
 $modern=Get-VeliqPendingFileEvidence $modernCleanup $root
 Check (!$modern.required -and $modern.cleanup -eq 2) 'modern Windows cleanup prefixes lost'
 $mixedNames=@(('*2\??\'+$root+'\.\iu-fixture.tmp\_unins.tmp'),'',('*1\??\'+$cloneDir),'')
 $mixed=Get-VeliqPendingFileEvidence $mixedNames $root
 Check (!$mixed.required -and $mixed.cleanup -eq 2) 'mixed canonical names lost deletion pair'
 Check ((Get-VeliqPendingFileEvidence @(('*3\??\'+$clone),'',('*1\??\'+$cloneDir),'') $root).required) 'unknown Windows prefix bypass'
 Check ((Get-VeliqPendingFileEvidence @(('*2\??\'+$clone),$original) $root).required) 'modern replacement bypass'
 $fso=New-Object -ComObject Scripting.FileSystemObject
 $shortDirectory=$fso.GetFolder($cloneDir).ShortPath
 Check (Test-VeliqInnoCleanupDirectory $shortDirectory $root) 'short TEMP alias lost cleanup ownership'
 [void][Runtime.InteropServices.Marshal]::ReleaseComObject($fso)
 $script:registry=@{'SYSTEM\CurrentControlSet\Control\Session Manager|PendingFileRenameOperations'=$cleanup}
 $state=Get-VeliqRebootState $root
 Check ($state.known -and !$state.required -and $state.deferred_cleanup_count -eq 2) 'cleanup evidence lost'
 Check ((New-VeliqInstallResult 'PASS' 'VERIFY' $state).deferred_cleanup_count -eq 2) 'cleanup omitted from result'
 Check ((Get-VeliqPendingFileEvidence @($clone,'') $root).required) 'unpaired cleanup bypass'
 Check ((Get-VeliqPendingFileEvidence @($clone,$original) $root).required) 'rename bypass'
 Check ((Get-VeliqPendingFileEvidence @($clone) $root).required) 'malformed operation bypass'
 $script:fixtureProduct='Foreign'
 Check ((Get-VeliqPendingFileEvidence $cleanup $root).required) 'foreign uninstaller bypass'
 $script:fixtureProduct='VELIQ'
 [IO.File]::WriteAllText($clone,'different clone')
 Check ((Get-VeliqPendingFileEvidence $cleanup $root).required) 'clone hash mismatch bypass'
 [IO.File]::WriteAllText($clone,'same Inno clone')
 $extra=Join-Path $cloneDir 'foreign.dat';[IO.File]::WriteAllText($extra,'foreign')
 Check ((Get-VeliqPendingFileEvidence $cleanup $root).required) 'nonempty foreign directory bypass'
 Remove-Item -LiteralPath $extra
 # Vendor fixtures use real paths, hashes, handles and links in this workspace.
 # Only registry and PE metadata are synthetic; no vendor executable is run.
 $script:vendorRoots=@{
  temp=Join-Path $root 'Windows\Temp'
  usertemp=Join-Path $root 'User\AppData\Local\Temp'
  nvidia=Join-Path $root 'Program Files\NVIDIA Corporation\Installer2\InstallerCore\NVI2.dll'
  edge=Join-Path $root 'Program Files (x86)\Microsoft\EdgeUpdate'
  gaming=Join-Path $root 'Windows\System32\gamingservicesproxy_11.dll'
 }
 function Get-VeliqVendorCleanupRoots { $script:vendorRoots }
 $nvCopy=Join-Path $script:vendorRoots.temp 'INS_1234abcd.TMP'
 $nvOriginal=$script:vendorRoots.nvidia
 $edgeOld=Join-Path $script:vendorRoots.edge '1.3.311.5'
 $edgeNew=Join-Path $script:vendorRoots.edge '1.3.315.17\MicrosoftEdgeUpdate.exe'
 foreach($directory in @($script:vendorRoots.temp,[IO.Path]::GetDirectoryName($nvOriginal),$edgeOld,[IO.Path]::GetDirectoryName($edgeNew))){[void][IO.Directory]::CreateDirectory($directory)}
 foreach($file in @($nvCopy,$nvOriginal)){[IO.File]::WriteAllText($file,'identical NVIDIA fixture')}
 [IO.File]::WriteAllText($edgeNew,'new updater fixture')
 $script:versions=@{}
 foreach($file in @($nvCopy,$nvOriginal)){
  $script:versions[$file]=[pscustomobject]@{CompanyName='NVIDIA Corporation';ProductName='NVIDIA Install Application';FileDescription='NVIDIA Install Core';OriginalFilename='NVI2.dll';FileVersion='2.1002.474.0'}
 }
 $script:versions[$edgeNew]=[pscustomobject]@{CompanyName='Microsoft Corporation';ProductName='Microsoft Edge Update';OriginalFilename='MicrosoftEdgeUpdate.exe';FileVersion='1.3.315.17'}
 function Read-VeliqFileVersion([string]$Path){$script:versions[$Path]}
 $script:queueKey='SYSTEM\CurrentControlSet\Control\Session Manager|PendingFileRenameOperations'
 $script:edgeKey='SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}|pv'
 function Set-CleanupQueue($Operations){
  $script:registry=@{};$script:registry[$script:queueKey]=$Operations;$script:registry[$script:edgeKey]='1.3.315.17'
 }
 function Check-CleanupBlocked($Operations,[string]$Message,[switch]$Unknown){
  Set-CleanupQueue $Operations
  $s=Get-VeliqRebootState $root
  Check (!$s.known -or $s.required) $Message
  if($Unknown){Check (!$s.known -and $null -eq $s.required) ($Message+' must be unknown')}
 }
 $nvQueue=@(('*1\??\'+$nvCopy),'')
 # Current-user TEMP is a fixed LocalApplicationData child, not arbitrary TEMP.
 [void][IO.Directory]::CreateDirectory($script:vendorRoots.usertemp)
 $userCopy=Join-Path $script:vendorRoots.usertemp 'INS_89abcdef.TMP'
 [IO.File]::WriteAllText($userCopy,'identical NVIDIA fixture')
 $script:versions[$userCopy]=[pscustomobject]@{CompanyName='NVIDIA Corporation';ProductName='NVIDIA Install Application';FileDescription='NVIDIA Install Core';OriginalFilename='NVI2.dll';FileVersion='2.1002.474.0'}
 $userQueue=@(('*1\??\'+$userCopy),'')
 Set-CleanupQueue ($nvQueue+$userQueue)
 $s=Get-VeliqRebootState $root
 Check ($s.known -and !$s.required -and $s.deferred_cleanup_count -eq 2) 'system and user core copies blocked'
 [IO.File]::WriteAllText($userCopy,'different bytes')
 Check-CleanupBlocked $userQueue 'user temp hash mismatch bypass'
 [IO.File]::WriteAllText($userCopy,'identical NVIDIA fixture')
 foreach($identity in @('NvTelemetryAPI.dll','NvUI.dll','nvspcap64.dll')){
  $script:versions[$userCopy].OriginalFilename=$identity
  Check-CleanupBlocked $userQueue 'other NVIDIA component bypass'
 }
 $script:versions[$userCopy].OriginalFilename='NVI2.dll'
 $foreignDir=Join-Path $root 'OtherUser\AppData\Local\Temp'
 [void][IO.Directory]::CreateDirectory($foreignDir)
 $foreignCopy=Join-Path $foreignDir 'INS_89abcdef.TMP'
 [IO.File]::WriteAllText($foreignCopy,'identical NVIDIA fixture')
 $script:versions[$foreignCopy]=$script:versions[$userCopy]
 Check-CleanupBlocked @($foreignCopy,'') 'other user temp bypass'
 Check-CleanupBlocked ($userQueue+@($foreignCopy,'')) 'user cleanup masks mixed queue'
 Check-CleanupBlocked @($userCopy,$nvOriginal) 'user temp replacement bypass'
 $link=Join-Path $root 'user-hardlink-fixture'
 [void](New-Item -ItemType HardLink -Path $link -Target $userCopy)
 try{Check-CleanupBlocked $userQueue 'user temp hardlink bypass' -Unknown}finally{Remove-Item -LiteralPath $link}
 $directory=$script:vendorRoots.usertemp
 $saved=$directory+'.saved'
 Move-Item -LiteralPath $directory -Destination $saved
 try{
  [void](New-Item -ItemType Junction -Path $directory -Target $saved)
  try{Check-CleanupBlocked $userQueue 'user temp junction bypass' -Unknown}
  finally{[IO.Directory]::Delete($directory)}
 }finally{Move-Item -LiteralPath $saved -Destination $directory}
 Set-CleanupQueue $userQueue
 Check (!(Get-VeliqRebootState $root).required) 'user initial recheck failed'
 [IO.File]::WriteAllText($userCopy,'changed after first read')
 Reject {New-VeliqInstallResult 'PASS' 'VERIFY' (Get-VeliqRebootState $root)} 'INSTALL_REBOOT_REQUIRED'
 [IO.File]::WriteAllText($userCopy,'identical NVIDIA fixture')
 Write-Output 'PASS current-user NVIDIA core cleanup; mismatch, other components/users, mixed queue, replacement, hardlink, junction and recheck blocked'
 $edgeQueue=@(('*1\??\'+$edgeOld),'')
 $both=$nvQueue+$edgeQueue
 Set-CleanupQueue $both
 $verified=Get-VeliqRebootState $root
 if(!$verified.known){[void](Get-VeliqPendingFileEvidence $both $root)} # expose fixture failure, never machine data
 Check ($verified.known -and !$verified.required -and $verified.deferred_cleanup_count -eq 2) 'verified vendor cleanup blocked'
 Check ((New-VeliqInstallResult 'PASS' 'VERIFY' $verified).deferred_cleanup_count -eq 2) 'vendor cleanup result lost'
 foreach($name in @('PendingFileRenameOperations','PendingFileRenameOperations2')){
  Set-CleanupQueue @();$script:registry['SYSTEM\CurrentControlSet\Control\Session Manager|'+$name]=$both
  Check (!(Get-VeliqRebootState $root).required) ('vendor cleanup in '+$name)
 }
 foreach($ops in @(
  @($nvCopy,$nvOriginal),@($nvCopy,('!'+$nvOriginal)),@($edgeOld,($edgeOld+'.new')),
  @($nvCopy),@('',''),@(' ',''),@(42,''),@($null,''),@($nvCopy,$null),
  @(('*3\??\'+$nvCopy),''),@(($nvCopy+':stream'),''),@(($nvCopy+'.'),''),@(($nvCopy+' '),''),
  @((Join-Path $root 'INS_1234abcd.TMP'),''),@((Join-Path $script:vendorRoots.temp 'foreign.TMP'),''),
  @((Join-Path $script:vendorRoots.temp '..\Temp\INS_1234abcd.TMP'),''),
  @((Join-Path $script:vendorRoots.edge 'not-a-version'),'')
 )){
  Check-CleanupBlocked $ops 'unknown/rename/path/blank operation bypass'
 }
 Check-CleanupBlocked ($both+@((Join-Path $root 'foreign.tmp'),'')) 'mixed unknown operation bypass'
 [IO.File]::WriteAllText($nvCopy,'different bytes with matching metadata')
 Check-CleanupBlocked $nvQueue 'NVIDIA hash mismatch bypass'
 [IO.File]::WriteAllText($nvCopy,'identical NVIDIA fixture')
 $script:versions[$nvCopy].OriginalFilename='other.dll'
 Check-CleanupBlocked $nvQueue 'NVIDIA original filename bypass'
 $script:versions[$nvCopy].OriginalFilename='NVI2.dll'
 $script:versions[$nvCopy].FileVersion='0.0.0.0'
 Check-CleanupBlocked $nvQueue 'NVIDIA version mismatch bypass'
 $script:versions[$nvCopy].FileVersion='2.1002.474.0'
 $script:versions[$nvCopy].CompanyName='Foreign'
 Check-CleanupBlocked $nvQueue 'NVIDIA publisher mismatch bypass'
 $script:versions[$nvCopy].CompanyName='NVIDIA Corporation'
 Move-Item -LiteralPath $nvOriginal -Destination ($nvOriginal+'.saved')
 try{Check-CleanupBlocked $nvQueue 'missing NVIDIA reference bypass' -Unknown}
 finally{Move-Item -LiteralPath ($nvOriginal+'.saved') -Destination $nvOriginal}
 $heldVendor=[IO.File]::Open($nvCopy,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
 try{Check-CleanupBlocked $nvQueue 'unreadable vendor file bypass' -Unknown}finally{$heldVendor.Dispose()}
 Move-Item -LiteralPath $nvCopy -Destination ($nvCopy+'.saved')
 try{
  [void][IO.Directory]::CreateDirectory($nvCopy)
  Check-CleanupBlocked $nvQueue 'directory masquerading as NVIDIA file bypass' -Unknown
 }finally{[IO.Directory]::Delete($nvCopy);Move-Item -LiteralPath ($nvCopy+'.saved') -Destination $nvCopy}
 [IO.Directory]::Delete($edgeOld)
 try{
  [IO.File]::WriteAllText($edgeOld,'file masquerading as old directory')
  Check-CleanupBlocked $edgeQueue 'file masquerading as old directory bypass' -Unknown
 }finally{Remove-Item -LiteralPath $edgeOld;[void][IO.Directory]::CreateDirectory($edgeOld)}
 # A same-hash hardlink to a working file must not become a cleanup exception.
 foreach($file in @($nvCopy,$nvOriginal,$edgeNew)){
  $hardlink=Join-Path $root 'hardlink-fixture'
  [void](New-Item -ItemType HardLink -Path $hardlink -Target $file -ErrorAction Stop)
  try{Check-CleanupBlocked $both 'hardlink alias bypass' -Unknown}finally{Remove-Item -LiteralPath $hardlink -Force}
 }
 # Check the leaf and every ancestor, including an ancestor of a trusted root.
 foreach($directory in @($edgeOld,$script:vendorRoots.temp,[IO.Path]::GetDirectoryName($nvOriginal),(Join-Path $root 'Program Files (x86)'))){
  $saved=$directory+'.saved'
  Move-Item -LiteralPath $directory -Destination $saved
  try{
   [void](New-Item -ItemType Junction -Path $directory -Target $saved -ErrorAction Stop)
   try{Check-CleanupBlocked $both 'reparse leaf/ancestor bypass' -Unknown}
   finally{[IO.Directory]::Delete($directory)} # remove only the junction, never recurse
  }finally{Move-Item -LiteralPath $saved -Destination $directory}
 }
 $unexpected=Join-Path $edgeOld 'hidden-working-file'
 [IO.File]::WriteAllText($unexpected,'must preserve')
 [IO.File]::SetAttributes($unexpected,[IO.FileAttributes]::Hidden)
 try{Check-CleanupBlocked $edgeQueue 'nonempty obsolete directory bypass'}finally{Remove-Item -LiteralPath $unexpected -Force}
 foreach($active in @($null,'1.3.311.5','1.3.269.9','not-a-version','1.3.999.1')){
  Set-CleanupQueue $edgeQueue;$script:registry[$script:edgeKey]=$active
  $s=Get-VeliqRebootState $root
  Check (!$s.known -or $s.required) 'unregistered/current/newer directory or missing active binary bypass'
 }
 $script:versions[$edgeNew].FileVersion='1.3.311.5'
 Check-CleanupBlocked $edgeQueue 'registered/executable version mismatch bypass'
 $script:versions[$edgeNew].FileVersion='1.3.315.17'
 $script:versions[$edgeNew].OriginalFilename='other.exe'
 Check-CleanupBlocked $edgeQueue 'Edge executable identity bypass'
 $script:versions[$edgeNew].OriginalFilename='MicrosoftEdgeUpdate.exe'
 # Re-read after the initial success: accepted cleanup must never be cached.
 Set-CleanupQueue $both
 Check (!(Get-VeliqRebootState $root).required) 'initial vendor snapshot failed'
 [IO.File]::WriteAllText($unexpected,'appeared after preflight')
 try{Reject {New-VeliqInstallResult 'PASS' 'VERIFY' (Get-VeliqRebootState $root)} 'INSTALL_REBOOT_REQUIRED'}
 finally{Remove-Item -LiteralPath $unexpected}
 foreach($signal in @(
  @('SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending|',$true),
  @('SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired|',$true),
  @('SOFTWARE\Microsoft\Updates|UpdateExeVolatile',1),
  @('SYSTEM\CurrentControlSet\Control\Session Manager|PendingFileRenameOperations2',@('C:\unknown.tmp',''))
 )){
  Set-CleanupQueue $both;$script:registry[$signal[0]]=$signal[1]
  Check ((Get-VeliqRebootState $root).required) 'vendor cleanup masked other reboot evidence'
 }
 Set-CleanupQueue $both
 $script:registry['SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName|ComputerName']='before'
 $script:registry['SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName|ComputerName']='after'
 Check ((Get-VeliqRebootState $root).required) 'vendor cleanup masked computer rename'
 $script:denyRegistry=$true
 try{Check (!(Get-VeliqRebootState $root).known) 'vendor cleanup masked registry read failure'}finally{$script:denyRegistry=$false}
 Write-Output 'PASS verified vendor cleanup: path/handle/hash identity, registered newer Edge, empty directory, hardlinks/reparse ancestors, unknown/mixed operations, recheck, other reboot signals; no registry mutation'
 # Gaming Services uses a fixed, verified digest in production. Check the real
 # anchor first: identical unknown bytes must still block. Only then substitute
 # the fixture digest in this test scope; file IO, handles and links stay real.
 $gamingPinReader=${function:Get-VeliqGamingCleanupHash}
 Check ((Get-VeliqGamingCleanupHash) -ceq 'AAA72D56250D5DC10C5E13FADEEE0D25BAD63A40F0285188C4C9C1A89CC6A3E2') 'Gaming Services trust anchor changed'
 $gamingActive=$script:vendorRoots.gaming;$gamingCopy=$gamingActive+'.0'
 $gamingBytes='known Gaming Services fixture';$gamingDirectory=[IO.Path]::GetDirectoryName($gamingActive)
 [void][IO.Directory]::CreateDirectory($gamingDirectory)
 foreach($file in @($gamingActive,$gamingCopy)){
  [IO.File]::WriteAllText($file,$gamingBytes)
  $script:versions[$file]=[pscustomobject]@{CompanyName='Microsoft Corporation';FileVersion='10.0.26100.8569 (WinBuild.160101.0800)'}
 }
 $gamingQueue=@(('\??\'+$gamingCopy),'')
 Check-CleanupBlocked $gamingQueue 'identical unpinned Gaming Services files bypass'
 $script:gamingFixtureHash=(Get-FileHash -LiteralPath $gamingActive -Algorithm SHA256).Hash
 function Get-VeliqGamingCleanupHash { $script:gamingFixtureHash }
 try{
  foreach($queueName in @('PendingFileRenameOperations','PendingFileRenameOperations2')){
   foreach($prefix in @('','\??\','*1\??\','*2\??\')){
    Set-CleanupQueue @();$script:registry['SYSTEM\CurrentControlSet\Control\Session Manager|'+$queueName]=@(($prefix+$gamingCopy),'')
    $s=Get-VeliqRebootState $root
    if(!$s.known){[void](Get-VeliqPendingFileEvidence @(($prefix+$gamingCopy),'') $root)}
    Check ($s.known -and !$s.required -and $s.deferred_cleanup_count -eq 1) 'verified Gaming Services retired copy blocked'
    Check ((New-VeliqInstallResult 'PASS' 'VERIFY' $s).deferred_cleanup_count -eq 1) 'Gaming Services cleanup omitted from result'
   }
  }
  Set-CleanupQueue ($gamingQueue+$both)
  $s=Get-VeliqRebootState $root
  Check ($s.known -and !$s.required -and $s.deferred_cleanup_count -eq 3) 'verified vendor cleanups cannot coexist'
  foreach($ops in @(
   @($gamingActive,''),@(($gamingActive+'.1'),''),@(($gamingActive+'.00'),''),
   @(($gamingCopy+'\'),''),@(($gamingCopy+'\\'),''),
   @((Join-Path $root 'gamingservicesproxy_11.dll.0'),''),
   @((Join-Path $gamingDirectory '..\System32\gamingservicesproxy_11.dll.0'),''),
   @(('*3\??\'+$gamingCopy),''),@(($gamingCopy+':stream'),''),@(($gamingCopy+'.'),''),@(($gamingCopy+' '),''),
   @($gamingCopy,$gamingActive),@($gamingCopy,('!'+$gamingActive)),@($gamingCopy),@($gamingCopy,$null)
  )){Check-CleanupBlocked $ops 'Gaming Services unknown/path/rename operation bypass'}
  Check-CleanupBlocked ($gamingQueue+@((Join-Path $root 'unknown.tmp'),'')) 'Gaming Services hides mixed unknown queue'
  Check-CleanupBlocked ($gamingQueue+@($gamingActive,'')) 'Gaming Services hides active DLL deletion'
  Check-CleanupBlocked ($gamingQueue+@(($gamingCopy+'\'),'')) 'malformed delete was deduplicated against the valid one'
  # PowerShell linguistic comparison can ignore a soft hyphen. Even a byte-for-byte
  # copy with genuine version metadata must have the exact Windows filename.
  $lookalike=$gamingCopy.Insert($gamingCopy.Length-1,[string][char]0x00ad)
  [IO.File]::Copy($gamingCopy,$lookalike)
  $script:versions[$lookalike]=$script:versions[$gamingCopy]
  try{Check-CleanupBlocked @($lookalike,'') 'linguistically equivalent filename bypass'}
  finally{Remove-Item -LiteralPath $lookalike}
  foreach($file in @($gamingCopy,$gamingActive)){
   [IO.File]::WriteAllText($file,'different bytes')
   Check-CleanupBlocked $gamingQueue 'Gaming Services hash mismatch bypass'
   [IO.File]::WriteAllText($file,$gamingBytes)
   $script:versions[$file].CompanyName='Foreign'
   Check-CleanupBlocked $gamingQueue 'Gaming Services publisher mismatch bypass'
   $script:versions[$file].CompanyName='Microsoft Corporation'
   $script:versions[$file].FileVersion='10.0.26100.9000 (WinBuild.160101.0800)'
   Check-CleanupBlocked $gamingQueue 'Gaming Services unknown version bypass'
   $script:versions[$file].FileVersion='10.0.26100.8569 (WinBuild.160101.0800)'
   Move-Item -LiteralPath $file -Destination ($file+'.saved')
   try{Check-CleanupBlocked $gamingQueue 'Gaming Services missing copy bypass' -Unknown}
   finally{Move-Item -LiteralPath ($file+'.saved') -Destination $file}
   $held=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
   try{Check-CleanupBlocked $gamingQueue 'Gaming Services concurrent writer bypass' -Unknown}finally{$held.Dispose()}
   $link=Join-Path $root 'gaming-hardlink-fixture'
   [void](New-Item -ItemType HardLink -Path $link -Target $file -ErrorAction Stop)
   try{Check-CleanupBlocked $gamingQueue 'Gaming Services hardlink bypass' -Unknown}finally{Remove-Item -LiteralPath $link}
   Move-Item -LiteralPath $file -Destination ($file+'.saved')
   try{
    [void][IO.Directory]::CreateDirectory($file)
    Check-CleanupBlocked $gamingQueue 'Gaming Services directory masquerading as DLL bypass' -Unknown
   }finally{[IO.Directory]::Delete($file);Move-Item -LiteralPath ($file+'.saved') -Destination $file}
  }
  # Both copies changing together must not defeat the independently pinned hash.
  foreach($file in @($gamingCopy,$gamingActive)){[IO.File]::WriteAllText($file,'same but untrusted new bytes')}
  Check-CleanupBlocked $gamingQueue 'Gaming Services equal unknown hashes bypass'
  foreach($file in @($gamingCopy,$gamingActive)){[IO.File]::WriteAllText($file,$gamingBytes)}
  Move-Item -LiteralPath $gamingDirectory -Destination ($gamingDirectory+'.saved')
  try{
   [void](New-Item -ItemType Junction -Path $gamingDirectory -Target ($gamingDirectory+'.saved') -ErrorAction Stop)
   try{Check-CleanupBlocked $gamingQueue 'Gaming Services reparse ancestor bypass' -Unknown}
   finally{[IO.Directory]::Delete($gamingDirectory)}
  }finally{Move-Item -LiteralPath ($gamingDirectory+'.saved') -Destination $gamingDirectory}
  Set-CleanupQueue $gamingQueue
  Check (!(Get-VeliqRebootState $root).required) 'Gaming Services initial snapshot failed'
  [IO.File]::WriteAllText($gamingActive,'changed after preflight')
  try{Reject {New-VeliqInstallResult 'PASS' 'VERIFY' (Get-VeliqRebootState $root)} 'INSTALL_REBOOT_REQUIRED'}
  finally{[IO.File]::WriteAllText($gamingActive,$gamingBytes)}
  foreach($signal in @(
   @('SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending|',$true),
   @('SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired|',$true),
   @('SOFTWARE\Microsoft\Updates|UpdateExeVolatile',1),
   @('SYSTEM\CurrentControlSet\Control\Session Manager|PendingFileRenameOperations2',@('C:\unknown.tmp',''))
  )){
   Set-CleanupQueue $gamingQueue;$script:registry[$signal[0]]=$signal[1]
   Check ((Get-VeliqRebootState $root).required) 'Gaming Services masked independent reboot signal'
  }
  Set-CleanupQueue $gamingQueue
  $script:registry['SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName|ComputerName']='before'
  $script:registry['SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName|ComputerName']='after'
  Check ((Get-VeliqRebootState $root).required) 'Gaming Services masked computer rename'
  $script:denyRegistry=$true
  try{Check (!(Get-VeliqRebootState $root).known) 'Gaming Services masked registry failure'}finally{$script:denyRegistry=$false}
  foreach($file in @($gamingCopy,$gamingActive)){Check ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ceq $script:gamingFixtureHash) 'Gaming Services classifier changed file bytes'}
  Write-Output 'PASS Gaming Services pinned cleanup: exact path/version/hash, both queues, real handles/links, mismatches/mixed queues/other reboot signals/recheck fail closed; no registry mutation'
 }finally{Set-Item -LiteralPath Function:\Get-VeliqGamingCleanupHash -Value $gamingPinReader}
 $script:registry=@{}
 foreach($name in @('gui/VELIQ.exe','VELIQ.exe')){[IO.File]::WriteAllText((Join-Path $root $name),'GUI fixture')}
 foreach($name in @('service/veliq-service.exe','installed/veliq-service.exe')){[IO.File]::WriteAllText((Join-Path $root $name),'service fixture')}
 $hashes=Assert-VeliqInstalledBinaries $root (Join-Path $root 'installed')
 Check ($hashes.gui_sha256.Length -eq 64 -and $hashes.service_sha256.Length -eq 64) 'missing binary evidence'
 $record=New-VeliqInstallResult 'PASS' 'VERIFY' (Get-VeliqRebootState) -Hashes $hashes
 Check (!$record.reboot_required -and $record.reboot_check_known -and $record.gui_sha256 -ceq $hashes.gui_sha256) 'clean result'
 [IO.File]::WriteAllText((Join-Path $root 'VELIQ.exe'),'old GUI still installed')
 Reject {Assert-VeliqInstalledBinaries $root (Join-Path $root 'installed')} 'INSTALL_GUI_HASH_MISMATCH'
 [IO.File]::WriteAllText((Join-Path $root 'VELIQ.exe'),'GUI fixture')
 [IO.File]::WriteAllText((Join-Path $root 'installed/veliq-service.exe'),'old service')
 Reject {Assert-VeliqInstalledBinaries $root (Join-Path $root 'installed')} 'INSTALL_SERVICE_HASH_MISMATCH'
 $target=Join-Path $root 'VELIQ.exe';$before=(Get-FileHash -LiteralPath $target).Hash
 $held=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{Reject {Assert-VeliqInstallPreflight $root} 'INSTALL_FILE_IN_USE_OR_NOT_WRITABLE'}finally{$held.Dispose()}
 Check ((Get-FileHash -LiteralPath $target).Hash -ceq $before) 'preflight changed locked bytes'
 Assert-VeliqInstallPreflight $root
 $script:registry=@{'SOFTWARE\Microsoft\Updates|UpdateExeVolatile'=1}
 Assert-VeliqInstallPreflight $root
 $scoped=Get-VeliqInstallRebootState $root
 Check ($scoped.windows_reboot_pending -and !$scoped.required) 'unrelated Windows update must remain visible without blocking this package'
 $script:registry=@{'SYSTEM\CurrentControlSet\Control\Session Manager|PendingFileRenameOperations'=@($target,'')}
 Reject {Assert-VeliqInstallPreflight $root} 'INSTALL_REBOOT_REQUIRED'
 Write-Output 'PASS installer safety: GUI/service hashes, held-file refusal, six reboot signals, verified Inno cleanup, unknown fail-closed, truthful result; no installation'
}finally{
 $full=[IO.Path]::GetFullPath($root)
 if(!$full.StartsWith($base+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'FIXTURE_CLEANUP_PATH_INVALID'}
 if(Test-Path -LiteralPath $full){Remove-Item -LiteralPath $full -Recurse -Force}
}
