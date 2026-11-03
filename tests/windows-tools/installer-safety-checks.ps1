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
$script:registry=@{'SYSTEM\CurrentControlSet\Control\Session Manager|PendingFileRenameOperations'=@('','');'SOFTWARE\Microsoft\Updates|UpdateExeVolatile'=0}
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
$root=Join-Path $base ('installer-safety-'+[guid]::NewGuid().ToString('N'))
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
 $modernCleanup=@(('*2\??\'+$clone),'',('*1\??\'+$cloneDir),'')
 $modern=Get-VeliqPendingFileEvidence $modernCleanup $root
 Check (!$modern.required -and $modern.cleanup -eq 2) 'modern Windows cleanup prefixes lost'
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
 Reject {Assert-VeliqInstallPreflight $root} 'INSTALL_REBOOT_REQUIRED'
 Write-Output 'PASS installer safety: GUI/service hashes, held-file refusal, six reboot signals, verified Inno cleanup, unknown fail-closed, truthful result; no installation'
}finally{
 $full=[IO.Path]::GetFullPath($root)
 if(!$full.StartsWith($base+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'FIXTURE_CLEANUP_PATH_INVALID'}
 if(Test-Path -LiteralPath $full){Remove-Item -LiteralPath $full -Recurse -Force}
}
