# Explicitly opt-in install/update/uninstall on a disposable Actions VM only.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$SetupExecutable,
      [Parameter(Mandatory=$true)][string]$PackageDirectory,
      [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedCommit)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -or $env:VELIQ_BETA_INSTALL_SMOKE -cne '1'){throw 'DISPOSABLE_ACTIONS_INSTALL_OPT_IN_REQUIRED'}
$setup=(Resolve-Path -LiteralPath $SetupExecutable).Path
$payload=(Resolve-Path -LiteralPath $PackageDirectory).Path
$release=Get-Content -Raw -LiteralPath (Join-Path $payload 'public/release.json')|ConvertFrom-Json
$package=Get-Content -Raw -LiteralPath (Join-Path $payload 'package.json')|ConvertFrom-Json
if($package.commit -cne $ExpectedCommit -or $release.control_plane_url -cne 'https://127.0.0.1:1' -or $release.probe_target -cne '127.0.0.1:1' -or $release.tcp_probe_target -cne '127.0.0.1:1'){throw 'DISPOSABLE_LOOPBACK_PACKAGE_REQUIRED'}
$installed=Join-Path $env:ProgramData 'VELIQ';$app=Join-Path $env:ProgramFiles 'VELIQ'
function Get-OwnedServiceState([string]$Name='VELIQ'){
 $service=Get-Service $Name -ErrorAction SilentlyContinue
 if(!$service){return 'ABSENT'}
 try{return [string]$service.Status}finally{$service.Dispose()}
}
foreach($name in @('VELIQ','neexitlag')){if((Get-OwnedServiceState $name) -ne 'ABSENT'){throw 'EXISTING_SERVICE_PRESERVED'}}
foreach($path in @($installed,$app,(Join-Path $env:ProgramData 'neexitlag'),(Join-Path $env:ProgramFiles 'VELIQ Setup'))){if(Test-Path -LiteralPath $path){throw 'EXISTING_INSTALLATION_PRESERVED'}}
function Invoke-OwnedInstaller([string]$Path,[string]$Stage,[int]$ExpectedExit=0,[switch]$InvalidClubImage,[switch]$AccountImage,[switch]$OmitNoRestart,[switch]$UpdateMode){
 # Inno's uninstaller delegates to _unins.tmp. Process.WaitForExit waits only
 # for the launcher; PowerShell Start-Process -Wait waits for its process tree.
 # A worker job preserves that behavior and bounds it without killing browsers.
 $log=Join-Path $env:RUNNER_TEMP ('beta-inno-'+$Stage+'-'+[guid]::NewGuid().ToString('N')+'.log')
 Write-Output ('BETA_INSTALLER_START stage='+$Stage)
 if([IO.Path]::GetFileName($Path) -eq 'unins000.exe'){
  # Read-only diagnostics for a refusal, without registry values or user paths.
  $helper=Join-Path $app 'installer/install-safety.ps1'
  $probeCommand='. '''+$helper+'''; try { Assert-VeliqInstallPreflight '''+$app+'''; Write-Output "BETA_UNINSTALL_PREFLIGHT_PASS" } catch { Write-Output ("BETA_UNINSTALL_PREFLIGHT_FAILURE type="+$_.Exception.GetType().Name+" line="+$_.InvocationInfo.ScriptLineNumber); if($_.Exception.Message -cmatch "^[A-Z][A-Z0-9_]{3,80}$"){Write-Output $_.Exception.Message}; exit 1 }'
  & (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe') -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand ([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probeCommand)))
  foreach($file in @(Get-ChildItem -LiteralPath $app -Recurse -File | Where-Object {$_.Name -notmatch '^unins000\.'})){
   try{$handle=[IO.File]::Open($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$handle.Dispose()}
   catch{Write-Output ('BETA_UNINSTALL_LOCKED '+$file.FullName.Substring($app.Length+1))}
  }
  # This fixture owns the entire disposable VM. Show only Inno temp metadata;
  # never print arbitrary registry values or installation/activation contents.
  . $helper
  foreach($value in @(Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations')){
   if([string]$value -match '^\\\?\?\\([a-zA-Z]:\\.*\\iu-[a-zA-Z0-9]+\.tmp)$'){
    $directory=$Matches[1];$clone=Join-Path $directory '_unins.tmp'
    if(Test-Path -LiteralPath $clone){
     $metadata=Read-VeliqFileVersion $clone
     $same=(Get-FileHash -LiteralPath $clone).Hash -ceq (Get-FileHash -LiteralPath (Join-Path $app 'unins000.exe')).Hash
     $diagnostic=[ordered]@{temp_roots=@(Get-VeliqTemporaryRoots);clone_directory=$directory;child_count=@(Get-ChildItem -LiteralPath $directory -Force).Count;description=$metadata.FileDescription;product=$metadata.ProductName;company=$metadata.CompanyName;same_hash=$same;recognized=(Test-VeliqInnoCleanupDirectory $directory $app)}
     Write-Output ('BETA_INNO_CLEANUP_METADATA '+($diagnostic|ConvertTo-Json -Compress))
    }
   }
  }
 }
 $worker=Start-Job -ScriptBlock {
  param($Executable,$LogFile,$InvalidImage,$AccountImageMode,$UnsafeArguments,$ServiceUpdate)
  $ErrorActionPreference='Stop'
  $arguments=@('/VERYSILENT','/SUPPRESSMSGBOXES',('/LOG="'+$LogFile+'"'))
  if(!$UnsafeArguments){$arguments+='/NORESTART';$arguments+='/RESTARTEXITCODE=3010'}
  if($ServiceUpdate){$arguments+='/UPDATE=1'}
  if($AccountImageMode){$arguments+='/CLUBIMAGE=1'}
  if($InvalidImage){$arguments+='/CLUBIMAGE=1';$missing=Join-Path (Split-Path $Executable -Parent) ('missing-code-'+[guid]::NewGuid().ToString('N')+'.txt');$arguments+=('/CLUBCODEFILE="'+$missing+'"')}
  $process=Start-Process -FilePath $Executable -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
  try{[int]$process.ExitCode}finally{$process.Dispose()}
 } -ArgumentList $Path,$log,([bool]$InvalidClubImage),([bool]$AccountImage),([bool]$OmitNoRestart),([bool]$UpdateMode)
 try{
  $finished=Wait-Job -Job $worker -Timeout 180
  if(!$finished){throw ('OWNED_INSTALLER_TREE_TIMEOUT stage='+$Stage)}
  if($worker.State -ne 'Completed'){throw ('OWNED_INSTALLER_WORKER_FAILED stage='+$Stage)}
  $codes=@(Receive-Job -Job $worker -ErrorAction Stop)
  if($codes.Count -ne 1 -or $codes[0] -ne $ExpectedExit){throw ('OWNED_INSTALLER_EXIT_FAILED stage='+$Stage+' expected='+$ExpectedExit+' actual='+($codes -join ','))}
  Write-Output ('BETA_INSTALLER_FINISHED stage='+$Stage)
 }finally{
  if($worker.State -in @('Running','NotStarted')){Stop-Job -Job $worker}
  Remove-Job -Job $worker -Force
 }
}
function Write-PreflightEnvironmentProbe {
 # Reproduce only the read-only package check with identical input. Comparing
 # one environment variable distinguishes an inherited PS7 module path from a
 # damaged payload. Output is restricted to class/command/line constants.
 $powershell=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
 $escaped=$payload.Replace("'","''")
 $command='$ErrorActionPreference="Stop";try{. '+"'"+$escaped+"/installer/package-contract.ps1'"+';Assert-VeliqPackage '+"'"+$escaped+"'"+';Write-Output "PASS";exit 0}catch{Write-Output ("TYPE="+$_.Exception.GetType().FullName);Write-Output ("COMMAND="+$_.InvocationInfo.MyCommand.Name);Write-Output ("LINE="+$_.InvocationInfo.ScriptLineNumber);exit 1}'
 foreach($mode in @('inherited','windows_modules')){
  $info=[Diagnostics.ProcessStartInfo]::new()
  $info.FileName=$powershell
  $info.Arguments='-NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
  $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.CreateNoWindow=$true
  if($mode -eq 'windows_modules'){$info.EnvironmentVariables['PSModulePath']=(Join-Path (Split-Path $powershell -Parent) 'Modules')+';'+[Environment]::GetEnvironmentVariable('PSModulePath','Machine')}
  $process=[Diagnostics.Process]::new();$process.StartInfo=$info
  try{
   $null=$process.Start()
   if(!$process.WaitForExit(15000)){$process.Kill();Write-Output ('BETA_PREFLIGHT_PROBE mode='+$mode+' timeout=true');continue}
   foreach($line in $process.StandardOutput.ReadToEnd().Split("`n")){
    $line=$line.Trim()
    if($line -cmatch '^(PASS|TYPE=[A-Za-z0-9_.]+|COMMAND=[A-Za-z0-9_-]+|LINE=[0-9]+)$'){Write-Output ('BETA_PREFLIGHT_PROBE mode='+$mode+' '+$line)}
   }
   Write-Output ('BETA_PREFLIGHT_PROBE mode='+$mode+' exit='+$process.ExitCode)
  }finally{$process.Dispose()}
 }
}
function Assert-InstalledCandidate {
 if((Get-OwnedServiceState) -ne 'Running'){throw 'INSTALLED_SERVICE_NOT_RUNNING'}
 $result=Get-Content -Raw -LiteralPath (Join-Path $app 'install-result.json')|ConvertFrom-Json
 if($result.result -cne 'PASS' -or !$result.reboot_check_known -or $result.reboot_required -ne $false -or @($result.reboot_reasons).Count){throw 'INSTALL_RESULT_NOT_PASS'}
 foreach($pair in @(@('service/veliq-service.exe',(Join-Path $installed 'veliq-service.exe')),@('gui/VELIQ.exe',(Join-Path $app 'VELIQ.exe')))){
  if((Get-FileHash -LiteralPath (Join-Path $payload $pair[0])).Hash -cne (Get-FileHash -LiteralPath $pair[1]).Hash){throw 'INSTALLED_CANDIDATE_HASH_MISMATCH'}
 }
 if($result.gui_sha256 -cne (Get-FileHash -LiteralPath (Join-Path $app 'VELIQ.exe')).Hash.ToLowerInvariant() -or $result.service_sha256 -cne (Get-FileHash -LiteralPath (Join-Path $installed 'veliq-service.exe')).Hash.ToLowerInvariant()){throw 'INSTALL_RESULT_HASH_EVIDENCE_MISMATCH'}
 $snapshotFile=Join-Path $env:RUNNER_TEMP ('beta-snapshot-'+[guid]::NewGuid().ToString('N')+'.json')
 & (Join-Path $PSScriptRoot '../../tools/windows/Get-BetaSnapshot.ps1') -Manifest (Join-Path $PSScriptRoot '../../bin/beta-kit/candidate.json') -PCId 'PC01' -OutputPath $snapshotFile
 $snapshot=Get-Content -Raw -LiteralPath $snapshotFile|ConvertFrom-Json
 if($snapshot.source_commit -cne $ExpectedCommit -or @($snapshot.checks.PSObject.Properties|Where-Object {$_.Value.status -cne 'NOT_RUN'}).Count){throw 'BETA_SNAPSHOT_FALSE_ACCEPTANCE'}
 $overwriteRejected=$false
 try{& (Join-Path $PSScriptRoot '../../tools/windows/Get-BetaSnapshot.ps1') -Manifest (Join-Path $PSScriptRoot '../../bin/beta-kit/candidate.json') -PCId 'PC01' -OutputPath $snapshotFile}catch{$overwriteRejected=$true}
 if(!$overwriteRejected){throw 'BETA_SNAPSHOT_OVERWROTE_EVIDENCE'}
 Remove-Item -LiteralPath $snapshotFile
 foreach($name in @('identity.json','device.pem','probe.token')){if(Test-Path -LiteralPath (Join-Path $installed $name)){throw 'UNEXPECTED_ENROLLMENT_STATE'}}
}
$uninstalled=$false
try{
 # This negative case must exit during initialization, before any file or SCM change.
 Invoke-OwnedInstaller $setup 'missing-norestart' -ExpectedExit 1 -OmitNoRestart
 foreach($path in @($installed,$app)){if(Test-Path -LiteralPath $path){throw 'UNSAFE_SETUP_ARGUMENTS_MUTATED_MACHINE'}}
 # An explicitly supplied missing legacy file must fail before SCM/identity creation.
 # New CLUBIMAGE mode without a file uses account approval instead.
 # Inno used to suppress the script exception and falsely return exit 0.
 Invoke-OwnedInstaller $setup 'invalid-image' -ExpectedExit 1 -InvalidClubImage
 $failure=Get-Content -Raw -LiteralPath (Join-Path $app 'install-result.json')|ConvertFrom-Json
 if($failure.result -cne 'FAIL' -or $failure.code -cne 'CLUB_CODE_FILE_INVALID' -or (Get-OwnedServiceState) -ne 'ABSENT'){throw 'FAILED_SETUP_FALSE_SUCCESS_OR_STATE_MUTATION'}
 Invoke-OwnedInstaller (Join-Path $app 'unins000.exe') 'invalid-image-uninstall'
 foreach($path in @($installed,$app)){if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force}}
 Write-Output 'BETA_NEGATIVE_SETUP_PASS exit=1; invalid legacy file; no SCM service'
 Invoke-OwnedInstaller $setup 'install'
 Assert-InstalledCandidate
 # A real incompatible file handle must stop both interactive-owner and SYSTEM
 # update modes BEFORE [InstallDelete], preserving the running service and GUI.
 $beforeService=Get-CimInstance Win32_Service -Filter "Name='VELIQ'"
 $beforeHash=(Get-FileHash -LiteralPath (Join-Path $app 'VELIQ.exe')).Hash
 $held=[IO.File]::Open((Join-Path $app 'VELIQ.exe'),[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  Invoke-OwnedInstaller $setup 'locked-gui' -ExpectedExit 7
  Invoke-OwnedInstaller $setup 'locked-gui-update-mode' -ExpectedExit 7 -UpdateMode
 }finally{$held.Dispose()}
 if((Get-CimInstance Win32_Service -Filter "Name='VELIQ'").ProcessId -ne $beforeService.ProcessId -or (Get-FileHash -LiteralPath (Join-Path $app 'VELIQ.exe')).Hash -cne $beforeHash){throw 'LOCKED_GUI_PREFLIGHT_MUTATED_INSTALLATION'}
 Assert-InstalledCandidate
 # Simulate the old false-success case: payload is valid but installed GUI is old.
 [IO.File]::AppendAllText((Join-Path $app 'VELIQ.exe'),'mismatched-installed-gui')
 $powershell=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
 $packageScript=Join-Path $app 'installer/install-package.ps1'
 $check=Start-Process -FilePath $powershell -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',('"& '''+$packageScript+''' -Update"')) -WindowStyle Hidden -Wait -PassThru
 try{if($check.ExitCode -eq 0){throw 'WRONG_INSTALLED_GUI_ACCEPTED'}}finally{$check.Dispose()}
 $failure=Get-Content -Raw -LiteralPath (Join-Path $app 'install-result.json')|ConvertFrom-Json
 if($failure.result -cne 'FAIL' -or $failure.code -cne 'INSTALL_GUI_HASH_MISMATCH' -or (Test-Path -LiteralPath (Join-Path $app 'install-success.json'))){throw 'WRONG_INSTALLED_GUI_FALSE_SUCCESS'}
 Write-Output 'BETA_NO_REBOOT_PASS unsafe argv refused; locked GUI leaves service/files unchanged; installed GUI mismatch cannot PASS'
 # Re-install the identical package exercises the real existing-service update.
 Invoke-OwnedInstaller $setup 'update'
 Assert-InstalledCandidate
 $uninstaller=Join-Path $app 'unins000.exe'
 if(!(Test-Path -LiteralPath $uninstaller)){throw 'REAL_UNINSTALLER_REQUIRED'}
 Invoke-OwnedInstaller $uninstaller 'uninstall'
 if((Get-OwnedServiceState) -ne 'ABSENT'){throw 'SERVICE_REMAINED_AFTER_UNINSTALL'}
 foreach($name in @('VELIQ.exe','installer/install-package.ps1','unins000.exe')){if(Test-Path -LiteralPath (Join-Path $app $name)){throw 'UNINSTALL_LEFT_PACKAGE_FILES'}}
 $uninstalled=$true
 foreach($path in @($installed,$app)){if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force}}
 $uninstalled=$false
 Invoke-OwnedInstaller $setup 'account-image' -AccountImage
 Assert-InstalledCandidate
 $preparation=Get-Content -Raw -LiteralPath (Join-Path $installed 'club-account-preparation.json')|ConvertFrom-Json
 if($preparation.version -ne 1 -or $preparation.owner_sid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'ACCOUNT_IMAGE_PREPARATION_OWNER_MISMATCH'}
 foreach($name in @('identity.json','device.pem','probe.token','club-boot-ready.json','club-mode.json')){if(Test-Path -LiteralPath (Join-Path $installed $name)){throw 'ACCOUNT_IMAGE_ENROLLED_OR_SEALED_BEFORE_OWNER_APPROVAL'}}
 $manifest=Get-Content -Raw -LiteralPath (Join-Path $installed 'service.json')|ConvertFrom-Json
 if($manifest.club_image){throw 'ACCOUNT_IMAGE_ACTIVATED_BEFORE_APPROVAL'}
 . (Join-Path $PSScriptRoot '../../tools/windows/common.ps1')
 $account=Invoke-ServiceIPCOnce 'account.status'
 if(!$account.image_preparation -or $account.state -cne 'NOT_LINKED'){throw 'ACCOUNT_IMAGE_IPC_NOT_PENDING'}
 if($account.PSObject.Properties['secret'] -or $account.PSObject.Properties['bootstrap_secret']){throw 'ACCOUNT_IMAGE_IPC_EXPORTED_SECRET'}
 $task=Get-ScheduledTask -TaskName 'VELIQ Club Boot'
 if(!$task -or $task.Principal.UserId -notin @('SYSTEM','S-1-5-18')){throw 'ACCOUNT_IMAGE_BOOT_TASK_NOT_SYSTEM'}
 Write-Output 'BETA_ACCOUNT_IMAGE_PASS no_code=true real_owner_IPC=true approval_pending=true no_identity=true system_boot_task=true'
 Invoke-OwnedInstaller (Join-Path $app 'unins000.exe') 'account-image-uninstall'
 $uninstalled=$true
}catch{
 # Preserve the initiating assertion before a cleanup failure can mask it.
 $safe='UNEXPECTED_FIXTURE_EXCEPTION'
 if($_.Exception.Message -cmatch '^([A-Z][A-Z0-9_]{3,80})(;| |$)'){$safe=$Matches[1]}
 Write-Output ('BETA_INSTALLER_PRIMARY_FAILURE code='+$safe+' line='+$_.InvocationInfo.ScriptLineNumber+' type='+$_.Exception.GetType().Name)
 Write-PreflightEnvironmentProbe
 $resultPath=Join-Path $app 'install-result.json'
 if(Test-Path -LiteralPath $resultPath){
  $record=Get-Content -Raw -LiteralPath $resultPath|ConvertFrom-Json
  foreach($field in @('result','step','code')){
   $property=$record.PSObject.Properties[$field]
   if($property -and [string]$property.Value -cmatch '^[A-Z][A-Z0-9_]{1,80}$'){Write-Output ('BETA_INSTALL_RESULT '+$field+'='+$property.Value)}
  }
 }
 throw
}finally{
 $uninstaller=Join-Path $app 'unins000.exe'
 if(!$uninstalled -and (Test-Path -LiteralPath $uninstaller)){Invoke-OwnedInstaller $uninstaller 'cleanup'}
 if((Get-OwnedServiceState) -ne 'ABSENT'){throw 'OWNED_SERVICE_CLEANUP_FAILED'}
 # All paths were absent at entry and are owned by this isolated fixture.
 foreach($path in @($installed,$app)){
  $until=[DateTime]::UtcNow.AddSeconds(15)
  while(Test-Path -LiteralPath $path){
   try{Remove-Item -LiteralPath $path -Recurse -Force;break}catch{
    if([DateTime]::UtcNow -ge $until){throw 'OWNED_INSTALLER_FILES_CLEANUP_FAILED'}
    Start-Sleep -Milliseconds 100
   }
  }
 }
}

Write-Output 'BETA_INSTALLER_SMOKE_PASS real Inno install/update/uninstall and cleanup; loopback-only inactive activation; no production acceptance'
