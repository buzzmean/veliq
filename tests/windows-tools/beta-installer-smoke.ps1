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
& (Join-Path $PSScriptRoot 'service-startup-checks.ps1')
& (Join-Path $PSScriptRoot 'service-recovery-checks.ps1')
. (Join-Path $PSScriptRoot '../../tools/windows/common.ps1')
. (Join-Path $PSScriptRoot 'service-recovery-native.ps1')
function Invoke-OwnedInstaller([string]$Path,[string]$Stage,[int]$ExpectedExit=0,[switch]$InvalidClubImage,[switch]$AccountImage,[switch]$OmitNoRestart,[switch]$UpdateMode,[string]$InstallerAction='',
 [string]$LateGuiPath='',[string]$LateGuiArguments='',[string]$LateGuiReady=''){
 # Inno's uninstaller delegates to _unins.tmp. Process.WaitForExit waits only
 # for the launcher; PowerShell Start-Process -Wait waits for its process tree.
 # A worker job preserves that behavior and bounds it without killing browsers.
 $log=Join-Path $env:RUNNER_TEMP ('beta-inno-'+$Stage+'-'+[guid]::NewGuid().ToString('N')+'.log')
 $lateWorker=$null
 if($LateGuiPath){
  $lateWorker=Start-Job -ScriptBlock {
   param($LogFile,$Executable,$Arguments,$ReadyFile)
   $ErrorActionPreference='Stop';$process=$null
   try{
    $deadline=[DateTime]::UtcNow.AddSeconds(90)
    $prepared=$false
    while(!$prepared){
     if(Test-Path -LiteralPath $LogFile){
      $stream=[IO.File]::Open($LogFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
      $reader=[IO.StreamReader]::new($stream)
      try{$prepared=$reader.ReadToEnd() -match 'VELIQ_GUI_RACE_TEST_WINDOW'}finally{$reader.Dispose()}
     }
     if($prepared){break}
     if([DateTime]::UtcNow -ge $deadline){throw 'LATE_GUI_PREPARE_WINDOW_MISSING'}
     Start-Sleep -Milliseconds 10
    }
    $process=Start-Process -FilePath $Executable -ArgumentList $Arguments -WindowStyle Hidden -PassThru
    $null=$process.Handle
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    while(!(Test-Path -LiteralPath $ReadyFile) -and !$process.HasExited -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 25}
    if(!(Test-Path -LiteralPath $ReadyFile)){throw 'LATE_GUI_NOT_READY'}
    if(!$process.WaitForExit(120000)){throw 'LATE_GUI_NOT_CLOSED'}
    if($null -eq $process.ExitCode){throw 'LATE_GUI_EXIT_UNAVAILABLE'}
    [pscustomobject]@{pid=$process.Id;exit_code=[int]$process.ExitCode;ready=$true}
   }finally{if($process){if(!$process.HasExited){$process.Kill();$process.WaitForExit()};$process.Dispose()}}
  } -ArgumentList $log,$LateGuiPath,$LateGuiArguments,$LateGuiReady
 }
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
  $pendingItems=@(Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations')
  $shapes=@(foreach($pendingItem in $pendingItems){
   $text=[string]$pendingItem;$parts=$text.Split('\');$tail=($parts | Select-Object -Last 2) -join '\'
   if($tail -notmatch '^[a-zA-Z0-9_.~!\\-]{0,100}$'){$tail='REDACTED'}
   [ordered]@{empty=($text.Length -eq 0);prefix_codes=@($text.ToCharArray()|Select-Object -First 4|ForEach-Object {[int]$_});tail=$tail}
  })
  Write-Output ('BETA_PENDING_FILE_SHAPES '+($shapes|ConvertTo-Json -Depth 4 -Compress))
  Write-Output ('BETA_REBOOT_STATE '+((Get-VeliqRebootState $app)|ConvertTo-Json -Compress))
  foreach($value in @(Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations')){
   if([string]$value -match '^(?:\*[12])?\\\?\?\\([a-zA-Z]:\\.*\\iu-[a-zA-Z0-9]+\.tmp)$'){
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
  param($Executable,$LogFile,$InvalidImage,$AccountImageMode,$UnsafeArguments,$ServiceUpdate,$Action)
  $ErrorActionPreference='Stop'
  $arguments=@('/VERYSILENT','/SUPPRESSMSGBOXES',('/LOG="'+$LogFile+'"'))
  if(!$UnsafeArguments){$arguments+='/NORESTART';$arguments+='/RESTARTEXITCODE=3010'}
  if($ServiceUpdate){$arguments+='/UPDATE=1'}
  if($Action){$arguments+=('/ACTION='+$Action)}
  if($AccountImageMode){$arguments+='/CLUBIMAGE=1'}
  if($InvalidImage){$arguments+='/CLUBIMAGE=1';$missing=Join-Path (Split-Path $Executable -Parent) ('missing-code-'+[guid]::NewGuid().ToString('N')+'.txt');$arguments+=('/CLUBCODEFILE="'+$missing+'"')}
  $process=Start-Process -FilePath $Executable -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
  try{[int]$process.ExitCode}finally{$process.Dispose()}
 } -ArgumentList $Path,$log,([bool]$InvalidClubImage),([bool]$AccountImage),([bool]$OmitNoRestart),([bool]$UpdateMode),$InstallerAction
 try{
  $finished=Wait-Job -Job $worker -Timeout 180
  if(!$finished){throw ('OWNED_INSTALLER_TREE_TIMEOUT stage='+$Stage)}
  if($worker.State -ne 'Completed'){throw ('OWNED_INSTALLER_WORKER_FAILED stage='+$Stage)}
  $codes=@(Receive-Job -Job $worker -ErrorAction Stop)
  if($codes.Count -ne 1 -or $codes[0] -ne $ExpectedExit){throw ('OWNED_INSTALLER_EXIT_FAILED stage='+$Stage+' expected='+$ExpectedExit+' actual='+($codes -join ','))}
  if($InstallerAction -and $ExpectedExit -eq 0 -and (Get-Content -Raw -LiteralPath $log) -notmatch ('VELIQ_OPERATION='+[regex]::Escape($InstallerAction)+';')){throw 'INSTALLER_SELECTED_ACTION_NOT_EXECUTED'}
  if($Stage -like 'locked-gui*' -and (Get-Content -Raw -LiteralPath $log) -notmatch 'VELIQ_PREPARE_FAILED code=INSTALL_FILE_IN_USE_OR_NOT_WRITABLE'){throw 'INSTALLER_LOCKED_FILE_REASON_MISSING'}
  if($lateWorker){
   if(!(Wait-Job -Job $lateWorker -Timeout 15) -or $lateWorker.State -ne 'Completed'){throw 'LATE_GUI_WORKER_INCOMPLETE'}
   $late=@(Receive-Job -Job $lateWorker -ErrorAction Stop)
   if($late.Count -ne 1 -or $late[0].exit_code -ne 0 -or !$late[0].ready){throw 'LATE_GUI_NOT_GRACEFULLY_CLOSED'}
   $content=[IO.File]::ReadAllText($log)
   $sha=[Security.Cryptography.SHA256]::Create()
   try{$key=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::Unicode.GetBytes($app.TrimEnd('\').ToLowerInvariant())))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
   if(!$content.Contains('VELIQ_GUI_BARRIER_ACQUIRED name=Global\VELIQ-GUI-Update-'+$key) -or !$content.Contains('VELIQ transaction ReplaceGui exit=0') -or !$content.Contains('VELIQ_GUI_BARRIER_RELEASED')){throw 'LATE_GUI_BARRIER_COPY_EVIDENCE_MISSING'}
   Write-Output ('BETA_LATE_LEGACY_GUI_PASS pid='+$late[0].pid+' after Prepare; first Setup exit0; exclusive verified copy; scoped barrier released')
  }
  Write-Output ('BETA_INSTALLER_FINISHED stage='+$Stage)
 }finally{
  if($worker.State -in @('Running','NotStarted')){Stop-Job -Job $worker}
  Remove-Job -Job $worker -Force
  if($lateWorker){if($lateWorker.State -in @('Running','NotStarted')){Stop-Job -Job $lateWorker};Remove-Job -Job $lateWorker -Force}
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
 Assert-OwnedRecoveryPolicy $installed
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
 # The failed transaction restores the previously empty payload. There are no
 # installed package scripts to delegate uninstall to in this negative case.
 if(Test-Path -LiteralPath (Join-Path $app 'installer/install-package.ps1')){throw 'FAILED_FRESH_INSTALL_LEFT_PAYLOAD'}
 foreach($path in @($installed,$app)){if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force}}
 Write-Output 'BETA_NEGATIVE_SETUP_PASS exit=1; invalid legacy file; no SCM service'
 Invoke-OwnedInstaller $setup 'install'
 Assert-InstalledCandidate
 # A legacy GUI can release its lease as part of graceful close. Use the exact
 # owner activation pipe and installed GUI path, with a disposable stand-in
 # that removes only this fixture's lease after observing the persisted port.
 $guiStage=Join-Path $env:RUNNER_TEMP ('beta-owner-gui-'+[guid]::NewGuid().ToString('N'))
 New-Item -ItemType Directory -Path $guiStage|Out-Null
 $guiSource=Join-Path $guiStage 'gui.go';$guiMarker=Join-Path $guiStage 'closed.txt'
 $guiCode=@'
package main
import("encoding/json";"io";"os";"github.com/Microsoft/go-winio")
func main(){
 l,e:=winio.ListenPipe(os.Args[1],&winio.PipeConfig{SecurityDescriptor:"D:P(A;;GA;;;SY)(A;;GA;;;BA)"});if e!=nil{os.Exit(41)};defer l.Close()
 if os.WriteFile(os.Args[4]+".ready",[]byte("ready"),0600)!=nil{os.Exit(42)}
 c,e:=l.Accept();if e!=nil{os.Exit(43)};defer c.Close();b:=make([]byte,1);if _,e=io.ReadFull(c,b);e!=nil||b[0]!=2{os.Exit(44)}
 raw,e:=os.ReadFile(os.Args[3]);var state struct{Primary string};if e!=nil||json.Unmarshal(raw,&state)!=nil||state.Primary!=os.Args[5]{os.WriteFile(os.Args[4],[]byte("ADDRESS_NOT_PERSISTED"),0600);os.Exit(45)}
 if e:=os.Remove(os.Args[2]);e!=nil&&!os.IsNotExist(e){os.Exit(46)};os.WriteFile(os.Args[4],[]byte("PERSISTED_BEFORE_GUI_CLOSE"),0600)
}
'@
 [IO.File]::WriteAllText($guiSource,$guiCode,[Text.UTF8Encoding]::new($false))
 & go build -trimpath -o (Join-Path $app 'VELIQ.exe') $guiSource
 if($LASTEXITCODE){throw 'OWNER_GUI_FIXTURE_BUILD_FAILED'}
 Disable-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog'|Out-Null
 Stop-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog'
 Stop-Service VELIQ;(Get-Service VELIQ).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
 $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $manifest=Get-Content -Raw -LiteralPath (Join-Path $installed 'service.json')|ConvertFrom-Json
 $leasePath=Join-Path $manifest.state_directory 'browser-owner-proxy.json'
 $endpointPath=Join-Path $manifest.state_directory 'browser-owner-endpoints.json'
 $probe=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$probe.Start();$address='127.0.0.1:'+$probe.LocalEndpoint.Port;$probe.Stop()
 $lease=@{version=1;owner=$owner;original=@{flags=1;server='';pac='';bypass=''};installed=@{flags=3;server=('http='+$address+';https='+$address);pac='';bypass=''}}
 [IO.File]::WriteAllText($leasePath,($lease|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
 $pipe='\\.\pipe\NeExitLag-activate-'+$owner+'-'+[Diagnostics.Process]::GetCurrentProcess().SessionId
 $guiArgs='"'+$pipe+'" "'+$leasePath+'" "'+$endpointPath+'" "'+$guiMarker+'" "'+$address+'"'
 $fakeGui=Start-Process -FilePath (Join-Path $app 'VELIQ.exe') -ArgumentList $guiArgs -WindowStyle Hidden -PassThru
 try{
  $deadline=[DateTime]::UtcNow.AddSeconds(10)
  while(!(Test-Path -LiteralPath ($guiMarker+'.ready')) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 100}
  if(!(Test-Path -LiteralPath ($guiMarker+'.ready'))){throw 'OWNER_GUI_FIXTURE_NOT_READY'}
  $raceStage=Join-Path $env:RUNNER_TEMP ('beta-late-gui-'+[guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $raceStage|Out-Null
  $compiler=Join-Path $env:RUNNER_TEMP 'veliq-inno-6.4.3/ISCC.exe'
  $fixtureVersion=[Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $payload 'gui/VELIQ.exe')).FileVersion
  & $compiler /Q ('/DStageRoot='+(Split-Path $payload -Parent)) ('/DAppVersion='+$fixtureVersion) /DVeliqGuiRaceFixture=1 ('/O'+$raceStage) (Join-Path $PSScriptRoot '../../installer/setup.iss')
  if($LASTEXITCODE){throw 'LATE_GUI_FIXTURE_COMPILE_FAILED'}
  $lateMarker=Join-Path $guiStage 'late-closed.txt'
  $lateArgs='"'+$pipe+'" "'+$leasePath+'" "'+$endpointPath+'" "'+$lateMarker+'" "'+$address+'"'
  Invoke-OwnedInstaller (Join-Path $raceStage 'VELIQ-Setup.exe') 'legacy-gui-endpoint-update' -LateGuiPath (Join-Path $app 'VELIQ.exe') -LateGuiArguments $lateArgs -LateGuiReady ($lateMarker+'.ready')
  if([IO.File]::ReadAllText($lateMarker) -cne 'PERSISTED_BEFORE_GUI_CLOSE'){throw 'LATE_GUI_CLOSE_NOT_CONFIRMED'}
  if(!$fakeGui.WaitForExit(1000) -or [IO.File]::ReadAllText($guiMarker) -cne 'PERSISTED_BEFORE_GUI_CLOSE'){throw 'OWNER_ADDRESS_SAVED_AFTER_GUI_CLOSE'}
  $remembered=Get-Content -Raw -LiteralPath $endpointPath|ConvertFrom-Json
  if($remembered.primary -cne $address){throw 'OWNER_ADDRESS_CHANGED_DURING_SETUP'}
  Assert-InstalledCandidate
  Write-Output 'BETA_OWNER_ENDPOINT_PRE_GUI_PASS real Setup; exact GUI pipe closes process and removes legacy lease after persistence'
 }finally{if(!$fakeGui.HasExited){$fakeGui.Kill();$fakeGui.WaitForExit()};$fakeGui.Dispose()}
 # Setup resumes the real GUI after replacing the stand-in. Return this new
 # fixture to the original no-GUI baseline before the independent failure,
 # locked-file and uninstall scenarios below; never terminate by process name.
 $resumed=@(Get-CimInstance Win32_Process -Filter "Name='VELIQ.exe'"|Where-Object {$_.ExecutablePath -ieq (Join-Path $app 'VELIQ.exe')})
 if($resumed.Count -ne 1){throw 'OWNER_GUI_FIXTURE_RESUME_COUNT_INVALID'}
 $guiOwner=Invoke-CimMethod -InputObject $resumed[0] -MethodName GetOwnerSid
 if($guiOwner.ReturnValue -ne 0 -or $guiOwner.Sid -cne $owner){throw 'OWNER_GUI_FIXTURE_RESUME_OWNER_INVALID'}
 $close=[IO.Pipes.NamedPipeClientStream]::new('.','NeExitLag-activate-'+$owner+'-'+$resumed[0].SessionId,[IO.Pipes.PipeDirection]::Out)
 try{$close.Connect(5000);$close.WriteByte(2)}finally{$close.Dispose()}
 try{
  $resumedProcess=[Diagnostics.Process]::GetProcessById([int]$resumed[0].ProcessId)
  try{if(!$resumedProcess.WaitForExit(15000)){throw 'OWNER_GUI_FIXTURE_CLOSE_TIMEOUT'}}finally{$resumedProcess.Dispose()}
 }catch [ArgumentException]{}
 # A terminated image can remain mapped briefly after WaitForExit. Require an
 # actual exclusive open, with a bounded wait; never dismiss a persistent lock.
 $unlockDeadline=[DateTime]::UtcNow.AddSeconds(15)
 while($true){
  try{$unlocked=[IO.File]::Open((Join-Path $app 'VELIQ.exe'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$unlocked.Dispose();break}
  catch [IO.IOException]{
   if([DateTime]::UtcNow -ge $unlockDeadline){
    $remaining=@(Get-CimInstance Win32_Process -Filter "Name='VELIQ.exe'"|Where-Object {$_.ExecutablePath -ieq (Join-Path $app 'VELIQ.exe')}|Select-Object ProcessId,ParentProcessId,SessionId)
    Write-Output ('BETA_GUI_REMAINING_PROCESSES '+(ConvertTo-Json -Compress -InputObject $remaining))
    throw 'OWNER_GUI_FIXTURE_EXECUTABLE_STILL_LOCKED'
   }
   Start-Sleep -Milliseconds 100
  }
 }
 Write-Output 'BETA_OWNER_GUI_FIXTURE_CLEAN_PASS resumed owner GUI closed through its pipe; executable unlocked'
 # A verified package with a deliberately failing service must restore both
 # the previous executable AND the previous GUI/package/uninstall metadata.
 $failureStage=Join-Path $env:RUNNER_TEMP ('beta-service-failure-'+[guid]::NewGuid().ToString('N'))
 $failurePayload=Join-Path $failureStage 'payload'
 New-Item -ItemType Directory -Path $failureStage|Out-Null
 Copy-Item -LiteralPath $payload -Destination $failurePayload -Recurse
 $badService=Join-Path $failurePayload 'service/veliq-service.exe'
 Remove-Item -LiteralPath $badService
 $failureSource=Join-Path $failureStage 'failed-service.go'
 $startedMarker=Join-Path $failureStage 'failed-service-started.txt'
 $markerLiteral=$startedMarker|ConvertTo-Json -Compress
 # Allow the pre-stop migration command so this fixture reaches its intended
 # SCM start failure. Only the service invocation may write the parent marker.
 $fakeSource='package main; import ("os"; "strconv"); func main() { if len(os.Args)>1 && os.Args[1]=="-remember-owner-proxy-endpoints" { return }; _ = os.WriteFile('+$markerLiteral+', []byte(strconv.Itoa(os.Getppid())), 0600); os.Exit(42) }'
 [IO.File]::WriteAllText($failureSource,$fakeSource,[Text.UTF8Encoding]::new($false))
 & go build -trimpath -o $badService $failureSource
 if($LASTEXITCODE){throw 'SERVICE_FAILURE_BINARY_BUILD_FAILED'}
 $badManifest=Get-Content -Raw -LiteralPath (Join-Path $failurePayload 'package.json')|ConvertFrom-Json
 foreach($entry in $badManifest.files){if($entry.path -eq 'service/veliq-service.exe'){$entry.sha256=(Get-FileHash -LiteralPath $badService).Hash.ToLowerInvariant()}}
 $badManifest|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $failurePayload 'package.json') -Encoding UTF8
 $compiler=Join-Path $env:RUNNER_TEMP 'veliq-inno-6.4.3/ISCC.exe'
 # Exercise the real SCM failure, not the new earlier downgrade guard. Keep
 # the fixture's version equal to the candidate whose files are being repaired.
 $fixtureVersion=[Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $payload 'gui/VELIQ.exe')).FileVersion
 if($fixtureVersion -notmatch '^\d+\.\d+\.\d+\.\d+$'){throw 'SERVICE_FAILURE_FIXTURE_VERSION_UNAVAILABLE'}
 & $compiler /Q ('/DStageRoot='+$failureStage) ('/DAppVersion='+$fixtureVersion) (Join-Path $PSScriptRoot '../../installer/setup.iss')
 if($LASTEXITCODE){throw 'SERVICE_FAILURE_FIXTURE_COMPILE_FAILED'}
 $preserved=@{}
 foreach($name in @('service.json','ipc.token')){$preserved[$name]=(Get-FileHash -LiteralPath (Join-Path $installed $name)).Hash}
 $oldPackageHash=(Get-FileHash -LiteralPath (Join-Path $app 'package.json')).Hash
 Invoke-OwnedInstaller (Join-Path $failureStage 'output/VELIQ-Setup.exe') 'service-start-failure' -ExpectedExit 1
 if(!(Test-Path -LiteralPath $startedMarker)){throw 'SERVICE_FAILURE_FIXTURE_NEVER_EXECUTED'}
 $serviceParent=[int][IO.File]::ReadAllText($startedMarker)
 $scmPids=@(Get-CimInstance Win32_Process -Filter "Name='services.exe'"|ForEach-Object {[int]$_.ProcessId})
 if($serviceParent -notin $scmPids){throw 'SERVICE_FAILURE_WAS_NOT_STARTED_BY_SCM'}
 if((Get-OwnedServiceState) -ne 'Running' -or (Get-FileHash -LiteralPath (Join-Path $app 'package.json')).Hash -cne $oldPackageHash){throw 'SERVICE_FAILURE_PREVIOUS_PACKAGE_NOT_RESTORED'}
 foreach($name in $preserved.Keys){if((Get-FileHash -LiteralPath (Join-Path $installed $name)).Hash -cne $preserved[$name]){throw 'SERVICE_FAILURE_CONFIGURATION_CHANGED'}}
 if((Get-FileHash -LiteralPath (Join-Path $installed 'veliq-service.exe')).Hash -cne (Get-FileHash -LiteralPath (Join-Path $payload 'service/veliq-service.exe')).Hash){throw 'SERVICE_FAILURE_PREVIOUS_BINARY_NOT_RESTORED'}
 if(Test-Path -LiteralPath (Join-Path $app 'install-success.json')){throw 'SERVICE_FAILURE_FALSE_SUCCESS'}
 # The same verified Setup must recover from this failure on a normal retry.
 Invoke-OwnedInstaller $setup 'retry-after-service-failure'
 Assert-InstalledCandidate
 Write-Output 'BETA_SERVICE_FAILURE_ROLLBACK_PASS real SCM start failure; previous package/binary/config/token restored; normal retry PASS'
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
 # Explicit repair must retain the installed owner configuration and IPC token.
 $repairHashes=@{}
 foreach($name in @('service.json','ipc.token')){$repairHashes[$name]=(Get-FileHash -LiteralPath (Join-Path $installed $name)).Hash}
 # Remove recovery only from this fixture's previously absent disposable service.
 # The real existing-service REINSTALL must restore SCM state, not just keep a valid old policy.
 Clear-OwnedRecoveryFixture $installed
 Invoke-OwnedInstaller $setup 'explicit-reinstall' -InstallerAction 'REINSTALL'
 Assert-InstalledCandidate
 foreach($name in $repairHashes.Keys){if((Get-FileHash -LiteralPath (Join-Path $installed $name)).Hash -cne $repairHashes[$name]){throw 'REINSTALL_EXISTING_STATE_CHANGED'}}
 Write-Output 'BETA_REINSTALL_PASS explicit action; cleared SCM recovery restored restart5s x3/reset86400/noncrash; Auto/Running/IPC; owner/config/token preserved'
 $recovered=Assert-OwnedCrashRecovery $installed $ExpectedCommit (Get-FileHash -LiteralPath (Join-Path $payload 'service/veliq-service.exe')).Hash $repairHashes
 Assert-InstalledCandidate
 Write-Output ('BETA_CRASH_RECOVERY_PASS '+($recovered|ConvertTo-Json -Compress)+'; SCM automatic restart; no manual start; config/token preserved')
 # A newer registered version must refuse before touching service or GUI files.
 $registration='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{E18D91DB-2E64-4405-A05E-AB15A4192318}_is1'
 $previousVersion=(Get-ItemProperty -LiteralPath $registration).DisplayVersion
 $beforePid=(Get-CimInstance Win32_Service -Filter "Name='VELIQ'").ProcessId
 try{
  Set-ItemProperty -LiteralPath $registration -Name DisplayVersion -Value '0.3.65535'
  Invoke-OwnedInstaller $setup 'newer-installed' -ExpectedExit 7
  if((Get-CimInstance Win32_Service -Filter "Name='VELIQ'").ProcessId -ne $beforePid){throw 'DOWNGRADE_GUARD_RESTARTED_SERVICE'}
  Assert-InstalledCandidate
 }finally{Set-ItemProperty -LiteralPath $registration -Name DisplayVersion -Value $previousVersion}
 Write-Output 'BETA_DOWNGRADE_REFUSED_PASS installed files and service preserved'
 # Managed updates use the same SYSTEM transaction during an active desktop
 # session. Exercise its actual GUI resume argument as well as service recovery.
 $backgroundGuiPath=Join-Path $app 'VELIQ.exe'
 $backgroundGui=Start-Process -FilePath $backgroundGuiPath -ArgumentList '--autostart' -PassThru
 $backgroundSession=$backgroundGui.SessionId;$backgroundPid=$backgroundGui.Id
 $backgroundDeadline=[DateTime]::UtcNow.AddSeconds(15)
 $backgroundReady=$false
 do{
  $probe=[IO.Pipes.NamedPipeClientStream]::new('.','NeExitLag-activate-'+$owner+'-'+$backgroundSession,[IO.Pipes.PipeDirection]::Out)
  try{$probe.Connect(300);$backgroundReady=$true}catch [TimeoutException]{}finally{$probe.Dispose()}
  if(!$backgroundReady){Start-Sleep -Milliseconds 200}
 }while(!$backgroundReady -and [DateTime]::UtcNow -lt $backgroundDeadline)
 if(!$backgroundReady){throw 'BACKGROUND_GUI_BASELINE_NOT_READY'}
 $systemTask='VELIQ-Setup-System-Fixture-'+[guid]::NewGuid().ToString('N')
 $systemLog=Join-Path $env:RUNNER_TEMP ('beta-inno-system-update-'+[guid]::NewGuid().ToString('N')+'.log')
 $beforeSystem=@{}
 foreach($name in @('service.json','ipc.token')){$beforeSystem[$name]=(Get-FileHash -LiteralPath (Join-Path $installed $name)).Hash}
 $started=[DateTime]::UtcNow
 try{
  $action=New-ScheduledTaskAction -Execute $setup -Argument ('/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /NOCLOSEAPPLICATIONS /UPDATE=1 /BACKGROUNDUPDATE=1 /RESTARTEXITCODE=3010 /LOG="'+$systemLog+'"')
  $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(3))
  Register-ScheduledTask -TaskName $systemTask -Action $action -Principal $principal -Settings $settings|Out-Null
  Start-ScheduledTask -TaskName $systemTask
  $deadline=[DateTime]::UtcNow.AddSeconds(180);$completed=$false
  do{
   $task=Get-ScheduledTask -TaskName $systemTask
   $info=Get-ScheduledTaskInfo -TaskName $systemTask
   $completed=$info.LastRunTime.ToUniversalTime() -ge $started.AddSeconds(-1) -and [string]$task.State -ne 'Running' -and $info.LastTaskResult -notin @(267009,267011)
   if(!$completed){Start-Sleep -Milliseconds 300}
  }while(!$completed -and [DateTime]::UtcNow -lt $deadline)
  if(!$completed -or $info.LastTaskResult -ne 0){throw 'SYSTEM_UPDATE_INSTALLER_FAILED'}
  Assert-InstalledCandidate
  foreach($name in $beforeSystem.Keys){if((Get-FileHash -LiteralPath (Join-Path $installed $name)).Hash -cne $beforeSystem[$name]){throw 'SYSTEM_UPDATE_CHANGED_OWNER_OR_TOKEN'}}
  $backgroundResumed=@(Get-CimInstance Win32_Process -Filter "Name='VELIQ.exe'"|Where-Object {$_.ExecutablePath -ieq $backgroundGuiPath})
  if($backgroundResumed.Count -ne 1 -or $backgroundResumed[0].ProcessId -eq $backgroundPid -or $backgroundResumed[0].CommandLine -notmatch '(?:^|\s)--autostart(?:\s|$)'){throw 'BACKGROUND_UPDATE_GUI_NOT_RESUMED_IN_TRAY_MODE'}
  $backgroundOwner=Invoke-CimMethod -InputObject $backgroundResumed[0] -MethodName GetOwnerSid
  if($backgroundOwner.ReturnValue -ne 0 -or $backgroundOwner.Sid -cne $owner -or $backgroundResumed[0].SessionId -ne $backgroundSession){throw 'BACKGROUND_UPDATE_GUI_OWNER_CHANGED'}
  Write-Output ('BETA_BACKGROUND_UPDATE_PASS SYSTEM Setup/exit0; actual replacement GUI --autostart/same owner+session; total_transaction_ms='+[int]([DateTime]::UtcNow-$started).TotalMilliseconds+'; not measured service outage or visual tray proof')
  Write-Output 'BETA_SYSTEM_UPDATE_PASS real SYSTEM Setup UPDATE=1; original owner/config/token and running service preserved'
 }finally{
  Unregister-ScheduledTask -TaskName $systemTask -Confirm:$false -ErrorAction SilentlyContinue
  $backgroundGui.Dispose()
 }
 # Close only the GUI belonging to this isolated fixture before uninstallation.
 $backgroundClose=[IO.Pipes.NamedPipeClientStream]::new('.','NeExitLag-activate-'+$owner+'-'+$backgroundResumed[0].SessionId,[IO.Pipes.PipeDirection]::Out)
 try{$backgroundClose.Connect(5000);$backgroundClose.WriteByte(2)}finally{$backgroundClose.Dispose()}
 try{$p=[Diagnostics.Process]::GetProcessById([int]$backgroundResumed[0].ProcessId);try{if(!$p.WaitForExit(15000)){throw 'BACKGROUND_FIXTURE_GUI_CLOSE_TIMEOUT'}}finally{$p.Dispose()}}catch [ArgumentException]{}
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
 # Only these disposable loopback fixtures create this directory. Emit bounded
 # stage/code/action/PID fields, not configs, tokens or arbitrary exception text.
 foreach($diagnostic in @(Get-ChildItem -LiteralPath (Join-Path $env:ProgramData 'VELIQ-Setup/Logs') -Filter '*.jsonl' -File -ErrorAction SilentlyContinue|Sort-Object LastWriteTime|Select-Object -Last 5)){
  foreach($line in @(Get-Content -LiteralPath $diagnostic.FullName|Select-Object -Last 12)){
   try{$item=$line|ConvertFrom-Json;$fields=[ordered]@{stage=$item.stage}
    foreach($key in @('code','action','pid','exception_type','line')){if($item.evidence.PSObject.Properties[$key]){$fields[$key]=$item.evidence.PSObject.Properties[$key].Value}}
    Write-Output ('BETA_TRANSACTION_TRACE '+($fields|ConvertTo-Json -Compress))
   }catch{}
  }
 }
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
