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
foreach($name in @('VELIQ','neexitlag')){if(Get-Service $name -ErrorAction SilentlyContinue){throw 'EXISTING_SERVICE_PRESERVED'}}
foreach($path in @($installed,$app,(Join-Path $env:ProgramData 'neexitlag'),(Join-Path $env:ProgramFiles 'VELIQ Setup'))){if(Test-Path -LiteralPath $path){throw 'EXISTING_INSTALLATION_PRESERVED'}}
function Invoke-OwnedInstaller([string]$Path,[string]$Stage){
 # Inno's uninstaller delegates to _unins.tmp. Process.WaitForExit waits only
 # for the launcher; PowerShell Start-Process -Wait waits for its process tree.
 # A worker job preserves that behavior and bounds it without killing browsers.
 $log=Join-Path $env:RUNNER_TEMP ('beta-inno-'+$Stage+'-'+[guid]::NewGuid().ToString('N')+'.log')
 Write-Output ('BETA_INSTALLER_START stage='+$Stage)
 $worker=Start-Job -ScriptBlock {
  param($Executable,$LogFile)
  $ErrorActionPreference='Stop'
  $process=Start-Process -FilePath $Executable -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+$LogFile+'"')) -Wait -PassThru
  try{[int]$process.ExitCode}finally{$process.Dispose()}
 } -ArgumentList $Path,$log
 try{
  $finished=Wait-Job -Job $worker -Timeout 180
  if(!$finished){throw ('OWNED_INSTALLER_TREE_TIMEOUT stage='+$Stage)}
  if($worker.State -ne 'Completed'){throw ('OWNED_INSTALLER_WORKER_FAILED stage='+$Stage)}
  $codes=@(Receive-Job -Job $worker -ErrorAction Stop)
  if($codes.Count -ne 1 -or $codes[0] -ne 0){throw ('OWNED_INSTALLER_EXIT_FAILED stage='+$Stage)}
  Write-Output ('BETA_INSTALLER_FINISHED stage='+$Stage)
 }finally{
  if($worker.State -in @('Running','NotStarted')){Stop-Job -Job $worker}
  Remove-Job -Job $worker -Force
 }
}
function Assert-InstalledCandidate {
 if((Get-Service VELIQ).Status -ne 'Running'){throw 'INSTALLED_SERVICE_NOT_RUNNING'}
 $result=Get-Content -Raw -LiteralPath (Join-Path $app 'install-result.json')|ConvertFrom-Json
 if($result.result -cne 'PASS'){throw 'INSTALL_RESULT_NOT_PASS'}
 foreach($pair in @(@('service/veliq-service.exe',(Join-Path $installed 'veliq-service.exe')),@('gui/VELIQ.exe',(Join-Path $app 'VELIQ.exe')))){
  if((Get-FileHash -LiteralPath (Join-Path $payload $pair[0])).Hash -cne (Get-FileHash -LiteralPath $pair[1]).Hash){throw 'INSTALLED_CANDIDATE_HASH_MISMATCH'}
 }
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
 Invoke-OwnedInstaller $setup 'install'
 Assert-InstalledCandidate
 # Re-install the identical package exercises the real existing-service update.
 Invoke-OwnedInstaller $setup 'update'
 Assert-InstalledCandidate
 $uninstaller=Join-Path $app 'unins000.exe'
 if(!(Test-Path -LiteralPath $uninstaller)){throw 'REAL_UNINSTALLER_REQUIRED'}
 Invoke-OwnedInstaller $uninstaller 'uninstall'
 if(Get-Service VELIQ -ErrorAction SilentlyContinue){throw 'SERVICE_REMAINED_AFTER_UNINSTALL'}
 $uninstalled=$true
}finally{
 $uninstaller=Join-Path $app 'unins000.exe'
 if(!$uninstalled -and (Test-Path -LiteralPath $uninstaller)){Invoke-OwnedInstaller $uninstaller 'cleanup'}
 if(Get-Service VELIQ -ErrorAction SilentlyContinue){throw 'OWNED_SERVICE_CLEANUP_FAILED'}
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
