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
function Invoke-OwnedInstaller([string]$Path){
 $process=Start-Process -FilePath $Path -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -PassThru
 try{
  if(!$process.WaitForExit(180000)){$process.Kill();throw 'OWNED_INSTALLER_TIMEOUT'}
  if($process.ExitCode -ne 0){throw 'OWNED_INSTALLER_EXIT_FAILED'}
 }finally{$process.Dispose()}
}
function Assert-InstalledCandidate {
 if((Get-Service VELIQ).Status -ne 'Running'){throw 'INSTALLED_SERVICE_NOT_RUNNING'}
 $result=Get-Content -Raw -LiteralPath (Join-Path $app 'install-result.json')|ConvertFrom-Json
 if($result.result -cne 'PASS'){throw 'INSTALL_RESULT_NOT_PASS'}
 foreach($pair in @(@('service/veliq-service.exe',(Join-Path $installed 'veliq-service.exe')),@('gui/VELIQ.exe',(Join-Path $app 'VELIQ.exe')))){
  if((Get-FileHash -LiteralPath (Join-Path $payload $pair[0])).Hash -cne (Get-FileHash -LiteralPath $pair[1]).Hash){throw 'INSTALLED_CANDIDATE_HASH_MISMATCH'}
 }
 foreach($name in @('identity.json','device.pem','probe.token')){if(Test-Path -LiteralPath (Join-Path $installed $name)){throw 'UNEXPECTED_ENROLLMENT_STATE'}}
}
try{
 Invoke-OwnedInstaller $setup
 Assert-InstalledCandidate
 # Re-install the identical package exercises the real existing-service update.
 Invoke-OwnedInstaller $setup
 Assert-InstalledCandidate
 $uninstaller=Join-Path $app 'unins000.exe'
 if(!(Test-Path -LiteralPath $uninstaller)){throw 'REAL_UNINSTALLER_REQUIRED'}
 Invoke-OwnedInstaller $uninstaller
 if(Get-Service VELIQ -ErrorAction SilentlyContinue){throw 'SERVICE_REMAINED_AFTER_UNINSTALL'}
 Write-Output 'BETA_INSTALLER_SMOKE_PASS real Inno install/update/uninstall; loopback-only inactive activation; no production acceptance'
}finally{
 $uninstaller=Join-Path $app 'unins000.exe'
 if(Test-Path -LiteralPath $uninstaller){Invoke-OwnedInstaller $uninstaller}
 if(Get-Service VELIQ -ErrorAction SilentlyContinue){throw 'OWNED_SERVICE_CLEANUP_FAILED'}
 # All paths were absent at entry and are owned by this isolated fixture.
 foreach($path in @($installed,$app)){if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force}}
}
