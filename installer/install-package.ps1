[CmdletBinding()]
param([string]$ClubCodeFile='',[switch]$ClubImage,[switch]$Remove,[switch]$Update,[string]$DiagnosticFile='')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent
$result=Join-Path $root 'install-result.json';$success=Join-Path $root 'install-success.json'
Remove-Item -LiteralPath $success -Force -ErrorAction SilentlyContinue
$step='PACKAGE_PREFLIGHT'
$installerModulePath=$env:PSModulePath
. (Join-Path $PSScriptRoot 'install-safety.ps1') -DiagnosticFile $DiagnosticFile
try{
 # Inno inherits the launching shell's environment. A PS7 PSModulePath can hide
 # Windows PowerShell's Get-FileHash even though other cmdlets still resolve.
 # Use trusted Windows/machine modules for this privileged PS5.1 invocation;
 # preserve the caller's environment when the script is invoked directly.
 if($PSVersionTable.PSEdition -eq 'Desktop'){
  $env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')+';'+[Environment]::GetEnvironmentVariable('PSModulePath','Machine')
 }
 . (Join-Path $PSScriptRoot 'package-contract.ps1')
 Assert-VeliqPackage $root
 $packageInfo=Get-Content -Raw -LiteralPath (Join-Path $root 'package.json')|ConvertFrom-Json
 Write-VeliqInstallDiagnostic 'PACKAGE_VERIFIED' @{commit=$packageInfo.commit;file_count=@($packageInfo.files).Count}
 Assert-VeliqNoPendingReboot (Get-VeliqInstallRebootState $root)
 $installed=Join-Path $env:ProgramData 'VELIQ';$manifest=Join-Path $installed 'service.json'
 if($Update){
  # Service-driven update (SYSTEM): the installed owner stays the owner.
  if($ClubImage -or $Remove -or $ClubCodeFile -or !(Test-Path $manifest)){throw 'UPDATE_EXISTING_INSTALL_REQUIRED'}
  $owner=(Get-Content -Raw -LiteralPath $manifest|ConvertFrom-Json).owner_sid;$session=-1
 }else{
  $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if($owner -in @('S-1-5-18','S-1-5-19','S-1-5-20')){throw 'INSTALL_INTERACTIVE_OWNER_REQUIRED'}
  $session=[Diagnostics.Process]::GetCurrentProcess().SessionId
  foreach($shell in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object {$_.SessionId -eq $session})){
   if((Invoke-CimMethod -InputObject $shell -MethodName GetOwnerSid).Sid -ne $owner){throw 'INSTALL_SAME_OWNER_ELEVATION_REQUIRED'}
  }
 }
 if($ClubImage){if($Remove){throw 'CLUB_IMAGE_REMOVE_CONFLICT'};if($ClubCodeFile -and !(Test-Path -LiteralPath $ClubCodeFile -PathType Leaf)){throw 'CLUB_CODE_FILE_INVALID'};. (Join-Path $root 'tools\windows\club-image-common.ps1');Assert-ClubImageClean $installed;Protect-ClubPackageTree -Root $root -OwnerSid $owner}
 if(Test-Path $manifest){$existing=Get-Content -Raw -LiteralPath $manifest|ConvertFrom-Json;if($existing.owner_sid -ne $owner){throw 'INSTALL_OWNER_MISMATCH'}}
 # Setup refuses locked files before copying. No replacement is queued for boot.
 # Earlier builds installed the GUI per-user; that copy is removed.
 $gui=Join-Path $root 'VELIQ.exe'
 $legacyGui=if($Update){''}else{Join-Path $env:LOCALAPPDATA 'Programs\VELIQ\VELIQ.exe'}
 if($legacyGui){
  $step='GUI_SHUTDOWN'
  $pipe=[IO.Pipes.NamedPipeClientStream]::new('.','NeExitLag-activate-'+$owner+'-'+$session,[IO.Pipes.PipeDirection]::Out)
  try{$pipe.Connect(500);$pipe.WriteByte(2)}catch [TimeoutException]{}finally{$pipe.Dispose()}
  foreach($p in @(Get-Process VELIQ,NeExitLag -ErrorAction SilentlyContinue)){
   try{if($p.Path -and ([IO.Path]::GetDirectoryName($p.Path) -ieq [IO.Path]::GetDirectoryName($legacyGui)) -and !$p.WaitForExit(12000)){throw 'INSTALL_GUI_CLOSE_PENDING'}}finally{$p.Dispose()}
  }
 }
 function Remove-VeliqLegacyUserGui {
  if(!$legacyGui){return}
  $guiRoot=Split-Path $legacyGui -Parent;$stamp=Join-Path $guiRoot 'veliq-install.json'
  if(Test-Path -LiteralPath $stamp){
   $mark=Get-Content -Raw -LiteralPath $stamp|ConvertFrom-Json
   if($mark.product -ne 'VELIQ'){throw 'UNINSTALL_FOREIGN_GUI_PRESERVED'}
   foreach($name in @('VELIQ.exe','NeExitLag.exe')){$path=Join-Path $guiRoot $name;if(Test-Path -LiteralPath $path){if((Get-FileHash $path).Hash -ine $mark.sha256){throw 'UNINSTALL_MODIFIED_GUI_PRESERVED'};Remove-Item -LiteralPath $path -Force}}
   Remove-Item -LiteralPath $stamp -Force
  }
  $link=Join-Path ([Environment]::GetFolderPath('Programs')) 'VELIQ.lnk'
  if(Test-Path $link){$shell=New-Object -ComObject WScript.Shell;if($shell.CreateShortcut($link).TargetPath -ieq $legacyGui){Remove-Item -LiteralPath $link}}
 }
 $scripts=Join-Path $root 'tools\windows'
 if($Remove){
  . (Join-Path $scripts 'club-image-common.ps1');Remove-OwnedClubBootTask
  $step='REMOVE_SERVICE';& (Join-Path $scripts 'uninstall.ps1') -InstallDirectory $installed
  $step='REMOVE_GUI';Remove-VeliqLegacyUserGui
  $run='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';$v=Get-ItemProperty -LiteralPath $run -ErrorAction SilentlyContinue
  foreach($name in 'NeExitLag','VELIQ'){
   if($v -and $v.PSObject.Properties[$name] -and ([string]$v.$name) -match 'VELIQ\.exe|NeExitLag\.exe'){Remove-ItemProperty -LiteralPath $run -Name $name}
  }
 }
 else{
  $step='SERVICE_INSTALL';$config=Get-Content -Raw -LiteralPath (Join-Path $root 'public\release.json')|ConvertFrom-Json
  $pins=Get-Content -Raw -LiteralPath (Join-Path $root 'driver\pins.json')|ConvertFrom-Json
  . (Join-Path $scripts 'migrate-legacy-install.ps1');[void](Move-VeliqLegacyInstall -Start);Update-VeliqClubTaskPaths
  if(Get-Service VELIQ -ErrorAction SilentlyContinue){
   & (Join-Path $scripts 'update-service.ps1') -ServiceExecutable (Join-Path $root 'service\veliq-service.exe') -InstallDirectory $installed
  }else{
   $serviceArgs=@{ServiceExecutable=(Join-Path $root 'service\veliq-service.exe');OwnerSid=$owner;ActivationOnly=$true;TrustDirectory=(Join-Path $root 'public');DriverDirectory=(Join-Path $root 'driver');DllSha256=$pins.dll_sha256;DriverSha256=$pins.driver_sha256;ControlPlaneUrl=$config.control_plane_url;ProbeTarget=$config.probe_target;TCPProbeTarget=$config.tcp_probe_target;InstallDirectory=$installed}
   if(Test-Path $manifest){$serviceArgs.Reinstall=$true}
   & (Join-Path $scripts 'install.ps1') @serviceArgs
  }
  $step='GUI_INSTALL'
  if(!(Test-Path -LiteralPath $gui)){throw 'INSTALL_GUI_MISSING'}
  Remove-VeliqLegacyUserGui
  if($legacyGui){
   # Retarget an enabled autostart that pointed at the old per-user copy.
   $run='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';$v=Get-ItemProperty -LiteralPath $run -ErrorAction SilentlyContinue
   foreach($name in 'NeExitLag','VELIQ'){if($v -and $v.PSObject.Properties[$name] -and ([string]$v.$name) -like ('"'+(Split-Path $legacyGui -Parent)+'*')){$rest=([string]$v.$name) -replace '^"[^"]*"','';Remove-ItemProperty -LiteralPath $run -Name $name;Set-ItemProperty -LiteralPath $run -Name VELIQ -Value ('"'+$gui+'"'+$rest)}}
  }
  if($ClubImage){$step='CLUB_IMAGE_SEAL';& (Join-Path $scripts 'configure-club-image.ps1') -InstallDirectory $installed -ClubCodeFile $ClubCodeFile}
  elseif($ClubCodeFile -ne ''){$step='CLUB_STAGE';& (Join-Path $scripts 'stage-club-activation.ps1') -ProtectedCodeFile $ClubCodeFile -InstallDirectory $installed}
  $step='VERIFY';$state=Get-Service VELIQ;if(($ClubImage -and $ClubCodeFile -and $state.Status -ne 'Stopped') -or ((!$ClubImage -or !$ClubCodeFile) -and $state.Status -ne 'Running')){throw 'INSTALL_SERVICE_NOT_RUNNING'}
  $installedHashes=Assert-VeliqInstalledBinaries $root $installed
  if($state.Status -eq 'Running'){
   $step='IPC_READINESS';. (Join-Path $scripts 'common.ps1')
   $deadline=[DateTime]::UtcNow.AddSeconds(30);$ready=$false
   do{
    try{$status=Invoke-ServiceIPC 'status' $null (Join-Path $installed 'ipc.token');$ready=$null -ne $status.PSObject.Properties['backend']}catch{$ready=$false}
    if(!$ready){Start-Sleep -Milliseconds 300}
   }while(!$ready -and [DateTime]::UtcNow -lt $deadline)
   if(!$ready){throw 'INSTALL_SERVICE_IPC_NOT_READY'}
   Write-VeliqInstallDiagnostic 'IPC_READY' @{service='VELIQ';hashes=$installedHashes}
  }
 }
 $reboot=Get-VeliqInstallRebootState $root
 Assert-VeliqNoPendingReboot $reboot
 $hashes=$null;if(!$Remove){$hashes=$installedHashes}
 New-VeliqInstallResult 'PASS' $step $reboot -Hashes $hashes|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $success -Encoding UTF8
 Copy-Item -LiteralPath $success -Destination $result -Force
 Write-VeliqInstallDiagnostic 'PACKAGE_COMPLETED' @{step=$step;result='COMPLETED'}
}catch{
 # Preserve safe constant error codes only; never print arbitrary exception text.
 $safe='INSTALL_STEP_FAILED';if($_.Exception.Message -cmatch '^([A-Z][A-Z0-9_]{3,80})(;|$)'){$safe=$Matches[1]}
 Remove-Item -LiteralPath $success -Force -ErrorAction SilentlyContinue
 Write-VeliqInstallDiagnostic 'PACKAGE_FAILED' @{step=$step;code=$safe}
 New-VeliqInstallResult 'FAIL' $step (Get-VeliqInstallRebootState $root) -Code $safe|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $result -Encoding UTF8
 throw ('VELIQ_SETUP_FAILED stage='+$step+' code='+$safe+'; installation incomplete; inspect transaction diagnostics')
}finally{
 $env:PSModulePath=$installerModulePath
}
