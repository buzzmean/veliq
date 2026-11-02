[CmdletBinding()]
param([string]$ClubCodeFile='',[switch]$ClubImage,[switch]$Remove,[switch]$Update)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent
$result=Join-Path $root 'install-result.json';$success=Join-Path $root 'install-success.json'
Remove-Item -LiteralPath $success -Force -ErrorAction SilentlyContinue
$step='PACKAGE_PREFLIGHT'
$installerModulePath=$env:PSModulePath
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
 if($ClubImage){if(!$ClubCodeFile -or $Remove){throw 'CLUB_IMAGE_CODE_FILE_REQUIRED'};. (Join-Path $root 'tools\windows\club-image-common.ps1');Assert-ClubImageClean $installed;Protect-ClubPackageTree -Root $root -OwnerSid $owner}
 if(Test-Path $manifest){$existing=Get-Content -Raw -LiteralPath $manifest|ConvertFrom-Json;if($existing.owner_sid -ne $owner){throw 'INSTALL_OWNER_MISMATCH'}}
 # The GUI lives in {app} (Setup copies it; a running copy is closed by Setup or
 # replaced at reboot). Earlier builds installed it per-user; that copy is removed.
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
  $step='VERIFY';$state=Get-Service VELIQ;if(($ClubImage -and $state.Status -ne 'Stopped') -or (!$ClubImage -and $state.Status -ne 'Running')){throw 'INSTALL_SERVICE_NOT_RUNNING'}
  if((Get-FileHash (Join-Path $root 'service\veliq-service.exe')).Hash -ne (Get-FileHash (Join-Path $installed 'veliq-service.exe')).Hash){throw 'INSTALL_SERVICE_HASH_MISMATCH'}
 }
 @{result='PASS';step=$step;reboot_required=$false;browser_processes='UNTOUCHED';credentials='PRESERVED'}|ConvertTo-Json|Set-Content -LiteralPath $success -Encoding UTF8
 Copy-Item -LiteralPath $success -Destination $result -Force
}catch{
 # Preserve safe constant error codes only; never print arbitrary exception text.
 $safe='INSTALL_STEP_FAILED';if($_.Exception.Message -cmatch '^([A-Z][A-Z0-9_]{3,80})(;|$)'){$safe=$Matches[1]}
 @{result='FAIL';step=$step;code=$safe;reboot_required=$false;credentials='PRESERVED'}|ConvertTo-Json|Set-Content -LiteralPath $result -Encoding UTF8
 throw ('VELIQ_SETUP_FAILED stage='+$step+' code='+$safe+'; existing state preserved')
}finally{
 $env:PSModulePath=$installerModulePath
}
