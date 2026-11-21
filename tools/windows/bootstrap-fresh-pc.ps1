# Fresh owner PC only. Default mode NEVER rotates/provisions the VPS.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$VpsIP,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-z_][a-z0-9_-]{0,31}$')][string]$SSHUser,
 [ValidateRange(1,65535)][int]$SSHPort=22,
 [string]$CaFingerprint='',
 [switch]$RepairBrowserReadiness,
 [string]$HardwareSalt="",
 [switch]$PreflightVps,
 [switch]$UpgradeVpsBinaries,
 [string]$ConfirmVpsUpgrade='',
 [switch]$RotateCA,
 [string]$ConfirmCARotation='',
 [string]$ExpectedCurrentCAFingerprint='',
 [switch]$ServicePhase,
 [string]$OwnerSid=''
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'fresh-pc-execution.ps1')
$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$state=Join-Path $root '.e2e\fresh-pc'

function Require-FreshPin([string]$Pin){
 $pin=$Pin.Replace(':','').ToLowerInvariant()
 if($pin -notmatch '^[a-f0-9]{64}$'){throw 'CA_SHA256_INVALID'}
 return $pin
}
function Assert-FreshVpsPreparation([bool]$ReadOnly,[bool]$Upgrade,[bool]$Rotate,[string]$Confirmation){
 if($ReadOnly -and ($Upgrade -or $Rotate)){throw 'PREFLIGHT_IS_READ_ONLY'}
 if($Upgrade -and $Confirmation -cne 'UPGRADE-VPS-2.56.177.4'){throw 'EXPLICIT_UPGRADE_CONFIRMATION_REQUIRED'}
 if(!$Upgrade -and $Confirmation -ne ''){throw 'UPGRADE_CONFIRMATION_WITHOUT_FLAG'}
}
function Assert-FreshTools {
 foreach($tool in @('git','go','dotnet','ssh.exe')){[void](Get-Command $tool -ErrorAction Stop)}
 if(!@(& dotnet --list-sdks | Where-Object {$_ -match '^8\.'}).Count){throw '.NET SDK 8 required; runtime alone is insufficient'}
 if($LASTEXITCODE){throw 'DOTNET_SDK_QUERY_FAILED'}
}
function Fresh-Property($Object,[string]$Name){
 $p=$Object.PSObject.Properties[$Name];if($null -eq $p){throw "Missing evidence field: $Name"};return $p.Value
}
function Assert-FreshSummary($Status){
 if((Fresh-Property $Status 'demo') -or !(Fresh-Property $Status 'connected')){throw 'SERVICE_NOT_AUTHENTICATED'}
 $backend=Fresh-Property $Status 'backend'
 if(!(Fresh-Property $backend 'ready')){throw 'CAPTURE_NOT_READY'}
}
function Wait-FreshServiceStartup([int]$TimeoutMilliseconds=60000){
 $until=[DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
 while($true){
  try{
   $status=Invoke-ServiceIPC 'status'
   $network=Invoke-ServiceIPC 'local.network'
   $errorProperty=$network.PSObject.Properties['error']
   $observed=[DateTimeOffset]::Parse((Fresh-Property $network 'observed_at'))
   if((Fresh-Property $status 'connected') -and !(Fresh-Property $status 'demo') -and (Fresh-Property $network 'fingerprint') -ne '' -and $observed -gt [DateTimeOffset]::UtcNow.AddSeconds(-45) -and ($null -eq $errorProperty -or [string]$errorProperty.Value -eq '')){return}
  }catch{# Startup can transiently lack IPC/network; never print arbitrary payloads.
  }
  # Check readiness BEFORE deadline, including the last permitted sample.
  if([DateTime]::UtcNow -ge $until){throw 'SERVICE_CONTROLPLANE_OR_NETWORK_STARTUP_TIMEOUT'}
  Start-Sleep -Milliseconds 500
 }
}
function Fresh-Optional($Object,[string]$Name){
 if($null -eq $Object){return $null};$p=$Object.PSObject.Properties[$Name];if($null -ne $p){return $p.Value};return $null
}
function Fresh-SafeBrowserCode($Value){
 $code=[string]$Value
 # Only fixed code vocabulary/prefixes; never arbitrary exception/IPC messages.
 $allowed=@('BROWSER_SETUP_FAILED','BROWSER_PROFILE_AMBIGUOUS','BROWSER_PROFILE_REGISTRATION_FAILED','BROWSER_PROFILE_MODE_CONFLICT','BROWSER_NOT_INSTALLED','BROWSER_EXECUTABLE_UNAVAILABLE','BROWSER_AUTO_NOT_COMMITTED','BROWSER_PAC_NOT_READY','BROWSER_ACTIVATION_CANCELLED','BROWSER_SERVICE_UNAVAILABLE','BROWSER_OPTIMIZE_FAILED','CHROME_ACTIVATION_BUSY','CHROME_ACTIVATION_FAILED','CHROME_LISTENER_BIND_FAILED','CHROME_PREPARE_FAILED','CHROME_READINESS_NOT_OBSERVED','CHROME_POLICY_NOT_OWNED','CHROME_RECOVERY_START_FAILED','CHROME_RECOVERY_FAILED','CHROME_ROLLBACK_FAILED','CHROME_POLICY_FAILED','EDGE_READINESS_NOT_OBSERVED','EDGE_READINESS_EXPIRED','EDGE_PREPARE_REQUIRED','EDGE_PROFILE_NOT_FOUND','EDGE_RECOVERY_FAILED','EDGE_BROWSER_POLICY_NOT_OBSERVED','EDGE_POLICY_MANAGED','EDGE_POLICY_ACCESS_DENIED','EDGE_OWNER_SID_REQUIRED','EDGE_LISTENER_BIND_FAILED','EDGE_OPERATION_FAILED','EDGE_IPC_ACCESS_DENIED','EDGE_IPC_UNSUPPORTED','EDGE_SERVICE_UNAVAILABLE','EDGE_LAUNCH_FAILED','EDGE_GUARD_STATE_WRITE_FAILED','NATIVE_OWNED_PAC_GUARD_REQUIRED','GUI_PAC_READINESS_TIMEOUT','GUI_PAC_READINESS_NO_REPORT','GUI_PAC_REPORT_INVALID','GUI_PAC_START_FAILED')
 foreach($known in $allowed){if($code -ceq $known -or $code.EndsWith(': '+$known,[StringComparison]::Ordinal)){return $known}}
 return 'BROWSER_SETUP_FAILED'
}
function Write-FreshPacFailure($Report,[string]$FallbackCode){
 $code=Fresh-SafeBrowserCode (Fresh-Optional $Report 'code')
 if($code -eq 'BROWSER_SETUP_FAILED'){$code=Fresh-SafeBrowserCode $FallbackCode}
 $browser=[string](Fresh-Optional $Report 'browser');if($browser -notin @('chrome','edge','both')){$browser='both'}
 $phase=[string](Fresh-Optional $Report 'stage')
 if($phase -notin @('service','profiles','edge_pac','chrome_pac','optimize','verify_pac','chrome.activation','chrome.processes','chrome.policy.check','chrome.policy.install','chrome.recovery','browser.prepare','browser.silent.apply','edge.silent.apply','browser.confirm','chrome.browser_probe','chrome.launch','chrome.rollback','edge.prepare','edge.confirm','edge.policy','edge.recovery','edge.browser_probe','edge.launch','profile.set')){$phase='pac_readiness'}
 Write-Host "PAC_READINESS_FAILED code=$code browser=$browser phase=$phase"
 foreach($lane in @('browser','edge')){
  try{
   $view=Invoke-ServiceIPC ($lane+'.status')
   $listening=Fresh-Optional $view 'listening';if($listening -isnot [bool]){$listening='unknown'}
   $policy=Fresh-Optional $view 'policy_ready';if($policy -isnot [bool]){$policy='unknown'}
   $readiness=[string](Fresh-Optional $view 'readiness_state')
   if($readiness -notin @('NOT_PREPARED','PREPARED','PAC_READY','READY','PAC_NONCE_CONFIRMED','NATIVE_ARMED_PAC_GUARD','GUARDED','LISTENER_UNAVAILABLE','OWNER_NONCE_VERIFIED','NONCE_INVALIDATED','NONCE_EXPIRED','WAITING_FOR_BROWSER_REQUEST','NATIVE_CAPTURE_NOT_READY','NATIVE_ARMED_NO_NEW_FLOW','NATIVE_UPSTREAM_OPENED_NO_EXCHANGE','NATIVE_TUNNEL_OBSERVED','PAC_TUNNEL_OBSERVED_NATIVE_IDLE','POLICY_PENDING_BROWSER_REFRESH','PAC_REQUEST_OBSERVED','POLICY_OR_LISTENER_UNAVAILABLE')){$readiness='UNKNOWN'}
   $last=[string](Fresh-Optional $view 'last_error');if($last -ne ''){$last=Fresh-SafeBrowserCode $last}
   $profiles=Fresh-Optional $view 'ready_profiles';$count=@($profiles | Where-Object {$null -ne $_}).Count
   Write-Host "$lane.status listening=$listening policy_ready=$policy readiness_state=$readiness last_error=$last ready_profiles_count=$count"
  }catch{Write-Host "$lane.status query=FAILED listening=unknown policy_ready=unknown readiness_state=UNKNOWN last_error=STATUS_QUERY_FAILED"}
 }
}
function Invoke-FreshPacReadiness([string]$Gui,[string]$Report,[int]$TimeoutMilliseconds=300000){
 $ready=$null;$failure='GUI_PAC_START_FAILED';$process=$null
 try{
  Remove-Item -LiteralPath $Report -Force -ErrorAction SilentlyContinue
  $process=Start-Process $Gui -ArgumentList @('--fresh-pc-setup',(Fresh-Quote $Report)) -PassThru
  $failure='GUI_PAC_READINESS_TIMEOUT';$until=[DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
  while($true){
   # Evidence check precedes deadline/exit, including the last boundary sample.
   if(Test-Path -LiteralPath $Report){break}
   $process.Refresh()
   if($process.HasExited -or [DateTime]::UtcNow -ge $until){
    # A report can be atomically published between the first sample and exit.
    if(Test-Path -LiteralPath $Report){break}
    if($process.HasExited){$failure='GUI_PAC_READINESS_NO_REPORT'};throw $failure
   }
   Start-Sleep -Milliseconds 500
  }
  $failure='GUI_PAC_REPORT_INVALID'
  if((Get-Item -LiteralPath $Report).Length -gt 32768){throw $failure}
  $ready=Get-Content -LiteralPath $Report -Raw | ConvertFrom-Json
  if((Fresh-Optional $ready 'pass') -cne $true){$failure=Fresh-SafeBrowserCode (Fresh-Optional $ready 'code');throw $failure}
  Write-Host 'PAC configured silently; browser uptake may be pending until policy refresh or next browser launch. No browser processes closed. Not a website PASS.'
 }catch{
  Write-FreshPacFailure $ready $failure
  throw 'GUI_PAC_READINESS_FAILED; local browser setup retained, inspect PAC_READINESS_FAILED above; do not rotate CA again'
 }finally{if($null -ne $process){$process.Dispose()}}
}
function Fresh-Quote([string]$Value){return '"'+[regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"'}
function Invoke-FreshSSH([string]$Payload,[string]$RemoteCode,[string]$KnownHosts){
 # Keep a real console for OpenSSH host-key/password prompts. Only protocol stdout
 # is captured; no password, CA private key or administrator token enters this PS.
 $code=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($RemoteCode))
 $remote="python3 -c `"exec(__import__('base64').b64decode('$code'))`""
 if($SSHUser -ne 'root'){$remote='sudo -n '+$remote}
 $sshArguments=@('-T','-F','none','-p',"$SSHPort",'-o','StrictHostKeyChecking=ask','-o',"UserKnownHostsFile=$KnownHosts",'-o','GlobalKnownHostsFile=NUL','-o','ConnectTimeout=15','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3',"${SSHUser}@${VpsIP}",$remote)
 $info=[Diagnostics.ProcessStartInfo]::new('ssh.exe',(($sshArguments|ForEach-Object {Fresh-Quote $_}) -join ' '))
 $info.UseShellExecute=$false;$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.CreateNoWindow=$false
 $p=[Diagnostics.Process]::Start($info)
 try{
  $output=$p.StandardOutput.ReadToEndAsync()
  $p.StandardInput.Write($Payload);$p.StandardInput.Close()
  if(!$p.WaitForExit(600000)){try{$p.Kill()}catch{};throw 'SSH_TIMEOUT; migration watchdog remains on VPS if armed'}
  $p.WaitForExit();$p.Refresh()
  if($p.ExitCode -ne 0){throw 'SSH_ENROLLMENT_FAILED; no installation performed'}
  $result=$output.GetAwaiter().GetResult()
  if($result.Length -gt 32768){throw 'SSH_RESPONSE_TOO_LARGE'}
  return $result
 }finally{$p.Dispose()}
}
function Protect-FreshState([string]$Directory,[string]$Sid){
 foreach($item in @((Get-Item -LiteralPath $Directory -Force)) + @(Get-ChildItem -LiteralPath $Directory -Recurse -Force)){
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'FRESH_REPARSE_POINT_REFUSED'}
  if($item.PSIsContainer){$acl=[Security.AccessControl.DirectorySecurity]::new();$inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}
  else{$acl=[Security.AccessControl.FileSecurity]::new();$inherit=[Security.AccessControl.InheritanceFlags]::None}
  $acl.SetAccessRuleProtection($true,$false)
  foreach($allowed in @('S-1-5-18','S-1-5-32-544',$Sid)){
   [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($allowed),[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
  }
  Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop
 }
}
function Install-FreshService([string]$InstallationOwnerSid) {
 $who=[Security.Principal.WindowsIdentity]::GetCurrent()
 try{
  $isAdmin=([Security.Principal.WindowsPrincipal]::new($who)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if(!$isAdmin -or $InstallationOwnerSid -cne $who.User.Value){throw 'Service installation requires the SAME owner SID and administrator token'}
 }finally{$who.Dispose()}
 $bin=Join-Path $root 'bin\windows-e2e';$driver=Join-Path $root '.e2e\windivert'
  $pins=Get-Content (Join-Path $driver 'pins.json') -Raw|ConvertFrom-Json
  & (Join-Path $PSScriptRoot 'install.ps1') -ServiceExecutable (Join-Path $bin 'veliq-service.exe') -OwnerSid $InstallationOwnerSid -DeviceDirectory (Join-Path $state 'device') -TrustDirectory (Join-Path $state 'trust') -DriverDirectory $driver -DllSha256 $pins.dll_sha256 -DriverSha256 $pins.driver_sha256 -ControlPlaneUrl "https://${VpsIP}:8443" -ProbeTarget "${VpsIP}:40000" -TCPProbeTarget "${VpsIP}:40000" -ProbeTokenFile (Join-Path $state 'echo.token')
  . (Join-Path $PSScriptRoot 'native-tcp-firewall.ps1')
  [void](Add-NativeTcpFirewallAdmission (Join-Path $env:ProgramData 'VELIQ\veliq-service.exe'))
  $installed=Join-Path $env:ProgramData 'VELIQ'
  $manifest=Get-Content (Join-Path $installed 'service.json') -Raw|ConvertFrom-Json
  if($manifest.owner_sid -cne $InstallationOwnerSid){throw 'INSTALLED_OWNER_MISMATCH'}
  foreach($pair in @(@('device\identity.json','identity.json'),@('device\device.pem','device.pem'),@('trust\ca.pem','ca.pem'),@('trust\trust.json','trust.json'),@('echo.token','probe.token'))){
   if((Get-FileHash (Join-Path $state $pair[0])).Hash -ne (Get-FileHash (Join-Path $installed $pair[1])).Hash){throw 'INSTALLED_CREDENTIAL_MISMATCH'}
  }
  $proof=@{owner_sid=$InstallationOwnerSid;sha256=(Get-FileHash (Join-Path $installed 'veliq-service.exe')).Hash}
  [IO.File]::WriteAllText((Join-Path $state 'service-install-proof.json'),($proof|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
}
function Invoke-FreshPC {
 $script:FreshStage='preflight'
 if($env:OS -ne 'Windows_NT'){throw 'Windows 10/11 x64 required'}
 $script:VpsIP=Assert-VpsIPv4 $VpsIP
 if($VpsIP -ne '2.56.177.4'){throw 'This owner bootstrap is scoped to existing VPS 2.56.177.4'}
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $bin=Join-Path $root 'bin\windows-e2e';$helper=Join-Path $bin 'fresh-pc.exe';$driver=Join-Path $root '.e2e\windivert'
 if($RepairBrowserReadiness -and ($PreflightVps -or $UpgradeVpsBinaries -or $RotateCA -or $ServicePhase -or $ConfirmCARotation -ne '' -or $ConfirmVpsUpgrade -ne '' -or $CaFingerprint -ne '' -or $ExpectedCurrentCAFingerprint -ne '')){throw 'BROWSER_REPAIR_IS_LOCAL_ONLY'}
 if($ServicePhase){Install-FreshService $OwnerSid;return}
 $evidence=New-FreshExecutionEvidence
 try{
  $evidence=Get-FreshExecutionEvidence
  $mode=Resolve-FreshExecutionMode $evidence
 }catch{
  Write-Host ('UAC_TOKEN_PREFLIGHT_REJECTED: '+(Format-FreshExecutionEvidence $evidence $_.Exception.Message))
  throw
 }
 Write-Host ("Execution mode: $mode; "+(Format-FreshExecutionEvidence $evidence 'ACCEPTED'))
 if($mode -eq 'UAC_DISABLED_FULL_ADMIN'){
  Write-Warning 'UAC is disabled: service installation stays in this process; GUI will also run with full administrator rights, without token lowering. Owner SID/ACL/IPC checks remain enforced.'
 }
 if($RepairBrowserReadiness){
  $script:FreshStage='browser_repair_preflight'
  $manifest=Get-Content (Join-Path $env:ProgramData 'VELIQ\service.json') -Raw | ConvertFrom-Json
  if((Fresh-Property $manifest 'owner_sid') -cne $sid){throw 'INSTALLED_OWNER_MISMATCH'}
  Assert-FreshSummary (Invoke-ServiceIPC 'status')
  foreach($directory in @($root,(Join-Path $root '.e2e'),$state)){
   if((Test-Path -LiteralPath $directory) -and ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'FRESH_REPARSE_POINT_REFUSED'}
  }
  [void][IO.Directory]::CreateDirectory($state)
  Protect-FreshState $state $sid
  $script:FreshStage='pac_readiness'
  Invoke-FreshPacReadiness (Join-Path $env:LOCALAPPDATA 'Programs\VELIQ\VELIQ.exe') (Join-Path $state 'gui-readiness.json')
  Write-Host 'PASS: local owned browser PAC readiness. No SSH, enroll, CA rotation or service reinstall performed.'
  return
 }
 if(!$PreflightVps -and (Get-Service VELIQ -ErrorAction SilentlyContinue)){throw 'EXISTING_INSTALLATION_PRESERVED: use the normal updater; fresh bootstrap does not rotate an installed identity'}
 if(!$PreflightVps -and (Test-Path (Join-Path $env:ProgramData 'VELIQ'))){throw 'PRESERVED_INSTALLATION_FOUND: do not delete credentials; use explicit reinstall/update'}
 Assert-FreshVpsPreparation ([bool]$PreflightVps) ([bool]$UpgradeVpsBinaries) ([bool]$RotateCA) $ConfirmVpsUpgrade
 if($RotateCA -and $CaFingerprint -ne ''){throw 'Use ExpectedCurrentCAFingerprint for rotation; the new CA pin is generated on the VPS'}
 if($RotateCA -and $ConfirmCARotation -cne "ROTATE-CA-$VpsIP"){throw 'Explicit -ConfirmCARotation ROTATE-CA-2.56.177.4 required'}
 if(!$RotateCA -and $ConfirmCARotation -ne ''){throw 'Confirmation without -RotateCA is invalid'}
 if($CaFingerprint -ne ''){$script:CaFingerprint=Require-FreshPin $CaFingerprint}
 if($ExpectedCurrentCAFingerprint -ne ''){$script:ExpectedCurrentCAFingerprint=Require-FreshPin $ExpectedCurrentCAFingerprint}
 if(!$PreflightVps -and @(Get-Process -Name VELIQ,NeExitLag -ErrorAction SilentlyContinue).Count){throw 'Exit only VELIQ GUI before fresh bootstrap; Chrome/Edge are handled by existing activation'}
 Assert-FreshTools
 if($UpgradeVpsBinaries){
  $dirty=@(& git -C $root status --porcelain=1 --untracked-files=normal)
  if($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0){throw 'CLEAN_SOURCE_REQUIRED_FOR_VPS_UPGRADE; local files preserved, no reset/delete performed'}
 }
 foreach($directory in @($root,(Join-Path $root '.e2e'),$state)){
  if((Test-Path -LiteralPath $directory) -and ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse enrollment directories refused'}
 }
 New-Item -ItemType Directory -Force $state|Out-Null
 Protect-FreshState $state $sid
 if(!$PreflightVps){
 $script:FreshStage='build'
 & (Join-Path $PSScriptRoot 'build-e2e.ps1')
 $nuget=Join-Path $state 'NuGet.Config'
 [IO.File]::WriteAllText($nuget,'<configuration><packageSources><clear/><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>',[Text.UTF8Encoding]::new($false))
 $priorRestore=$env:RestoreConfigFile
 try{if(!$PreflightVps){$env:RestoreConfigFile=$nuget;& (Join-Path $PSScriptRoot 'build-desktop.ps1')}}
 finally{$env:RestoreConfigFile=$priorRestore}
 if(!$PreflightVps -and !(Test-Path (Join-Path $driver 'pins.json'))){& (Join-Path $PSScriptRoot 'fetch-windivert.ps1') -Destination $driver}
 Push-Location $root
 $oldOS=$env:GOOS;$oldArch=$env:GOARCH;$oldCGO=$env:CGO_ENABLED
 try{
  $env:GOOS='windows';$env:GOARCH='amd64';$env:CGO_ENABLED='0'
  & go build -trimpath -o $helper ./tools/fresh-pc;if($LASTEXITCODE){throw 'FRESH_HELPER_BUILD_FAILED'}
  $env:GOOS='linux'
  $linux=Join-Path $bin 'linux\fresh-pc'
  & go build -trimpath -o $linux ./tools/fresh-pc;if($LASTEXITCODE){throw 'LINUX_ENROLL_HELPER_BUILD_FAILED'}
 }finally{$env:GOOS=$oldOS;$env:GOARCH=$oldArch;$env:CGO_ENABLED=$oldCGO;Pop-Location}
 }
 $request=$null
 if(!$PreflightVps){
 if($HardwareSalt -ne ''){
  if($HardwareSalt -notmatch '^[a-fA-F0-9]{64}$'){throw 'HARDWARE_SALT_INVALID'}
  $machine=(& $helper hardware-hash --hardware-salt $HardwareSalt | Out-String).Trim();if($LASTEXITCODE -or $machine -notmatch '^[a-f0-9]{64}$'){throw 'HARDWARE_ID_UNAVAILABLE'}
 }else{
 $uuid=([string](Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID).Trim().ToLowerInvariant()
 if($uuid -notmatch '^[a-f0-9-]{36}$' -or $uuid -match '^(0|-)+$|^(f|-)+$'){throw 'Stable unique SMBIOS UUID required; cloned/empty UUIDs cannot identify a machine safely'}
 $hash=[Security.Cryptography.SHA256]::Create();try{$machine=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes('veliq-machine-v1|'+$uuid)))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
 }

 $script:FreshStage='csr'
 & $helper request --state $state --machine-hash $machine;if($LASTEXITCODE){throw 'CSR_GENERATION_FAILED'}
 $request=Get-Content (Join-Path $state 'request.json') -Raw|ConvertFrom-Json
 }
 function Fresh-Artifact([string]$Path){return @{data=[Convert]::ToBase64String([IO.File]::ReadAllBytes($Path));sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()}}
 $body=@{request=$request;vps_ip=$VpsIP;rotate=[bool]$RotateCA;confirm=$ConfirmCARotation;expected_ca=$ExpectedCurrentCAFingerprint;enrollment_ca=$CaFingerprint;preflight_only=[bool]$PreflightVps;upgrade=[bool]$UpgradeVpsBinaries;upgrade_confirm=$ConfirmVpsUpgrade}
 if(!$PreflightVps){
  $body.helper=[Convert]::ToBase64String([IO.File]::ReadAllBytes($linux));$body.helper_sha256=(Get-FileHash $linux).Hash.ToLowerInvariant()
  $body.migration=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $root 'deploy\vps\rotate-fresh-pc-ca.py')))
 }
 if($PreflightVps -or $UpgradeVpsBinaries){
  $body.commit=(& git -C $root rev-parse HEAD).Trim();if($LASTEXITCODE){throw 'SOURCE_COMMIT_QUERY_FAILED'}
  $body.upgrade_script=Fresh-Artifact (Join-Path $root 'deploy\vps\fresh-vps-upgrade.py')
  $body.upgrade_engine=Fresh-Artifact (Join-Path $root 'deploy\vps\production-upgrade.py')
  if($UpgradeVpsBinaries){$body.binaries=@{relay=(Fresh-Artifact (Join-Path $bin 'linux\relay'));'control-plane'=(Fresh-Artifact (Join-Path $bin 'linux\control-plane'))}}
 }
 $payload=$body|ConvertTo-Json -Depth 7 -Compress
 $remote=[IO.File]::ReadAllText((Join-Path $root 'deploy\vps\fresh-pc-ssh.py'))
 $responsePath=Join-Path $state 'response.json'
 try{
 $script:FreshStage=if($PreflightVps){'vps_readonly_preflight'}elseif($UpgradeVpsBinaries){'vps_prepare_then_enrollment'}else{'ssh_enrollment'}
  $wire=Invoke-FreshSSH $payload $remote (Join-Path $state 'known_hosts')
  if($PreflightVps){
   $summary=$wire|ConvertFrom-Json
   if((Fresh-Property $summary 'pass') -cne $true -or (Fresh-Property $summary 'read_only') -cne $true){throw 'VPS_PREFLIGHT_FAILED'}
   Write-Host ($summary|ConvertTo-Json -Depth 7);return
  }
  [IO.File]::WriteAllText($responsePath,$wire,[Text.UTF8Encoding]::new($false))
  $reply=$wire|ConvertFrom-Json
  # This pin arrives over owner-verified SSH, NOT untrusted HTTPS. Owner can
  # supply -CaFingerprint as an independent stronger expected value.
  $pin=if($CaFingerprint -ne ''){$CaFingerprint}else{Require-FreshPin (Fresh-Property $reply 'ca_sha256')}
 $script:FreshStage='ca_and_device_verification'
  & $helper complete --state $state --ca-sha256 $pin;if($LASTEXITCODE){throw 'CA_PIN_OR_DEVICE_CERTIFICATE_REJECTED; service not installed'}
 $script:FreshStage='external_tcp_udp_probe'
  & $helper probe --state $state --vps-ip $VpsIP;if($LASTEXITCODE){throw 'REAL_CLIENT_RELAY_CHECK_FAILED; service not installed'}
 }finally{Remove-Item -LiteralPath $responsePath -Force -ErrorAction SilentlyContinue;$wire=$null;$payload=$null;$body=$null}
 # Install only after pin, device identity and real TCP/UDP relay verification.
 $script:FreshStage='service_install'
 Remove-Item (Join-Path $state 'service-install-proof.json') -Force -ErrorAction SilentlyContinue
 Invoke-FreshServicePhase -Mode $mode -Sid $sid -InProcess {
  param($installationSid)
  Install-FreshService $installationSid
 } -Elevate {
  param($installationSid)
  $scriptPath=Join-Path $PSScriptRoot 'bootstrap-fresh-pc.ps1'
  $q={param($v) "'"+$v.Replace("'","''")+"'"}
  $code='& '+(& $q $scriptPath)+' -VpsIP '+(& $q $VpsIP)+' -SSHUser '+(& $q $SSHUser)+' -SSHPort '+$SSHPort+' -ServicePhase -OwnerSid '+(& $q $installationSid)
  $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("try { $code; exit 0 } catch { Write-Error 'Service installation failed; preserved files were not deleted'; exit 1 }"))
  $child=Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-EncodedCommand',$encoded) -Wait -PassThru
  $child.WaitForExit();$child.Refresh();if($child.ExitCode -ne 0){throw 'SERVICE_INSTALL_FAILED; inspect preserved state, do not delete credentials'}
 }
 $proof=Get-Content (Join-Path $state 'service-install-proof.json') -Raw|ConvertFrom-Json
 if((Fresh-Property $proof 'owner_sid') -cne $sid -or (Fresh-Property $proof 'sha256') -ne (Get-FileHash (Join-Path $bin 'veliq-service.exe')).Hash){throw 'INSTALLED_SERVICE_PROOF_MISMATCH'}
 if((Get-FileHash (Join-Path $bin 'veliq-service.exe')).Hash -ne (Get-FileHash (Join-Path $env:ProgramData 'VELIQ\veliq-service.exe')).Hash){throw 'INSTALLED_SERVICE_HASH_MISMATCH'}
 # Installed private credentials are now SYSTEM/admin-only. Remove the owner's
 # enrollment staging copies; nothing from this boot is needed after freeze.
 Remove-Item -LiteralPath (Join-Path $state 'device\identity.json'),(Join-Path $state 'echo.token') -Force -ErrorAction Stop
 $script:FreshStage='service_startup'
 Wait-FreshServiceStartup
 $script:FreshStage='gui_install'
 & (Join-Path $PSScriptRoot 'install-desktop.ps1')
 $gui=Join-Path $env:LOCALAPPDATA 'Programs\VELIQ\VELIQ.exe'
 $report=Join-Path $state 'gui-readiness.json'
 Remove-Item $report -Force -ErrorAction SilentlyContinue
 # Silent owned PAC configuration. Browser uptake is a separate status, not a bootstrap failure.
 $script:FreshStage='pac_readiness'
 Invoke-FreshPacReadiness $gui $report
 $script:FreshStage='service_status'
 Assert-FreshSummary (Invoke-ServiceIPC 'status')
 Write-Host 'PASS: fresh identity, pinned trust, real TCP+UDP relay, installed service/GUI, owned PAC configuration and Optimize. Browser policy uptake reported separately. Website/ISP performance not asserted.'
}
if($MyInvocation.InvocationName -eq '.'){return}
try{Invoke-FreshPC}catch{if($script:FreshStage -eq 'pac_readiness'){Write-Host 'FRESH_PC_PAC_FAILURE code=GUI_PAC_READINESS_FAILED; installation retained; use local -RepairBrowserReadiness, not enroll/RotateCA'};Write-Error ('FRESH_PC_BOOTSTRAP_FAILED stage='+$script:FreshStage+' class='+$_.Exception.GetType().Name+'; installation/state preserved; see last safe stage/error code above');exit 1}
