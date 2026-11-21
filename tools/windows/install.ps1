# Run from an elevated PowerShell after building the service and provisioning device credentials.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$ServiceExecutable,
 [Parameter(Mandatory=$true)][string]$OwnerSid,
 [string]$DeviceDirectory="",
 [switch]$ActivationOnly,
 [Parameter(Mandatory=$true)][string]$TrustDirectory,
 [Parameter(Mandatory=$true)][string]$DriverDirectory,
 [Parameter(Mandatory=$true)][string]$DllSha256,
 [Parameter(Mandatory=$true)][string]$DriverSha256,
 [Parameter(Mandatory=$true)][string]$ControlPlaneUrl,
 [Parameter(Mandatory=$true)][string]$ProbeTarget,
 [string]$TCPProbeTarget="",
 [string]$ProbeTokenFile="",
 [string]$InstallDirectory="$env:ProgramData\VELIQ",
 [switch]$Reinstall,
 [switch]$NativeTcpFirewall=$true
)
$ErrorActionPreference="Stop"
. (Join-Path $PSScriptRoot "common.ps1")
. (Join-Path $PSScriptRoot "service-startup.ps1")
. (Join-Path $PSScriptRoot "native-tcp-firewall.ps1")
. (Join-Path $PSScriptRoot "reinstall-state.ps1")
$current=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(!$current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw "Administrator access is required to install the service."}
if(Get-Service VELIQ -ErrorAction SilentlyContinue){throw "Service already installed. Run uninstall.ps1 to stop/remove SCM while preserving files, then install/setup-e2e with -Reinstall."}
[void][Security.Principal.SecurityIdentifier]::new($OwnerSid)
$ServiceExecutable=(Resolve-Path $ServiceExecutable).Path
$DriverDirectory=(Resolve-Path $DriverDirectory).Path
if($DllSha256 -notmatch '^[0-9a-fA-F]{64}$' -or $DriverSha256 -notmatch '^[0-9a-fA-F]{64}$'){throw "SHA256 pins must be provided from a trusted WinDivert distribution."}
foreach($pair in @(@("WinDivert.dll",$DllSha256),@("WinDivert64.sys",$DriverSha256))){if((Get-FileHash (Join-Path $DriverDirectory $pair[0]) -Algorithm SHA256).Hash -ne $pair[1]){throw "WinDivert hash mismatch: $($pair[0])"}}
$sources=@{'ca.pem'=(Join-Path $TrustDirectory 'ca.pem')}
if(!$ActivationOnly){
 if($DeviceDirectory -eq ''){throw 'DeviceDirectory required without -ActivationOnly'}
 $sources['identity.json']=Join-Path $DeviceDirectory 'identity.json';$sources['device.pem']=Join-Path $DeviceDirectory 'device.pem';$sources['trust.json']=Join-Path $TrustDirectory 'trust.json'
}elseif(Test-Path -LiteralPath (Join-Path $TrustDirectory 'trust.json')){$sources['trust.json']=Join-Path $TrustDirectory 'trust.json'}
$cpCA=Join-Path $TrustDirectory 'cp-ca.pem'
if(Test-Path -LiteralPath $cpCA){$sources['cp-ca.pem']=$cpCA}
if($ProbeTokenFile -ne ''){$sources['probe.token']=$ProbeTokenFile}
foreach($source in $sources.Values){if(!(Test-Path -LiteralPath $source -PathType Leaf)){throw 'Required credential/trust input is missing; installation not modified'}}
$preserved=Assert-ServiceInstallState $InstallDirectory -Reinstall:$Reinstall -OwnerSid $OwnerSid -ControlPlaneUrl $ControlPlaneUrl -ProbeTarget $ProbeTarget -Sources $sources
if($null -ne $preserved -and !$PSBoundParameters.ContainsKey('TCPProbeTarget')){$TCPProbeTarget=$preserved.tcp_probe_target}
$tokenFile=Join-Path $InstallDirectory 'ipc.token'
if(Test-Path -LiteralPath $tokenFile){
 try {if([Convert]::FromBase64String([IO.File]::ReadAllText($tokenFile).Trim()).Length -ne 32){throw 'length'}}catch{throw 'Preserved IPC token is invalid; refusing to silently rotate it'}
}
New-Item -ItemType Directory -Force -Path $InstallDirectory -ErrorAction Stop | Out-Null
Protect-ServiceDirectory $InstallDirectory $OwnerSid
Copy-Item $ServiceExecutable (Join-Path $InstallDirectory "veliq-service.exe")
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDirectory "driver") | Out-Null
Copy-Item (Join-Path $DriverDirectory "WinDivert.dll") (Join-Path $InstallDirectory "driver")
Copy-Item (Join-Path $DriverDirectory "WinDivert64.sys") (Join-Path $InstallDirectory "driver")
foreach($name in $sources.Keys){Copy-ServiceCredential $sources[$name] (Join-Path $InstallDirectory $name)}
if(!(Test-Path -LiteralPath $tokenFile)){
$bytes=New-Object byte[] 32
$rng=[Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$token=[Convert]::ToBase64String($bytes)
[IO.File]::WriteAllText($tokenFile,$token,[Text.UTF8Encoding]::new($false))
}
New-Item -ItemType Directory -Force -Path (Join-Path $InstallDirectory "state") | Out-Null
$manifest=@{owner_sid=$OwnerSid;token_file=$tokenFile;state_directory=(Join-Path $InstallDirectory "state");control_plane_url=$ControlPlaneUrl;trust_file=(Join-Path $InstallDirectory "trust.json");device_identity_file=(Join-Path $InstallDirectory "identity.json");device_certificate=(Join-Path $InstallDirectory "device.pem");ca_file=(Join-Path $InstallDirectory "ca.pem");probe_target=$ProbeTarget;tcp_probe_target=$TCPProbeTarget;driver=@{directory=(Join-Path $InstallDirectory "driver");dll_sha256=$DllSha256;driver_sha256=$DriverSha256}}
if(Test-Path -LiteralPath (Join-Path $InstallDirectory "probe.token")){$manifest.probe_token_file=(Join-Path $InstallDirectory "probe.token")}
if(Test-Path -LiteralPath (Join-Path $InstallDirectory 'cp-ca.pem')){$manifest.control_plane_ca_file=(Join-Path $InstallDirectory 'cp-ca.pem')}
if($null -ne $preserved){foreach($property in $preserved.PSObject.Properties){if(!$manifest.ContainsKey($property.Name)){$manifest[$property.Name]=$property.Value}}}
# Pin the already verified public CA at installation; never trust an enroll reply as CA.
$activationCA=Join-Path $InstallDirectory 'cp-ca.pem';if(!(Test-Path $activationCA)){$activationCA=Join-Path $InstallDirectory 'ca.pem'}
$publicCert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 $activationCA
$caHash=[Security.Cryptography.SHA256]::Create();try{$manifest.activation_ca_sha256=([BitConverter]::ToString($caHash.ComputeHash($publicCert.RawData))).Replace('-','').ToLowerInvariant()}finally{$caHash.Dispose();$publicCert.Dispose()}
$manifestPath=Join-Path $InstallDirectory "service.json"
[IO.File]::WriteAllText($manifestPath,($manifest|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
Protect-ServiceDirectory $InstallDirectory $OwnerSid
$binary='"'+(Join-Path $InstallDirectory "veliq-service.exe")+'" -config "'+$manifestPath+'"'
New-Service -Name VELIQ -BinaryPathName $binary -DisplayName "VELIQ Routing Service" -StartupType Automatic | Out-Null
Set-VeliqServiceAutomatic
& sc.exe failure VELIQ reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
if($LASTEXITCODE){throw "Failed to configure service recovery"}
# Owner-authorized native browser TCP requires this app-scoped inbound reflection rule.
# Installing a rule does not load WinDivert or activate traffic before enrollment.
if($NativeTcpFirewall){[void](Add-NativeTcpFirewallAdmission (Join-Path $InstallDirectory 'veliq-service.exe'))}
Start-Service VELIQ
(Get-Service VELIQ).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
Write-Host "VELIQ service installed. Run the desktop GUI without elevation."

. (Join-Path $PSScriptRoot 'browser-policy-watchdog.ps1')
Install-VeliqPolicyWatchdog $InstallDirectory
