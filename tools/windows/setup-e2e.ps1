[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$VpsPublicIP,
 [Parameter(Mandatory=$true)][string]$SSHUser,
 [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$SSHPort,
 [string]$DriverDirectory=(Join-Path $PSScriptRoot '..\..\.e2e\windivert'),
 [switch]$Reinstall
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Administrator
$VpsPublicIP=Assert-VpsIPv4 $VpsPublicIP
Assert-Ssh $SSHUser $SSHPort
if(Get-Service VELIQ -ErrorAction SilentlyContinue){throw 'Existing Windows service found; preserve it and use a separate test PC or an explicit uninstall/rollback followed by setup-e2e.ps1 -Reinstall.'}
$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$output=Join-Path $root 'bin\windows-e2e'
& (Join-Path $PSScriptRoot 'build-e2e.ps1') -Output $output
if(!(Test-Path (Join-Path $DriverDirectory 'pins.json'))){& (Join-Path $PSScriptRoot 'fetch-windivert.ps1') -Destination $DriverDirectory}
$state=Join-Path $root '.e2e'
New-Item -ItemType Directory -Force $state|Out-Null
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls $state /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$($owner):(OI)(CI)F"|Out-Null
if($LASTEXITCODE){throw 'Failed to protect private E2E bundle'}
$bundle=Join-Path $state 'bundle'
if(Test-Path $bundle){
 $prior=Get-Content (Join-Path $bundle 'deployment.json') -Raw|ConvertFrom-Json
 if($prior.vps_public_ip -ne $VpsPublicIP){throw 'Existing private bundle belongs to another VPS; refusing to replace it'}
} else {
 & (Join-Path $output 'vps-provision.exe') -vps-ip $VpsPublicIP -out $bundle
 if($LASTEXITCODE){throw 'Provisioning failed; bundle was not overwritten'}
}
$caHash=(Get-FileHash (Join-Path $bundle 'server\ca.pem') -Algorithm SHA256).Hash.ToLowerInvariant()
$check='if test -d /etc/neexitlag; then sudo -n test -r /etc/neexitlag/control/ca.pem || exit 1; sudo -n sha256sum /etc/neexitlag/control/ca.pem; grep -Fx "VPS_PUBLIC_IP=__IP__" /etc/neexitlag/public/relay.env || exit 1; else echo NEW; fi'.Replace('__IP__',$VpsPublicIP)
$remoteState=@(Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort $check)
if($remoteState -contains 'NEW'){
 $upload='/tmp/neexitlag-e2e-'+[Guid]::NewGuid().ToString('N')
 Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort "umask 077; mkdir -p $upload"
 $tempUpload=Join-Path $state ('upload-'+[Guid]::NewGuid().ToString('N'))
 New-Item -ItemType Directory $tempUpload|Out-Null
 try {
  Copy-Item (Join-Path $bundle 'server') $tempUpload -Recurse
  Copy-Item (Join-Path $output 'linux') (Join-Path $tempUpload 'bin') -Recurse
  Copy-Item (Join-Path $root 'deploy\vps') (Join-Path $tempUpload 'units') -Recurse
  Convert-DeploymentToLF (Join-Path $tempUpload 'units')
  & scp -o BatchMode=yes -o StrictHostKeyChecking=yes -P $SSHPort -r "$tempUpload/." "${SSHUser}@${VpsPublicIP}:$upload/"
  if($LASTEXITCODE){throw 'Private upload failed; verify SSH authentication and host key'}
  Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort "sudo -n bash $upload/units/install.sh $upload $VpsPublicIP"
 } finally {
  try {Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort "rm -rf $upload"}finally{Remove-Item $tempUpload -Recurse -Force}
 }
} else {
 if(!@($remoteState|Where-Object{$_ -like "$caHash *"}).Count){throw 'Existing VPS deployment has different CA trust; refusing to overwrite it'}
 Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort 'sudo -n systemctl start neexitlag-control-plane neexitlag-relay neexitlag-echo'
}
# Provider/host firewall must permit TCP8443, UDP4433 and UDP40000 before enrollment.
$windows=Join-Path $bundle 'windows'
if(!(Test-Path (Join-Path $windows 'device\device.pem'))){
 & (Join-Path $output 'enroll.exe') -control-plane "https://${VpsPublicIP}:8443" -ca (Join-Path $windows 'trust\cp-ca.pem') -state (Join-Path $windows 'device') -name 'Windows real E2E' -admin-token-file (Join-Path $windows 'admin.token')
 if($LASTEXITCODE){throw 'Remote enrollment failed; open documented ingress ports, then rerun with the same protected bundle. No acceptance claimed.'}
}
# Bootstrap token is not a normal service credential.
Remove-Item (Join-Path $windows 'admin.token') -Force -ErrorAction SilentlyContinue
$pins=Get-Content (Join-Path $DriverDirectory 'pins.json') -Raw|ConvertFrom-Json
& (Join-Path $PSScriptRoot 'install.ps1') -Reinstall:$Reinstall -ServiceExecutable (Join-Path $output 'veliq-service.exe') -OwnerSid $owner -DeviceDirectory (Join-Path $windows 'device') -TrustDirectory (Join-Path $windows 'trust') -DriverDirectory $DriverDirectory -DllSha256 $pins.dll_sha256 -DriverSha256 $pins.driver_sha256 -ControlPlaneUrl "https://${VpsPublicIP}:8443" -ProbeTarget "${VpsPublicIP}:40000" -ProbeTokenFile (Join-Path $windows "echo.token")
Write-Host 'Backend enrolled and Windows service installed. Run acceptance.ps1; no runtime PASS is inferred from installation.'
