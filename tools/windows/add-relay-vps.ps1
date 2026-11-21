#requires -Version 5.1
# Owner-only preparation/deployment. Never invoked by GUI, installation or activation.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][Alias('Host')][string]$RelayHost,
 [ValidatePattern('^[A-Za-z0-9_-]{1,64}$')][string]$Name='hostkey-ams',
 [string]$SSHKey=(Join-Path $env:USERPROFILE '.ssh\id_ed25519'),
 [string]$Manifest=(Join-Path $env:ProgramData 'neexitlag\service.json'),
 [string]$ExpectedCommit='',
 [switch]$PromotePrimary,[switch]$Rollback,[switch]$Inspect
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'owner-tools-preflight.ps1')
if(!$PromotePrimary){throw 'P0_ONLY_REQUIRES_PromotePrimary; multi-relay A-E is deferred'}
$RelayHost=Assert-VpsIPv4 $RelayHost
if($RelayHost -eq '2.56.177.4'){throw 'NEW_RELAY_MUST_NOT_BE_CONTROL_PLANE'}
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
foreach($tool in @('git','go','ssh')){if(!(Get-Command $tool -ErrorAction SilentlyContinue)){throw ('REQUIRED_TOOL_'+$tool)}}
$python=Resolve-OwnerPython
if(!(Test-Path -LiteralPath $SSHKey -PathType Leaf)){throw 'OWNER_SSH_PRIVATE_KEY_REQUIRED; contents are never printed'}
if(!$Rollback -and !$Inspect -and !(Test-Path -LiteralPath $Manifest -PathType Leaf)){throw 'ACTIVATED_OWNER_PC_MANIFEST_REQUIRED; no installation/enrollment is performed'}
$commit=(& git -C $repo rev-parse HEAD).Trim();if($LASTEXITCODE -or $commit -notmatch '^[a-f0-9]{40}$'){throw 'EXACT_COMMIT_REQUIRED'}
if($ExpectedCommit -and $ExpectedCommit -cne $commit){throw 'EXPECTED_COMMIT_MISMATCH'}
Assert-TrackedCheckout $repo
$installed=$null
if(!$Inspect -and !$Rollback){
 Assert-Administrator
 $installed=Get-Content -Raw -LiteralPath $Manifest | ConvertFrom-Json
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 if($installed.owner_sid -ne $sid){throw 'INSTALLED_OWNER_SID_REQUIRED; no ACL/identity changes'}
 $activation=Invoke-ServiceIPC 'activation.status'
 if(!$activation.has_identity -or $activation.state -ne 'ACTIVATED'){throw 'EXISTING_ACTIVATED_IDENTITY_REQUIRED'}
 # Build and compile-check the pinned DLL filters BEFORE remote mutation.
 & (Join-Path $PSScriptRoot 'build-e2e.ps1') -DriverDirectory ([string]$installed.driver.directory)
}
$bin=Join-Path $repo 'bin\relay-fleet';[void][IO.Directory]::CreateDirectory($bin)
$oldOS=$env:GOOS;$oldArch=$env:GOARCH;$oldCGO=$env:CGO_ENABLED
Push-Location $repo
try{
 $env:GOOS='linux';$env:GOARCH='amd64';$env:CGO_ENABLED='0'
 foreach($tool in @('relay','relay-admin')){
  $package=if($tool -eq 'relay'){'./services/relay/cmd/relay'}else{'./tools/relay-admin'}
  $target=Join-Path $bin $tool;Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
  & go build -trimpath -o $target $package;if($LASTEXITCODE){throw ('BUILD_FAILED_'+$tool)}
 }
 $env:GOOS='windows'
 $target=Join-Path $bin 'relay-client.exe';Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue
 & go build -trimpath -o $target './tools/relay-client';if($LASTEXITCODE){throw 'CLIENT_PROOF_BUILD_FAILED'}
}finally{$env:GOOS=$oldOS;$env:GOARCH=$oldArch;$env:CGO_ENABLED=$oldCGO;Pop-Location}
$arguments=@($python.Prefix)+@((Join-Path $repo 'deploy\vps\relay-fleet-owner.py'),'--host',$RelayHost,'--name',$Name,'--key',$SSHKey,'--bin',$bin,'--manifest',$Manifest)
if($PromotePrimary){$arguments+='--promote'}
if($Rollback){$arguments+='--rollback'}
if($Inspect){$arguments+='--inspect'}
Write-Host ('Owner relay-only operation; commit='+$commit+' host='+$RelayHost+'; no CA rotation, enrollment, activation deployment or revoke-tests')
& $python.File @arguments
if($LASTEXITCODE){throw 'RELAY_FLEET_OPERATION_FAILED; inspect safe stage/rollback report above'}

if(!$Inspect -and !$Rollback){
 try {
 # Closing only the same owner's GUI through its existing activation pipe frees
 # legacy recovery helper handles. Never terminate Chrome/Edge/game processes.
 $needsGuiClose=$false
 # Before migrate-legacy-install.ps1 the installed binary still has its old name.
 $installedService=@('veliq-service.exe','neexitlag-service.exe'|ForEach-Object{Join-Path (Split-Path -Parent $Manifest) $_})
 foreach($helper in @(Get-CimInstance Win32_Process -Filter "Name='veliq-service.exe' OR Name='neexitlag-service.exe'")){
  if($installedService -icontains [string]$helper.ExecutablePath -and [string]$helper.CommandLine -like '*--chrome-recovery*'){
   $principal=Invoke-CimMethod -InputObject $helper -MethodName GetOwnerSid
   if($principal.ReturnValue -eq 0 -and $principal.Sid -eq $sid){$needsGuiClose=$true}
  }
 }
 if($needsGuiClose){& (Join-Path $PSScriptRoot 'Close-VeliqGuiForUpdate.ps1')}
 & (Join-Path $PSScriptRoot 'update-service.ps1') -InstallDirectory (Split-Path -Parent $Manifest)
 $until=[DateTime]::UtcNow.AddSeconds(60);$ready=$false
 while([DateTime]::UtcNow -lt $until){
  try{
   $state=Invoke-ServiceIPC 'relay.primary.status'
   $status=Invoke-ServiceIPC 'status'
   if($state.configured_primary -eq ($RelayHost+':4433') -and $status.connected -and $status.optimizing -and $status.backend.ready){$ready=$true;break}
  }catch{ }
  Start-Sleep -Seconds 2
 }
 if(!$ready){throw 'NODE_DEPLOYED_CLIENT_PRIMARY_NOT_OBSERVED; old relay retained; inspect relay.primary.status'}
 } catch {Write-Host 'NODE_DEPLOYED_CLIENT_UPDATE_FAILED; remote relay may already be committed; old relay retained; inspect safe local error below';throw}
 Write-Host 'PASS node deployment + existing service update; signed VPS-PRIMARY selected for new VPS-01 policy opens. Existing identity/codes/CA unchanged; no browser/game restart. No playback PASS inferred.'
}
