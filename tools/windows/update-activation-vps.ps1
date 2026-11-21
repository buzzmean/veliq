# Explicit owner-only release. Never invoked by installation or GUI.
[CmdletBinding()]
param(
 [ValidateSet('2.56.177.4')][string]$VpsIP='2.56.177.4',
 [ValidatePattern('^[a-z_][a-z0-9_-]{0,31}$')][string]$SSHUser='root',
 [ValidateRange(1,65535)][int]$SSHPort=22,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedCommit,
 [Parameter(Mandatory=$true)][ValidateSet('ACTIVATE-CODES-2.56.177.4')][string]$ConfirmDeployment
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
# This transport does not load fresh bootstrap or trigger enrollment.
. (Join-Path $PSScriptRoot 'activation-ssh.ps1')
$state=Join-Path $root '.e2e\fresh-pc'
$commit=(& git -C $root rev-parse HEAD).Trim()
if($LASTEXITCODE -or $commit -cne $ExpectedCommit){throw 'EXACT_RELEASE_COMMIT_MISMATCH'}
$dirty=& git -C $root status --porcelain --untracked-files=normal
if($LASTEXITCODE -or $dirty){throw 'CLEAN_RELEASE_CHECKOUT_REQUIRED; keep untracked reports outside release checkout; never add credentials to git'}
$bin=Join-Path $root 'bin\activation-release'
New-Item -ItemType Directory -Path $bin -Force|Out-Null
$oldOS=$env:GOOS;$oldArch=$env:GOARCH;$oldCGO=$env:CGO_ENABLED
Push-Location $root
try{
 $env:GOOS='linux';$env:GOARCH='amd64';$env:CGO_ENABLED='0'
 foreach($item in @(@('relay','./services/relay/cmd/relay'),@('control-plane','./services/control-plane/cmd/control-plane'),@('fresh-pc','./tools/fresh-pc'),@('codes','./tools/codes'))){
  & go build -trimpath -o (Join-Path $bin $item[0]) $item[1]
  if($LASTEXITCODE){throw 'RELEASE_BUILD_FAILED'}
 }
}finally{$env:GOOS=$oldOS;$env:GOARCH=$oldArch;$env:CGO_ENABLED=$oldCGO;Pop-Location}
$files=@{}
foreach($name in @('inspect-activation.py','activation-diagnostics.py','deploy-activation.py','fresh-vps-upgrade.py','renew-server-cert.py','veliq-certificate-renewal.service','veliq-certificate-renewal.timer','92-veliq-activation.conf','production-engine.py','fresh-pc','codes','relay','control-plane')){
 $path=if($name -in @('fresh-pc','codes','relay','control-plane')){Join-Path $bin $name}elseif($name -eq 'production-engine.py'){Join-Path $root 'deploy\vps\production-upgrade.py'}else{Join-Path (Join-Path $root 'deploy\vps') $name}
 $files[$name]=@{data=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path));sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}
}
New-Item -ItemType Directory -Force -Path $state|Out-Null
$payload=@{commit=$commit;confirm=$ConfirmDeployment;files=$files}|ConvertTo-Json -Depth 6 -Compress
$remote=[IO.File]::ReadAllText((Join-Path $root 'deploy\vps\activation-release-ssh.py'))
Write-Host 'Owner-authorized existing VPS update. No CA rotation; DB security records preserved. One host-verified SSH session.'
Invoke-ActivationSSH -Payload $payload -RemoteCode $remote -KnownHosts (Join-Path $state 'known_hosts') -VpsIP $VpsIP -SSHUser $SSHUser -SSHPort $SSHPort|Write-Host
