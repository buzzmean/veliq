[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$PublicTrustDirectory,[Parameter(Mandatory=$true)][string]$ControlPlaneUrl,[Parameter(Mandatory=$true)][string]$ProbeTarget,[string]$TCPProbeTarget='',[switch]$Fixture, [string]$Output=(Join-Path $PSScriptRoot '..\bin\installer'),[string]$Compiler='C:\Program Files (x86)\Inno Setup 6\ISCC.exe')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
. (Join-Path $PSScriptRoot 'build-support.ps1')
Assert-VeliqInnoCompiler $Compiler
$trust=(Resolve-Path $PublicTrustDirectory).Path
if(@(Get-ChildItem -LiteralPath $trust -File | Where-Object {$_.Name -notin @('ca.pem')}).Count){throw 'PUBLIC_TRUST_DIRECTORY_MUST_CONTAIN_ONLY_CA'}
$caText=[IO.File]::ReadAllText((Join-Path $trust 'ca.pem'));if($caText -match 'PRIVATE KEY' -or $caText -notmatch 'BEGIN CERTIFICATE'){throw 'PUBLIC_CA_REQUIRED'}
Assert-VeliqPublicCA (Join-Path $trust 'ca.pem')
$ca=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $trust 'ca.pem'))
$hash=[Security.Cryptography.SHA256]::Create();try{$pin=([BitConverter]::ToString($hash.ComputeHash($ca.RawData))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose();$ca.Dispose()}
$head=(& git -C $repo rev-parse HEAD).Trim();if($LASTEXITCODE -or $head -notmatch '^[0-9a-f]{40}$'){throw 'EXACT_BUILD_COMMIT_REQUIRED'}
$payload=Join-Path $Output 'payload';if(Test-Path $payload){throw 'OUTPUT_ALREADY_EXISTS'}
foreach($dir in @('service','gui','driver','public','installer','tools\windows')){[void][IO.Directory]::CreateDirectory((Join-Path $payload $dir))}
Copy-Item (Join-Path $repo 'bin\windows-e2e\veliq-service.exe') (Join-Path $payload 'service')
foreach($f in @('VELIQ.exe')){Copy-Item (Join-Path $repo ('bin\release\'+$f)) (Join-Path $payload 'gui')}
foreach($f in @('WinDivert.dll','WinDivert64.sys','pins.json','WinDivert-LICENSE.txt','SOURCE.txt')){Copy-Item (Join-Path $repo ('.e2e\windivert\'+$f)) (Join-Path $payload 'driver')}
foreach($f in @('common','install','update-service','migrate-legacy-install','uninstall','reinstall-state','install-desktop','native-tcp-firewall','browser-policy-watchdog','service-startup','stage-club-activation','Get-ClubStatus','club-code-common','New-ClubCodeFile','Set-ClubActivationCode','club-image-common','configure-club-image','club-image-boot')){Copy-Item (Join-Path $repo ('tools\windows\'+$f+'.ps1')) (Join-Path $payload 'tools\windows')}
foreach($f in @('install-package.ps1','package-contract.ps1','install-safety.ps1')){Copy-Item (Join-Path $PSScriptRoot $f) (Join-Path $payload 'installer')}
Copy-Item (Join-Path $trust 'ca.pem') (Join-Path $payload 'public')
@{fixture=[bool]$Fixture;control_plane_url=$ControlPlaneUrl;probe_target=$ProbeTarget;tcp_probe_target=$TCPProbeTarget;ca_der_sha256=$pin}|ConvertTo-Json|Set-Content (Join-Path $payload 'public\release.json') -Encoding UTF8
$files=@(Get-ChildItem -LiteralPath $payload -Recurse -File|ForEach-Object {@{path=$_.FullName.Substring([IO.Path]::GetFullPath($payload).Length+1).Replace('\','/');sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}})
@{product='VELIQ';commit=$head;files=$files}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $payload 'package.json') -Encoding UTF8
. (Join-Path $PSScriptRoot 'package-contract.ps1');Assert-VeliqPackage $payload -ForPackaging
& $Compiler ('/DStageRoot='+[IO.Path]::GetFullPath($Output)) (Join-Path $PSScriptRoot 'setup.iss')
if($LASTEXITCODE){throw 'INNO_BUILD_FAILED'}
Get-FileHash (Join-Path $Output 'output\VELIQ-Setup.exe') -Algorithm SHA256|ForEach-Object {($_.Hash.ToLowerInvariant()+'  VELIQ-Setup.exe')}|Set-Content (Join-Path $Output 'output\SHA256SUMS') -Encoding ASCII
