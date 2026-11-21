# One owner build command. The public Setup never contains a code or device identity.
[CmdletBinding()]
param(
 [string]$PublicTrustDirectory=(Join-Path $PSScriptRoot '..\..\.e2e\activation-trust'),
 [string]$ControlPlaneUrl='https://146.0.77.98:8443',
 [string]$ProbeTarget='146.0.77.98:40000',
 [string]$TCPProbeTarget='146.0.77.98:40000',
 [string]$Compiler='',
 [string]$ExpectedCommit='',
 [string]$Output=(Join-Path $PSScriptRoot '..\..\bin\installer')
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repo 'installer\build-support.ps1')
foreach($name in @('git','go','dotnet')){if(!(Get-Command $name -ErrorAction SilentlyContinue)){throw ('BUILD_TOOL_REQUIRED_'+$name)}}
$head=(& git -C $repo rev-parse HEAD).Trim();if($LASTEXITCODE -or $head -notmatch '^[a-f0-9]{40}$'){throw 'EXACT_BUILD_COMMIT_REQUIRED'}
if($ExpectedCommit -and $ExpectedCommit -cne $head){throw 'BUILD_EXPECTED_COMMIT_MISMATCH'}
$dirty=@(& git -C $repo status --porcelain --untracked-files=no);if($LASTEXITCODE -or $dirty.Count){throw 'BUILD_TRACKED_CHANGES_PRESENT; commit or preserve changes before packaging'}
$sdks=@(& dotnet --list-sdks);if($LASTEXITCODE -or !@($sdks|Where-Object {$_ -match '^8\.'}).Count){throw 'DOTNET_SDK_8_REQUIRED; runtime alone is insufficient'}
$trust=(Resolve-Path -LiteralPath $PublicTrustDirectory).Path
Assert-VeliqPublicCA (Join-Path $trust 'ca.pem')
$resolved=Resolve-VeliqInnoCompiler $Compiler
if(!$resolved){
 if($Compiler){throw 'INNO_EXPLICIT_COMPILER_NOT_FOUND'}
 if(!(Get-Command winget.exe -ErrorAction SilentlyContinue)){throw 'WINGET_REQUIRED_TO_INSTALL_APPROVED_INNO_SETUP_6_4_3'}
 & winget.exe install --id JRSoftware.InnoSetup --exact --version 6.4.3 --source winget --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
 if($LASTEXITCODE){throw 'INNO_SETUP_INSTALL_FAILED; no Setup was built'}
 $resolved=Resolve-VeliqInnoCompiler
}
Assert-VeliqInnoCompiler $resolved
. (Join-Path $PSScriptRoot 'activation-nuget.ps1')
Initialize-ActivationNuGetSource
& (Join-Path $PSScriptRoot 'build-e2e.ps1')
& (Join-Path $PSScriptRoot 'build-desktop.ps1')
$driver=Join-Path $repo '.e2e\windivert'
if(!(Test-Path -LiteralPath $driver)){& (Join-Path $PSScriptRoot 'fetch-windivert.ps1')}
# build-e2e already enforced the mandatory pinned-DLL compiler/evaluator gate.

$stage=Join-Path $repo ('bin\installer-staging\'+$head.Substring(0,12)+'-'+[Guid]::NewGuid().ToString('N'))
# Copy only the already validated PUBLIC CA. Input folder may contain owner-only
# working files, none of which is included in the release payload.
$public=Join-Path $stage 'trust';[void][IO.Directory]::CreateDirectory($public)
Copy-Item -LiteralPath (Join-Path $trust 'ca.pem') -Destination (Join-Path $public 'ca.pem')
try{
 & (Join-Path $repo 'installer\build.ps1') -PublicTrustDirectory $public -ControlPlaneUrl $ControlPlaneUrl -ProbeTarget $ProbeTarget -TCPProbeTarget $TCPProbeTarget -Compiler $resolved -Output (Join-Path $stage 'compiled')
 $out=[IO.Path]::GetFullPath($Output);[void][IO.Directory]::CreateDirectory($out)
 foreach($name in @('VELIQ-Setup.exe','SHA256SUMS')){
  $source=Join-Path $stage ('compiled\output\'+$name);$target=Join-Path $out $name;$temp=$target+'.pending'
  Copy-Item -LiteralPath $source -Destination $temp -Force
  if(Test-Path -LiteralPath $target){[IO.File]::Replace($temp,$target,[NullString]::Value)}else{[IO.File]::Move($temp,$target)}
 }
 $hash=(Get-FileHash -LiteralPath (Join-Path $out 'VELIQ-Setup.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
 Write-Output ('SETUP_BUILD_PASS commit='+$head+' sha256='+$hash+' file='+(Join-Path $out 'VELIQ-Setup.exe')+' signing=UNSIGNED_PILOT')
}finally{if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}}
