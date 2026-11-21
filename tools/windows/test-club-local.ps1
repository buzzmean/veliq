# Reproducible owner-PC checks only; no install/enroll/SSH/VPS or browser shutdown.
[CmdletBinding()]param([switch]$Race)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repo
try{
 foreach($name in @('installer-build-checks','installer-package-checks','club-image-checks','club-code-checks')){& (Join-Path $repo ('tests/windows-tools/'+$name+'.ps1'))}
 $goArgs=@('test','-p','1');if($Race){$goArgs+=,'-race'}
 & go @goArgs ./core/enrollment ./core/gameudp
 if($LASTEXITCODE){throw 'CLUB_CORE_CHECKS_FAILED'}
 & go @goArgs ./services/client-service ./platform/windows -run 'Test(Club|NonClub|GameUDP|Hardware|PrivateISCSI)'
 if($LASTEXITCODE){throw 'CLUB_GO_CHECKS_FAILED'}
 . (Join-Path $PSScriptRoot 'activation-nuget.ps1');Initialize-ActivationNuGetSource
 & dotnet test tests/desktop/NeExitLag.Client.Tests.csproj --nologo
 if($LASTEXITCODE){throw 'CLUB_CSHARP_CHECKS_FAILED'}
 & dotnet build apps/desktop/Neexitlag.Desktop.csproj --nologo
 if($LASTEXITCODE){throw 'CLUB_WPF_BUILD_FAILED'}
 Write-Output 'PASS local club contracts/Go native/C#/WPF; NO Inno install, real freeze, enrollment, SSH or VPS access'
}finally{Pop-Location}
