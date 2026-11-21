# Local equivalent of activation-windows CI. Tests/build only: never install/enroll/SSH.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'NATIVE_WINDOWS_REQUIRED'}
if($PSVersionTable.PSVersion.Major -ne 5){throw 'WINDOWS_POWERSHELL_5_1_REQUIRED'}
foreach($tool in @('git','go','dotnet','python')){if(!(Get-Command $tool -ErrorAction SilentlyContinue)){throw ('TEST_DEPENDENCY_REQUIRED: '+$tool)}}
$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $root
try{
 . (Join-Path $PSScriptRoot 'activation-nuget.ps1')
 Initialize-ActivationNuGetSource
 & (Join-Path $root 'tests/windows-tools/activation-nuget-checks.ps1')
 & go test -p 1 ./platform/windows ./services/client-service ./services/client-service/cmd/service -run Activation -count=1
 if($LASTEXITCODE){throw 'NATIVE_ACTIVATION_TESTS_FAILED'}
 & go test ./tools/fresh-pc -run '^TestUpgradeCapabilityAndJournalContracts$' -count=1
 if($LASTEXITCODE){throw 'HELPER_JOURNAL_TESTS_FAILED'}
 & dotnet test tests/desktop/NeExitLag.Client.Tests.csproj --nologo
 if($LASTEXITCODE){throw 'DESKTOP_TESTS_FAILED'}
 & dotnet build apps/desktop/Neexitlag.Desktop.csproj --nologo
 if($LASTEXITCODE){throw 'DESKTOP_BUILD_FAILED'}
 foreach($p in @('install','stage-club-activation','update-activation-vps','activation-ssh','verify-activation-vps')) {
  $tokens=$null;$errors=$null
  [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $root ('tools/windows/'+$p+'.ps1')),[ref]$tokens,[ref]$errors)
  if($errors.Count){throw ('PS_PARSE_FAILED: '+$p+'; '+($errors.Message -join ';'))}
 }
 & .\tests\windows-tools\activation-deploy-checks.ps1
 if($LASTEXITCODE){throw 'SSH_FIXTURE_FAILED'}
 Write-Host 'PASS local native Windows activation, C#, WPF, PS5.1/fake SSH fixture; no installation or VPS access'
}finally{Pop-Location}
