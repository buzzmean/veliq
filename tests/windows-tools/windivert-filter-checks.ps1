$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
foreach($relative in @('tools/windows/test-windivert-filters.ps1','tools/windows/build-e2e.ps1','tools/windows/build-setup.ps1')){
 $tokens=$null;$errors=$null
 [Management.Automation.Language.Parser]::ParseFile((Join-Path $root $relative),[ref]$tokens,[ref]$errors)|Out-Null
 if($errors.Count){throw ($errors|Out-String)}
}
$gate=Get-Content -Raw (Join-Path $root 'tools/windows/test-windivert-filters.ps1')
foreach($name in @('TestServiceFiltersCompileWithActualWinDivert','TestWinDivertCompilerRejectsLegacyGroupedNot','TestWinDivertCompilerReportsComplexityLimits','TestPrivateISCSIExcludedByActualWinDivertFilterEvaluator','NEEXITLAG_REQUIRE_FILTER_COMPILER','WINDIVERT_FILTER_PROOF_MISSING','WINDIVERT_FILTER_WINDOWS_RUNTIME_REQUIRED')){
 if(!$gate.Contains($name)){throw ('Required DLL proof missing: '+$name)}
}
if($gate -match 'Start-Service|Stop-Service|Invoke-ServiceIPC|WinDivertOpen|\bssh\b|\bscp\b'){throw 'Compiler gate must not change service/network/VPS state'}
if(!$gate.Contains('finally{') -or !$gate.Contains('$env:NEEXITLAG_TEST_DRIVER_DIR=$oldDriver') -or !$gate.Contains('$env:NEEXITLAG_REQUIRE_FILTER_COMPILER=$oldRequired')){throw 'Fixture environment must be restored'}
$build=Get-Content -Raw (Join-Path $root 'tools/windows/build-e2e.ps1')
if($build.IndexOf("'test-windivert-filters.ps1'") -gt $build.IndexOf(' $targets=@{') -or !$build.Contains('TestServiceWinDivertFilterInventory')){throw 'DLL gate must run before building service payload'}
Write-Host 'PASS filter gate scripts parse; mandatory DLL proof precedes service build; no service/network/VPS calls. Actual DLL execution is a separate Windows test.'

# Dotted native flags must be string arguments even in Windows PowerShell5.1.
$t=$null;$e=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($gate,[ref]$t,[ref]$e)
$native=$ast.Find({param($a)$a -is [Management.Automation.Language.CommandAst] -and $a.CommandElements.Count -gt 0 -and $a.CommandElements[0].Extent.Text -eq '$TestExecutable'},$true)
if(!$native){throw 'Native compiler invocation missing'}
foreach($flag in @('-test.run','-test.v','-test.timeout')){
 $argument=@($native.CommandElements|Where-Object {$_ -is [Management.Automation.Language.StringConstantExpressionAst] -and $_.Value -eq $flag -and $_.StringConstantType -ne 'BareWord'})
 if($argument.Count -ne 1){throw ('PS51_DOTTED_NATIVE_FLAG_NOT_QUOTED '+$flag)}
}

# Execute failures before and after building a service in an isolated repo.
# No real Go/compiler/driver/installation/VPS commands are called here.
$temp=Join-Path ([IO.Path]::GetTempPath()) ('veliq-build-clean-'+[guid]::NewGuid().ToString('N'))
$global:VeliqBuildFailureFixture='early'
function go {
 $values=@($args)
 if($global:VeliqBuildFailureFixture -eq 'early'){$global:LASTEXITCODE=1;return}
 $o=[Array]::IndexOf($values,'-o')
 if($o -ge 0){
  $destination=[string]$values[$o+1]
  if($destination -like '*lease-acceptance.exe'){$global:LASTEXITCODE=2;return}
  [IO.File]::WriteAllBytes($destination,[byte[]]@(77,90))
 }
 $global:LASTEXITCODE=0
}
try{
 $scripts=Join-Path $temp 'tools\windows';New-Item -ItemType Directory -Force $scripts|Out-Null
 Copy-Item (Join-Path $root 'tools/windows/build-e2e.ps1') (Join-Path $scripts 'build-e2e.ps1')
 Set-Content -LiteralPath (Join-Path $scripts 'test-windivert-filters.ps1') -Value "param(`$TestExecutable,`$DriverDirectory); 'FAKE_DLL_GATE_ONLY_FOR_CLEANUP_TEST'" -Encoding UTF8
 $output=Join-Path $temp 'bin\windows-e2e';New-Item -ItemType Directory -Force (Join-Path $output 'linux')|Out-Null
 foreach($phase in @('early','late')){
  $global:VeliqBuildFailureFixture=$phase
  foreach($name in @('veliq-service.exe','tcp-selected.exe','capture-acceptance.exe')){Set-Content (Join-Path $output $name) 'OLD'}
  Set-Content (Join-Path $output 'linux\relay') 'OLD'
  Set-Content (Join-Path $output 'unrelated.txt') 'PRESERVE'
  $failed=$false;try{& (Join-Path $scripts 'build-e2e.ps1') -Output $output}catch{$failed=$true}
  if(!$failed){throw 'Expected build fixture failure'}
  if(@(Get-ChildItem $output -Filter '*.exe').Count -or (Test-Path (Join-Path $output 'linux\relay'))){throw ('Stale/partial binaries retained '+$phase)}
  if((Get-Content (Join-Path $output 'unrelated.txt')) -ne 'PRESERVE'){throw 'Unrelated output deleted'}
 }
 Set-Content (Join-Path $output 'service.json') '{}'
 Set-Content (Join-Path $output 'veliq-service.exe') 'INSTALLED_SENTINEL'
 $failed=$false;try{& (Join-Path $scripts 'build-e2e.ps1') -Output $output}catch{$failed=$_.Exception.Message -like 'BUILD_OUTPUT_LOOKS_INSTALLED*'}
 if(!$failed -or (Get-Content (Join-Path $output 'veliq-service.exe')) -ne 'INSTALLED_SENTINEL'){throw 'Installed state cleanup guard failed'}
}finally{
 Remove-Item Function:\go
 Remove-Variable VeliqBuildFailureFixture -Scope Global -ErrorAction SilentlyContinue
 if(Test-Path $temp){Remove-Item -LiteralPath $temp -Recurse -Force}
 $global:LASTEXITCODE=0
}
Write-Host 'PASS quoted native test flags; early/late build failures remove only generated binaries, installed config guard preserved; isolated fixture, no driver/VPS'
