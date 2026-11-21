# Read-only user-mode DLL test. Never opens WinDivert or starts a driver.
[CmdletBinding()]
param(
 [string]$TestExecutable=(Join-Path $PSScriptRoot '..\..\bin\windows-e2e\capture-acceptance.exe'),
 [string]$DriverDirectory=(Join-Path $PSScriptRoot '..\..\.e2e\windivert')
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'WINDIVERT_FILTER_WINDOWS_RUNTIME_REQUIRED; cross-build is not filter proof'}
if(!(Test-Path -LiteralPath $TestExecutable -PathType Leaf)){throw 'WINDIVERT_FILTER_TEST_EXECUTABLE_REQUIRED; run build-e2e.ps1'}
if(!(Test-Path -LiteralPath $DriverDirectory)){
 & (Join-Path $PSScriptRoot 'fetch-windivert.ps1') -Destination $DriverDirectory
}
# Never overwrite a partial/modified directory. The test verifies the DLL pin.
if(!(Test-Path -LiteralPath (Join-Path $DriverDirectory 'WinDivert.dll') -PathType Leaf)){throw 'WINDIVERT_FILTER_DLL_REQUIRED; existing driver directory was not overwritten'}
$oldDriver=$env:NEEXITLAG_TEST_DRIVER_DIR;$oldRequired=$env:NEEXITLAG_REQUIRE_FILTER_COMPILER
try{
 $env:NEEXITLAG_TEST_DRIVER_DIR=(Resolve-Path -LiteralPath $DriverDirectory).Path
 $env:NEEXITLAG_REQUIRE_FILTER_COMPILER='1'
 $required=@('TestServiceFiltersCompileWithActualWinDivert','TestWinDivertCompilerRejectsLegacyGroupedNot','TestWinDivertCompilerReportsComplexityLimits','TestPrivateISCSIExcludedByActualWinDivertFilterEvaluator')
 $pattern='^(' + ($required -join '|') + ')$'
 # PS5.1 parses bare -test.run as -test followed by .run. Native dotted
 # flags MUST be quoted; keep values separate (regex has no spaces).
 $lines=@(& $TestExecutable '-test.run' $pattern '-test.v' '-test.timeout' '60s')
 $code=$LASTEXITCODE
 foreach($line in $lines){Write-Host $line}
 if($code){throw ('WINDIVERT_FILTER_COMPILATION_FAILED exit='+$code+'; service build must not be installed')}
 $text=$lines -join "`n"
 if($text -match '(?m)^\s*--- SKIP:'){throw 'WINDIVERT_FILTER_PROOF_SKIPPED; compiler tests cannot skip'}
 foreach($name in $required){if($text -notmatch ('(?m)^--- PASS: '+[regex]::Escape($name)+'\s')){throw ('WINDIVERT_FILTER_PROOF_MISSING '+$name+'; skipped/missing tests are not proof')}}
 Write-Host 'WINDIVERT_FILTERS_PASS version=2.2.2; all service layers, TCP ports/fixtures and private iSCSI semantics verified; driver_opened=false'
}finally{$env:NEEXITLAG_TEST_DRIVER_DIR=$oldDriver;$env:NEEXITLAG_REQUIRE_FILTER_COMPILER=$oldRequired}
