# Invoke with real Windows PowerShell 5.1 in CI. Exercise the production wrapper
# with a deterministic dotnet boundary; publishing the actual GUI is another step.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($PSVersionTable.PSVersion.Major -ne 5){throw 'This regression requires Windows PowerShell 5.1'}
$script=Join-Path $PSScriptRoot '..\..\tools\windows\build-desktop.ps1'
$bytes=[IO.File]::ReadAllBytes((Resolve-Path $script))
if(@($bytes|Where-Object{$_ -gt 127}).Count){throw 'PS5.1 production wrapper must be ASCII-only'}
$output=Join-Path ([IO.Path]::GetTempPath()) ('neexitlag-build-ps51-'+[Guid]::NewGuid().ToString('N'))
$global:neexitlagDesktopPublishFixture=@{published=$false}
function dotnet {
 $values=@($args);$index=[Array]::IndexOf($values,'-o');if($values[0] -ne 'publish' -or $index -lt 0){throw 'Unexpected publish command'}
 [IO.File]::WriteAllBytes((Join-Path $values[$index+1] 'VELIQ.exe'),[byte[]]@(77,90));$global:neexitlagDesktopPublishFixture.published=$true;$global:LASTEXITCODE=0
}
try{& $script -Output $output;if(!$global:neexitlagDesktopPublishFixture.published -or !(Test-Path (Join-Path $output 'VELIQ.exe'))){throw 'PS5.1 wrapper did not execute publish'};if(Test-Path (Join-Path $output 'NeExitLag.exe')){throw 'Legacy NeExitLag.exe alias must not be published'};Write-Host 'PASS real PS5.1 build-desktop parsing and execution'}finally{Remove-Variable neexitlagDesktopPublishFixture -Scope Global -ErrorAction SilentlyContinue;Remove-Item Function:\dotnet;Remove-Item $output -Recurse -Force -ErrorAction SilentlyContinue}
