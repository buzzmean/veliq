[CmdletBinding()]
param([string]$Output=(Join-Path $PSScriptRoot '..\..\bin\release'),[string]$Version='')
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if(!(Get-Command dotnet -ErrorAction SilentlyContinue)){throw 'Install .NET SDK 8 to build the desktop app.'}
New-Item $Output -ItemType Directory -Force|Out-Null
$Output=(Resolve-Path $Output).Path
# Same numbering as publish-release.ps1 (0.3.<commit count>), so the About screen shows the release version.
if(!$Version){$count=(& git -C $root rev-list --count HEAD 2>$null);$Version=if($LASTEXITCODE -eq 0 -and $count){'0.3.'+$count.Trim()}else{'0.3.0'}}
& dotnet publish (Join-Path $root 'apps\desktop\Neexitlag.Desktop.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:PublishTrimmed=false -p:DebugType=None -p:DebugSymbols=false -p:Version=$Version -o $Output --nologo
if($LASTEXITCODE){throw 'VELIQ desktop build failed.'}
if(!(Test-Path (Join-Path $Output 'VELIQ.exe'))){throw 'VELIQ executable was not created.'}
Write-Host "Ready: $(Join-Path $Output 'VELIQ.exe')"
# Identical compatibility entry point for existing shortcuts and HKCU Run values.
Remove-Item -LiteralPath (Join-Path $Output 'NeExitLag.exe') -Force -ErrorAction SilentlyContinue
Write-Host 'Run the desktop app as a standard user authorized to access the service.'

$scripts=Join-Path $Output 'tools\windows'
New-Item -ItemType Directory -Force $scripts|Out-Null
Copy-Item (Join-Path $PSScriptRoot '*.ps1') $scripts -Force
