# SDK preflight only; no restore, installation, credentials or VPS access.
function Initialize-ActivationNuGetSource {
 [CmdletBinding()]
 param([string]$ConfigFile='')
 $configArgs=@()
 if($ConfigFile){$configArgs=@('--configfile',$ConfigFile)}
 try {
  # Short format uses E/D independent of the SDK display language. Capture the
  # output: unrelated feed URLs may contain credentials and must not be logged.
  $sources=@(& dotnet nuget list source --format short @configArgs 2>&1)
  if($LASTEXITCODE){throw 'NUGET_SOURCE_LIST_FAILED'}
 }catch{throw 'NUGET_SOURCE_LIST_FAILED; check .NET SDK and NuGet configuration'}
 $official='^\s*E\s+https://api\.nuget\.org/v3/index\.json/?\s*$'
 if(@($sources | Where-Object { [string]$_ -match $official }).Count){
  Write-Host 'NuGet: nuget.org already enabled'
  return
 }
 if(@($sources | Where-Object { [string]$_ -match '^\s*D\s+https://api\.nuget\.org/v3/index\.json/?\s*$' }).Count){
  throw 'NUGET_ORG_SOURCE_DISABLED; enable the existing nuget.org feed in NuGet configuration'
 }
 try {
  $null=@(& dotnet nuget add source https://api.nuget.org/v3/index.json --name nuget.org @configArgs 2>&1)
  if($LASTEXITCODE){throw 'NUGET_ORG_SOURCE_ADD_FAILED'}
 }catch{throw 'NUGET_ORG_SOURCE_ADD_FAILED; check write access or a conflicting source named nuget.org; existing sources preserved'}
 Write-Host 'NuGet: added nuget.org'
}
