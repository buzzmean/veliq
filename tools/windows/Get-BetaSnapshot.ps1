# Read-only local binary evidence. No IPC token, identity, policy, activation or network.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Manifest,
      [Parameter(Mandatory=$true)][ValidatePattern('^PC[0-9]{2}$')][string]$PCId,
      [string]$OutputPath='')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$manifestPath=(Resolve-Path -LiteralPath $Manifest).Path
$root=Split-Path $manifestPath -Parent
$candidate=Get-Content -Raw -LiteralPath $manifestPath|ConvertFrom-Json
if($candidate.source_commit -cnotmatch '^[a-f0-9]{40}$'){throw 'BETA_SOURCE_COMMIT_INVALID'}
function Expected-Hash([string]$Name){
 $entry=@($candidate.files|Where-Object {$_.path -ceq $Name})
 if($entry.Count -ne 1 -or $entry[0].sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'BETA_MANIFEST_ENTRY_INVALID'}
 return [string]$entry[0].sha256
}
$templatePath=Join-Path $root 'BETA_RESULTS.template.json'
if((Get-FileHash -LiteralPath $templatePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne (Expected-Hash 'BETA_RESULTS.template.json')){throw 'BETA_TEMPLATE_HASH_MISMATCH'}
$template=Get-Content -Raw -LiteralPath $templatePath|ConvertFrom-Json
$service=Get-CimInstance Win32_Service -Filter "Name='VELIQ'"
if(!$service){throw 'BETA_SERVICE_NOT_INSTALLED'}
$match=[regex]::Match([string]$service.PathName,'^\s*"([^"]+)"(?:\s|$)')
if(!$match.Success -or [IO.Path]::GetFileName($match.Groups[1].Value) -ine 'veliq-service.exe'){throw 'BETA_SERVICE_IMAGE_UNKNOWN'}
$serviceHash=(Get-FileHash -LiteralPath $match.Groups[1].Value -Algorithm SHA256).Hash.ToLowerInvariant()
$processes=@(Get-Process -Name VELIQ -ErrorAction SilentlyContinue)
$paths=@()
foreach($process in $processes){
 try{if($process.Path){$paths+=,[string]$process.Path}}catch{throw 'BETA_GUI_PATH_UNAVAILABLE'}
}
$paths=@($paths|Sort-Object -Unique)
if($processes.Count -gt 0 -and $paths.Count -eq 0){throw 'BETA_GUI_PATH_UNAVAILABLE'}
if($paths.Count -eq 0){
 foreach($path in @((Join-Path $env:ProgramFiles 'VELIQ\VELIQ.exe'),(Join-Path $env:LOCALAPPDATA 'Programs\VELIQ\VELIQ.exe'))){if(Test-Path -LiteralPath $path){$paths+=,$path}}
}
if($paths.Count -ne 1){throw 'BETA_GUI_MISSING_OR_AMBIGUOUS'}
$guiHash=(Get-FileHash -LiteralPath $paths[0] -Algorithm SHA256).Hash.ToLowerInvariant()
$source=''
if($service.State -eq 'Running' -and $serviceHash -ceq (Expected-Hash 'veliq-service.exe') -and $guiHash -ceq (Expected-Hash 'VELIQ.exe')){$source=$candidate.source_commit}
$result=[ordered]@{id=$PCId;source_commit=$source;service_sha256=$serviceHash;gui_sha256=$guiHash;checks=[ordered]@{};measurement='BINARY_HASH_ONLY; MANUAL_ACCEPTANCE_NOT_PROVEN'}
foreach($check in $template.pcs[0].checks.PSObject.Properties){$result.checks[$check.Name]=[ordered]@{status='NOT_RUN';evidence='';sha256=''}}
if($OutputPath){
 $target=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
 $stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 8))
  $stream.Write($bytes,0,$bytes.Length)
 }finally{$stream.Dispose()}
 Write-Output 'BETA_SNAPSHOT_SAVED; binary hashes only; manual checks remain NOT_RUN'
}else{[pscustomobject]$result}
