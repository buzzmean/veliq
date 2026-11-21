# Read-only owner IPC aggregates. Never save tokens, URLs, domains, policy values or identity.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Manifest,
      [Parameter(Mandatory=$true)][ValidatePattern('^PC[0-9]{2}$')][string]$PCId,
      [Parameter(Mandatory=$true)][ValidateSet('BeforeEnable','Enabled','AfterOff','AfterRestart')][string]$Stage,
      [Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$manifestPath=(Resolve-Path -LiteralPath $Manifest).Path
$root=Split-Path $manifestPath -Parent
$candidate=Get-Content -Raw -LiteralPath $manifestPath|ConvertFrom-Json
if($candidate.source_commit -cnotmatch '^[a-f0-9]{40}$'){throw 'BETA_SOURCE_COMMIT_INVALID'}
foreach($name in @('common.ps1','Get-BetaSnapshot.ps1')){
 $entry=@($candidate.files|Where-Object {$_.path -ceq $name})
 if($entry.Count -ne 1 -or $entry[0].sha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry[0].sha256){throw 'BETA_RUNTIME_DEPENDENCY_HASH_MISMATCH'}
}
$binary=& (Join-Path $root 'Get-BetaSnapshot.ps1') -Manifest $manifestPath -PCId $PCId
if($binary.source_commit -cne $candidate.source_commit){throw 'BETA_INSTALLED_BINARY_MISMATCH'}
. (Join-Path $root 'common.ps1')
try{$native=Invoke-ServiceIPCOnce 'browser.native.status'}catch{throw 'BETA_RUNTIME_IPC_UNAVAILABLE'}
function Read-Field($Object,[string]$Name,$Default){
 if($null -eq $Object){return $Default}
 $field=@($Object.PSObject.Properties|Where-Object {$_.Name -ceq $Name})
 if($field.Count -ne 1){return $Default};return $field[0].Value
}
function Safe-Code($Value){$text=[string]$Value;if($text -cmatch '^[A-Z][A-Z0-9_; .-]{0,159}$'){return $text};return 'UNKNOWN'}
function Safe-Count($Value){$number=[uint64]0;if([uint64]::TryParse([string]$Value,[ref]$number)){return $number};return [uint64]0}
$authority=Read-Field $native 'authority_transport' $null
$proofs=@()
foreach($profile in @(Read-Field $authority 'profiles' @())){
 $id=[string](Read-Field $profile 'profile_id' '')
 if($id -cnotmatch '^[a-zA-Z0-9._:-]{1,128}$'){$id='PROFILE'}
 $proofs+=,[ordered]@{profile_id=$id;requests=(Safe-Count (Read-Field $profile 'requests' 0));exchanges=(Safe-Count (Read-Field $profile 'exchanges' 0))}
}
$result=[ordered]@{
 schema_version=1;pc_id=$PCId.ToUpperInvariant();stage=$Stage;source_commit=$candidate.source_commit
 service_sha256=$binary.service_sha256;gui_sha256=$binary.gui_sha256
 state=(Safe-Code (Read-Field $native 'state' 'UNKNOWN'))
 reason=(Safe-Code (Read-Field $native 'reason' 'UNKNOWN'))
 capture_ready=((Read-Field $native 'capture_ready' $false) -eq $true)
 optimizing=((Read-Field $native 'optimizing' $false) -eq $true)
 authority=[ordered]@{state=(Safe-Code (Read-Field $authority 'state' 'UNKNOWN'));system_proxy_applied=((Read-Field $authority 'system_proxy_applied' $false) -eq $true);profiles=$proofs}
 measurement='LOCAL_AGGREGATES_ONLY; MANUAL_ACCEPTANCE_NOT_PROVEN'
}
$target=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 8));$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
Write-Output 'BETA_RUNTIME_EVIDENCE_SAVED; local aggregates only; manual checks remain NOT_RUN'
