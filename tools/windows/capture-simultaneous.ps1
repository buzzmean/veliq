[CmdletBinding()]
param(
 [ValidateRange(10,600)][int]$DurationSeconds=120,
 [ValidateRange(100,2000)][int]$PollMilliseconds=500,
 [ValidateRange(32,4096)][int]$MaxPages=2048,
 [string]$RelayId='VPS-01',
 [string[]]$RequiredProcesses=@('msedge.exe','ChatGPT.exe','codex.exe','Discord.exe'),
 [string]$ReportDirectory=(Join-Path $PSScriptRoot '..\..\bin\simultaneous')
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'simultaneous-checks.ps1')
$run=Join-Path $ReportDirectory ([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
New-Item -ItemType Directory -Path $run -Force|Out-Null
$state=@{Cursor=$null;Flows=@{};Lost=$false}
$pageNumber=0;$sample=0;$failure=$null;$captureComplete=$false
function Save-SimJson($Value,[string]$Name){$Value|ConvertTo-Json -Depth 28|Set-Content -LiteralPath (Join-Path $run $Name) -Encoding UTF8}
function Receive-SimPages {
 for($batch=0;$batch -lt 128;$batch++){
  if($watch.Elapsed.TotalSeconds -gt ($DurationSeconds+15)){throw 'Capture wall-time bound exceeded: incomplete evidence'}
  if($script:pageNumber -ge $MaxPages){throw 'Capture page/disk bound reached: incomplete evidence'}
  $page=Invoke-ServiceIPC 'capture.changes' @{cursor=$state.Cursor}
  Save-SimJson $page ('page-{0:D5}.json' -f $script:pageNumber);$script:pageNumber++
  $more=Merge-SimPage $state $page
  if(!$more){return}
 }
 throw 'Capture did not drain within bounded batch: incomplete evidence'
}
try{
 $state.Cursor=Invoke-ServiceIPC 'capture.changes.marker'
 Save-SimJson (Invoke-ServiceIPC 'quality.diagnostics') 'quality-before.json'
 Save-SimJson (Invoke-ServiceIPC 'status') 'status-before.json'
 Write-Host 'Capture started. With Happ OFF, now start Chrome YouTube, Edge ChatGPT, ChatGPT/Codex and Discord together.'
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while($watch.Elapsed.TotalSeconds -lt $DurationSeconds){
  Receive-SimPages
  Save-SimJson (Invoke-ServiceIPC 'relay.pool.diagnostics' @{relay_id=$RelayId}) ('pool-{0:D4}.json' -f $sample)
  $sample++;Start-Sleep -Milliseconds $PollMilliseconds
 }
 Receive-SimPages
 $after=Invoke-ServiceIPC 'quality.diagnostics';Save-SimJson $after 'quality-after.json'
 $before=Get-Content -LiteralPath (Join-Path $run 'quality-before.json') -Raw|ConvertFrom-Json
 $captureComplete=$true
 $proof=Get-SimProof $state $RequiredProcesses
 Add-SimDropGates $proof $before $after
 Save-SimJson $proof 'proof.json'
 if(!$proof.transport_evidence_pass){throw 'Transport evidence gate failed; inspect proof, pages, per-flow open/queue diagnostics and pool samples'}
 Write-Host "TRANSPORT EVIDENCE PASS. Application loading, video and Discord voice still require operator observations. Reports: $run"
}catch{
 $failure=$_.Exception.Message
 Save-SimJson @{error=$failure;complete_evidence=($captureComplete -and !$state.Lost);application_acceptance='NOT_PROVEN';cursor=$state.Cursor;pages=$pageNumber} 'FAIL.json'
 throw
}finally{
 # Page files retain complete incremental evidence even if final status is too large.
 try{Save-SimJson (Invoke-ServiceIPC 'status') 'status-after.json'}catch{}
 try{Save-SimJson (Invoke-ServiceIPC 'relay.pool.diagnostics' @{relay_id=$RelayId}) 'pool-after.json'}catch{}
}
