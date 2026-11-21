[CmdletBinding()]
param(
 [ValidateRange(20,180)][int]$StageSeconds=60,
 [string[]]$Processes=@('chrome.exe','msedge.exe','ChatGPT.exe','codex.exe','Discord.exe'),
 [string[]]$RequiredRelayProcesses=@('msedge.exe','ChatGPT.exe','codex.exe','Discord.exe'),
 [string]$ReportDirectory=(Join-Path $PSScriptRoot '..\..\bin\hot-attach')
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'simultaneous-checks.ps1')
. (Join-Path $PSScriptRoot 'hot-attach-checks.ps1')
$run=Join-Path $ReportDirectory ([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
New-Item -ItemType Directory -Force $run|Out-Null
function Save-HotJson($Value,[string]$Name){$Value|ConvertTo-Json -Depth 28|Set-Content -LiteralPath (Join-Path $run $Name) -Encoding UTF8}
function Get-HotProcesses{return @(Invoke-ServiceIPC 'processes' @{executables=$Processes})}
$original=Invoke-ServiceIPC 'status';$pageNumber=0
try{
 $roots=@(Get-HotAttachRoots (Get-HotProcesses) $Processes);Save-HotJson $roots 'roots-before.json'
 Write-Host 'Happ must be OFF. Keep already-running YouTube/video/seek, Edge ChatGPT, ChatGPT/Codex requests and Discord voice/messages active. This tool never starts/restarts applications.'
 foreach($stage in @(1,2)){
  # Disabling is intentional test setup and permits DIRECT traffic. No protection
  # is asserted while Optimize is OFF; close sensitive requests if inappropriate.
  [void](Invoke-ServiceIPC 'optimize' @{enabled=$false})
  Start-Sleep -Seconds 1
  Assert-HotAttachRoots $roots (Get-HotProcesses)
  $before=Invoke-ServiceIPC 'quality.diagnostics'
  $state=@{Cursor=(Invoke-ServiceIPC 'capture.changes.marker');Flows=@{};Lost=$false}
  $enabled=Invoke-ServiceIPC 'optimize' @{enabled=$true}
  $epoch=[uint64](Get-SimValue (Get-SimValue $enabled 'hot_attach') 'epoch' 0)
  if(!$epoch){throw 'HOT ATTACH backend unavailable'}
  $watch=[Diagnostics.Stopwatch]::StartNew()
  do{
   for($batch=0;$batch -lt 128;$batch++){
    if($pageNumber -ge 4096 -or $watch.Elapsed.TotalSeconds -gt ($StageSeconds+15)){throw 'Bounded HOT ATTACH capture exceeded'}
    $page=Invoke-ServiceIPC 'capture.changes' @{cursor=$state.Cursor}
    Save-HotJson $page ('stage-{0}-page-{1:D5}.json' -f $stage,$pageNumber);$pageNumber++
    $more=Merge-SimPage $state $page
    if(!$more){break}
   }
   if($more){throw 'Capture did not drain'}
   $hot=Invoke-ServiceIPC 'hot_attach.status';Save-HotJson $hot ('stage-{0}-status.json' -f $stage)
   Assert-HotAttachRoots $roots (Get-HotProcesses)
   if($watch.Elapsed.TotalSeconds -ge $StageSeconds){break}
   Start-Sleep -Milliseconds 500
  }while($true)
  $after=Invoke-ServiceIPC 'quality.diagnostics'
  Save-HotJson $before ('stage-{0}-quality-before.json' -f $stage);Save-HotJson $after ('stage-{0}-quality-after.json' -f $stage)
  $proof=Get-HotAttachProof $state $hot $epoch $RequiredRelayProcesses
  Add-SimDropGates $proof $before $after
  $proof|Add-Member -NotePropertyName original_root_identities_preserved -NotePropertyValue $true
  Save-HotJson $proof ('stage-{0}-proof.json' -f $stage)
  if(!$proof.transport_evidence_pass){throw "Stage $stage HOT ATTACH transport proof failed"}
 }
 Save-HotJson (Get-HotProcesses) 'processes-after.json'
 Write-Host "HOT ATTACH TRANSPORT EVIDENCE PASS (two enable cycles, original roots alive). YouTube resumption, web/app requests and Discord voice/messages still require operator observations. Reports: $run"
}catch{
 Save-HotJson @{error=$_.Exception.Message;application_acceptance='NOT_PROVEN';pages=$pageNumber} 'FAIL.json'
 throw
}finally{
 try{Save-HotJson (Invoke-ServiceIPC 'status') 'status-after.json'}catch{}
 # Restore only prior Optimize state, never profiles, app processes or credentials.
 try{[void](Invoke-ServiceIPC 'optimize' @{enabled=[bool](Get-SimValue $original 'optimizing' $false)})}catch{Save-HotJson @{error=$_.Exception.Message;action='restore_original_optimize_state'} 'RESTORE-FAIL.json';Write-Warning 'Failed to restore original Optimize state; inspect RESTORE-FAIL.json and service status'}
}
