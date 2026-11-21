#requires -Version 5.1
[CmdletBinding()]
param([ValidateRange(0,1800)][int]$DurationSeconds=0,[string]$ReportDirectory=(Join-Path $PSScriptRoot '..\..\bin\game-udp'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'game-udp-report.ps1')
. (Join-Path $PSScriptRoot 'simultaneous-checks.ps1')
$run=Join-Path $ReportDirectory ([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))
New-Item -ItemType Directory -Path $run -Force|Out-Null
function Save-GameJson($Value,[string]$Name){$Value|ConvertTo-Json -Depth 24|Set-Content -LiteralPath (Join-Path $run $Name) -Encoding UTF8}
$status=Invoke-ServiceIPC 'gameudp.status';Save-GameJson $status 'status-before.json'
$status.profiles|Select-Object profile_id,name,state,ready,activity,reason,@{Name='initial_policy';Expression={Get-GameField $_.engine 'initial_policy' 'UNKNOWN'}}|Format-Table -AutoSize
Write-Host 'ACTIVE = режим готов, не доказательство матча; WAITING_NEW_FLOW = приманок пока нет. FACEIT/Vanguard в guard — наличие, решение по профилю.'
Write-Host ('guard='+($status.guard|ConvertTo-Json -Compress))
Get-GameUdpRows $status|Format-Table -AutoSize
if($DurationSeconds -gt 0){
 $state=@{Cursor=(Invoke-ServiceIPC 'capture.changes.marker');Flows=@{};Lost=$false};$watch=[Diagnostics.Stopwatch]::StartNew();$pages=0;$saved=0
 Write-Host 'Read-only capture running. Start the next match; no game process restart or packet generation is performed by this script.'
 try{
  do{
   for($batch=0;$batch -lt 128;$batch++){
    if($watch.Elapsed.TotalSeconds -gt ($DurationSeconds+15)){throw 'GAME_CAPTURE_WALL_TIME_BOUND: evidence incomplete'}
    if($pages -ge 4096){throw 'GAME_CAPTURE_PAGE_BOUND: evidence incomplete'}
    $page=Invoke-ServiceIPC 'capture.changes' @{cursor=$state.Cursor};$pages++;$more=Merge-SimPage $state $page
    $game=@($page.flows|Where-Object{$null -ne (Get-GameField $_ 'game_udp')})
    if($game.Count -gt 0){Save-GameJson @{cursor=$page.cursor;evidence_lost=$page.evidence_lost;flows=$game} ('page-{0:D5}.json' -f $pages);$saved++}
    if(!$more){break};if($batch -eq 127){throw 'GAME_CAPTURE_DRAIN_BOUND: evidence incomplete'}
   }
   if($watch.Elapsed.TotalSeconds -ge $DurationSeconds){break};Start-Sleep -Milliseconds 500
  }while($true)
  $flows=@($state.Flows.Values|Where-Object{$null -ne (Get-GameField $_ 'game_udp')});Save-GameJson @{complete_evidence=(!$state.Lost);pages=$pages;game_pages=$saved;flows=$flows;match_acceptance='NOT_PROVEN_REQUIRES_OPERATOR_OBSERVATION'} 'capture.json'
  Write-Host "Capture complete; $($flows.Count) game UDP flows. This is not a match/anti-cheat PASS."
 }catch{Save-GameJson @{code='GAME_CAPTURE_INCOMPLETE';pages=$pages;complete_evidence=$false} 'FAIL.json';throw}
}
$status=Invoke-ServiceIPC 'gameudp.status';Save-GameJson $status 'status-after.json';Get-GameUdpRows $status|Format-Table -AutoSize
# This is a hint, not a routing allowlist or proof that a captured IP is Frankfurt.
$dns=@(Get-DnsClientCache -ErrorAction SilentlyContinue|Where-Object{((Get-GameField $_ 'Entry' '')+' '+(Get-GameField $_ 'Data' '')) -match 'eu-central-1\.compute\.amazonaws\.com'}|Select-Object Entry,Data)
Save-GameJson $dns 'frankfurt-dns-hints.json';$dns|Format-Table -AutoSize
Write-Host "Saved: $run ; no secrets, installation or VPS operations."
