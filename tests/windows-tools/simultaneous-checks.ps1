$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\..\tools\windows\simultaneous-checks.ps1')
function Check($Value,[string]$Message){if(!$Value){throw $Message}}
function Reject([scriptblock]$Code){$rejected=$false;try{&$Code|Out-Null}catch{$rejected=$true};if(!$rejected){throw 'Invalid simultaneous evidence accepted'}}
$state=@{Cursor=[pscustomobject]@{ledger_id='test';after_update=0};Flows=@{};Lost=$false}
$f=[pscustomobject]@{flow_id=1;pid=7;creation_time=10;exe='C:\Apps\msedge.exe';selected_route='RELAY';policy=@{action='RELAY_REQUIRED'};counters=@{relayed_bytes=10;relay_reply_bytes=20;direct_bytes=0;direct_packets=0}}
$p=[pscustomobject]@{cursor=[pscustomobject]@{ledger_id='test';after_update=1};more=$false;evidence_lost=$false;flows=@($f)}
[void](Merge-SimPage $state $p)
$p.cursor.after_update=2;[void](Merge-SimPage $state $p)
Check ($state.Flows.Count -eq 1) 'Repeated cumulative flow duplicated'
$proof=Get-SimProof $state @('msedge.exe');Check (!$proof.transport_evidence_pass) 'No YouTube evidence passed'
$f.counters.direct_bytes=1;$p.cursor.after_update=3;[void](Merge-SimPage $state $p)
Check ((Get-SimProof $state @('msedge.exe')).direct_leaks -eq 1) 'Late existing-flow leak hidden'
$f.counters.direct_bytes=0
$yt=[pscustomobject]@{flow_id=2;pid=8;creation_time=11;exe='C:\Chrome\chrome.exe';protocol='tcp';domain='www.youtube.com';selected_route='DIRECT_PLUS';strategy='disorder';policy=@{source='configured_baseline'};counters=@{direct_plus_packets=1;relayed_bytes=0}}
$p.flows=@($yt);$p.cursor.after_update=4;[void](Merge-SimPage $state $p)
Check ((Get-SimProof $state @('msedge.exe')).transport_evidence_pass) 'Valid transport proof failed'
Check ((Get-SimProof $state @('msedge.exe')).application_acceptance -eq 'OPERATOR_OBSERVATION_REQUIRED') 'Application success invented'
$f.selected_route='BLOCK';Check (!(Get-SimProof $state @('msedge.exe')).transport_evidence_pass) 'Protected failure hidden';$f.selected_route='RELAY'
$f|Add-Member -NotePropertyName relay_open -NotePropertyValue @{failure_reason='stream_capacity'}
Check (!(Get-SimProof $state @('msedge.exe')).transport_evidence_pass) 'Open failure hidden';$f.relay_open.failure_reason=''
$f.counters.Remove('direct_bytes');Reject {Get-SimProof $state @('msedge.exe')};$f.counters.direct_bytes=0
$media=[pscustomobject]@{flow_id=3;pid=9;creation_time=12;exe='Discord.exe';selected_route='BLOCK';policy=@{fallback='FLOW_RELAY_FALLBACK'}}
$state.Flows['3']=$media;Check (!(Get-SimProof $state @('msedge.exe')).transport_evidence_pass) 'Failed adaptive media transport hidden';$state.Flows.Remove('3')
$p.evidence_lost=$true;Reject {Merge-SimPage $state $p};Reject {Get-SimProof $state @('msedge.exe')}
$p.evidence_lost=$false;$state.Lost=$false;$p.cursor.ledger_id='other';Reject {Merge-SimPage $state $p}
Write-Host 'PASS simultaneous cursor, cumulative replacement, late leaks, loss/restart, protected failures, no invented app success'
$state.Cursor.ledger_id='test';$p.cursor.ledger_id='test'
# Actual configured strategy IDs carry action semantics in the applied chain.
$yt.strategy='p2-youtube-c10ec666-disorder'
$yt|Add-Member -NotePropertyName chain -NotePropertyValue 'tcp-multisplit + tcp-disorder'
Check ((Get-SimProof $state @('msedge.exe')).transport_evidence_pass) 'Configured YouTube strategy ID rejected'
$yt.chain='tcp-multisplit'
Check (!(Get-SimProof $state @('msedge.exe')).transport_evidence_pass) 'Strategy name alone faked applied disorder'
$yt.chain='tcp-multisplit + tcp-disorder'
foreach($field in @('selected_route','policy','counters')){
 $saved=$yt.$field
 switch($field){
 'selected_route' {$yt.$field='DIRECT'}
 'policy' {$yt.$field=@{source='synthetic'}}
 'counters' {$yt.$field=@{direct_plus_packets=0;relayed_bytes=0}}
 }
 Check (!(Get-SimProof $state @('msedge.exe')).transport_evidence_pass) "Weakened YouTube $field"
 $yt.$field=$saved
}
$yt.counters.relayed_bytes=1
Check (!(Get-SimProof $state @('msedge.exe')).transport_evidence_pass) 'YouTube relay bytes hidden'
$yt.counters.relayed_bytes=0
$f|Add-Member -NotePropertyName failure_cause -NotePropertyValue 'TCP_RELAY_READ_FAILED'
Check (!(Get-SimProof $state @('msedge.exe')).transport_evidence_pass) 'Fatal failure with prior relay replies hidden'
$f.failure_cause=''
$f|Add-Member -NotePropertyName last_drop_cause -NotePropertyValue 'TCP_TEARDOWN_TAIL'
$f|Add-Member -NotePropertyName lifecycle -NotePropertyValue 'TCP_CLOSED'
Check ((Get-SimProof $state @('msedge.exe')).transport_evidence_pass) 'Normal successful TCP teardown rejected'
$f.lifecycle='UDP_IDLE_EXPIRED'
Check ((Get-SimProof $state @('msedge.exe')).transport_evidence_pass) 'Successful idle UDP rejected'
$before=@{capture=@{capture_queue_drops=@{count=0};worker_saturation_drops=@{count=0}}}
$after=@{capture=@{capture_queue_drops=@{count=0};worker_saturation_drops=@{count=375}}}
$proof=Get-SimProof $state @('msedge.exe');Add-SimDropGates $proof $before $after
Check (!$proof.transport_evidence_pass -and $proof.worker_saturation_drops_delta -eq 375) 'Worker drops escaped simultaneous gate'
$after.capture.worker_saturation_drops.count=0
# Bounded complete multi-page update churn: cumulative rows replace rather than sum.
for($i=4;$i -lt 704;$i++){
 $row=[pscustomobject]@{flow_id=$i;pid=$i;creation_time=10;exe='msedge.exe';selected_route='RELAY';protocol='udp';policy=@{action='RELAY_REQUIRED'};counters=@{relayed_bytes=1;relay_reply_bytes=1;direct_bytes=0;direct_packets=0}}
 $p.flows=@($row);$p.cursor.ledger_id='test';$p.cursor.after_update++
 [void](Merge-SimPage $state $p)
}
$proof=Get-SimProof $state @('msedge.exe');Add-SimDropGates $proof $before $after
Check ($proof.transport_evidence_pass -and $proof.flow_records -eq 702 -and $proof.worker_saturation_drops_delta -eq 0 -and $proof.capture_queue_drops_delta -eq 0) 'Complete bounded stress proof failed'
Write-Host 'PASS configured action chain, strict YouTube gates, fatal vs teardown/idle, queue+worker gates, 702 complete flow rows'
