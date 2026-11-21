$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\..\tools\windows\acceptance-checks.ps1')
. (Join-Path $PSScriptRoot '..\..\tools\windows\direct-plus-checks.ps1')
$exe='C:\tests\chosen.exe';$destination='203.0.113.9:443'
$report=[pscustomobject]@{pid=42;exe=$exe;creation_time=10;attempts=@([pscustomobject]@{success=$true;destination=$destination;response_source='198.51.100.2';response_rtt_ms=20})}
$flow=[pscustomobject]@{pid=42;exe=$exe;creation_time=10;destination=$destination;protocol='tcp';ip_version='IPv4';selected_route='DIRECT_PLUS';counters=[pscustomobject]@{captured_packets=4;captured_bytes=600;direct_bytes=100;relayed_bytes=0;relay_reply_bytes=0;relayed_packets=0;direct_packets=2;direct_plus_packets=2;relay_reply_packets=0;direct_plus_bytes=300}}
$e=[pscustomobject]@{truncated=$false;flows=@($flow)}
[void](Assert-DirectPlusEvidence $report $e 42 $exe 'DIRECT_PLUS' '192.0.2.9' $destination 1)
function Reject([scriptblock]$Code){$thrown=$false;try{& $Code}catch{$thrown=$true};if(!$thrown){throw 'Invalid evidence accepted'}}
$flow.counters.direct_plus_packets=0;Reject {[void](Assert-DirectPlusEvidence $report $e 42 $exe 'DIRECT_PLUS' '192.0.2.9' $destination 1)};$flow.counters.direct_plus_packets=2
$flow.creation_time=11;Reject {[void](Assert-DirectPlusEvidence $report $e 42 $exe 'DIRECT_PLUS' '192.0.2.9' $destination 1)};$flow.creation_time=10
$flow.counters.relayed_packets=1;Reject {[void](Assert-DirectPlusEvidence $report $e 42 $exe 'DIRECT_PLUS' '192.0.2.9' $destination 1)};$flow.counters.relayed_packets=0
$flow.counters.captured_bytes=0;Reject {[void](Assert-DirectPlusEvidence $report $e 42 $exe 'DIRECT_PLUS' '192.0.2.9' $destination 1)};$flow.counters.captured_bytes=600
$report.attempts[0].success=$false;Reject {[void](Assert-DirectPlusEvidence $report $e 42 $exe 'DIRECT_PLUS' '192.0.2.9' $destination 1)}
$m=Get-StrategyMeasurement $report $false;if($m.available -or $m.loss -ne 1 -or $m.samples -ne 0){throw 'Timeout/failure became successful telemetry'}
Write-Host 'PASS DIRECT+ proof rejects missing transforms, wrong identity, relay traffic and unsuccessful report'

$expected=[pscustomobject]@{id='!test';mode='DIRECT_PLUS';custom=$true;executables=@($exe);local_strategy_id='s'}
$snapshot=[pscustomobject]@{profiles=@($expected)}
Assert-LocalEffectiveProfile $snapshot $exe '!test' 'DIRECT_PLUS' 's'
$snapshot.profiles+=@([pscustomobject]@{id='!aaa';mode='DIRECT';custom=$true;executables=@($exe)})
Reject {Assert-LocalEffectiveProfile $snapshot $exe '!test' 'DIRECT_PLUS' 's'}
Write-Host 'PASS local acceptance rejects a shadowed profile before launching traffic'

# Two independent connections: aggregate positive counters cannot conceal an
# untransformed second connection, even if a stale route label says DIRECT_PLUS.
$report.attempts[0].success=$true
$second=$flow | ConvertTo-Json -Depth 10 | ConvertFrom-Json
$e.flows=@($flow,$second)
$report.attempts=@($report.attempts[0],$report.attempts[0])
[void](Assert-DirectPlusEvidence $report $e 42 $exe 'DIRECT_PLUS' '192.0.2.9' $destination 2)
$second.selected_route='DIRECT'
Reject {[void](Assert-DirectPlusEvidence $report $e 42 $exe 'DIRECT_PLUS' '192.0.2.9' $destination 2)}
$second.selected_route='DIRECT_PLUS'
$second.counters.direct_plus_packets=0
Reject {[void](Assert-DirectPlusEvidence $report $e 42 $exe 'DIRECT_PLUS' '192.0.2.9' $destination 2)}
$second.counters.direct_plus_packets=2;$second.counters.direct_plus_bytes=0
Reject {[void](Assert-DirectPlusEvidence $report $e 42 $exe 'DIRECT_PLUS' '192.0.2.9' $destination 2)}
Write-Host 'PASS every connection requires its own route AND actual modification counters'
