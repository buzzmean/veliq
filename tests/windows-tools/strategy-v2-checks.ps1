$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\..\tools\windows\strategy-v2-checks.ps1')
function Reject([scriptblock]$Code){$failed=$false;try{&$Code|Out-Null}catch{$failed=$true};if(!$failed){throw 'Invalid v2 proof accepted'}}
$exe='C:\Apps\chrome.exe';$obs=[pscustomobject]@{success=$true;status=200;tls=$true;protocol='h2';destination='203.0.113.9:443';hostname='www.youtube.com';completed=$true;connection_id=99;socket_binding=@{status='BOUND';connection_id=99;source='192.0.2.1:55000';destination='203.0.113.9:443';method='chromium_netlog_socket_id'}}
$ids=@([pscustomobject]@{PID=42;CreationTime=100})
$flow=[pscustomobject]@{flow_id=11;started_at=[DateTimeOffset]::UtcNow.ToString('o');source='192.0.2.1:55000';protocol='tcp';domain='www.youtube.com';local_inspection=@{reason='REASSEMBLY_COMPLETE';observed_sni='www.youtube.com';transform_applied=$true};pid=42;creation_time=100;exe=$exe;destination=$obs.destination;strategy='fake5';selected_route='DIRECT_PLUS';counters=[pscustomobject]@{captured_packets=4;direct_plus_packets=1;direct_plus_bytes=1200;relayed_packets=0;relayed_bytes=0}}
$marker=[pscustomobject]@{ledger_id='trial';after_flow_id=10;lost_records=0}
$ev=[pscustomobject]@{truncated=$false;flows=@($flow);since=$marker;marker=$marker}
[void](Assert-V2BrowserEvidence $obs $ev $ids $exe 'DIRECT_PLUS' 'fake5')
$obs.success=$false;Reject {Assert-V2BrowserEvidence $obs $ev $ids $exe 'DIRECT_PLUS' 'fake5'};$obs.success=$true
$obs.status=403;Reject {Assert-V2BrowserEvidence $obs $ev $ids $exe 'DIRECT_PLUS' 'fake5'};$obs.status=200
$obs.tls=$false;Reject {Assert-V2BrowserEvidence $obs $ev $ids $exe 'DIRECT_PLUS' 'fake5'};$obs.tls=$true
$obs.protocol='h3';Reject {Assert-V2BrowserEvidence $obs $ev $ids $exe 'DIRECT_PLUS' 'fake5'};$obs.protocol='h2'
$flow.counters.direct_plus_packets=0;Reject {Assert-V2BrowserEvidence $obs $ev $ids $exe 'DIRECT_PLUS' 'fake5'};$flow.counters.direct_plus_packets=1
$flow.counters.relayed_bytes=1;Reject {Assert-V2BrowserEvidence $obs $ev $ids $exe 'DIRECT_PLUS' 'fake5'};$flow.counters.relayed_bytes=0
$flow.creation_time=101;Reject {Assert-V2BrowserEvidence $obs $ev $ids $exe 'DIRECT_PLUS' 'fake5'};$flow.creation_time=100
$ev.truncated=$true;Reject {Assert-V2BrowserEvidence $obs $ev $ids $exe 'DIRECT_PLUS' 'fake5'}
Write-Host 'PASS v2: complete real HTTPS + TCP + exact identity + actual transform + zero relay; no sent-packet PASS'

function Check($Condition,[string]$Message){if(!$Condition){throw $Message}}
$candidate=[pscustomobject]@{id='fake5';actions=@([pscustomobject]@{kind='fake-tls';ttl=5},[pscustomobject]@{kind='tcp-multisplit'})}
function New-DiagnosticFlow([int]$Port=443){return [pscustomobject]@{pid=42;creation_time=100;exe=$exe;destination="203.0.113.9:$Port";protocol='tcp';strategy='fake5';selected_route='DIRECT';local_inspection=$null;counters=[pscustomobject]@{captured_packets=4;direct_plus_packets=0;direct_plus_bytes=0;fake_tls_packets=0;quic_fallback_packets=0;relayed_bytes=0}}}
$f=New-DiagnosticFlow;$capture=[pscustomobject]@{truncated=$false;flows=@($f)}
function Diagnose([bool]$Valid=$true,[string]$Kind='NETWORK_TIMEOUT'){return Get-V2TrialDiagnostic $capture $ids $exe $obs.destination 'DIRECT_PLUS' $false $Valid $Kind $candidate}
$d=Diagnose;Check ($d.classifications -contains 'NO_TRANSFORM' -and $d.classifications -contains 'NETWORK_TIMEOUT') 'No-transform timeout not distinguished';Check ($d.counters.captured_packets -eq 4) 'Captured counters missing'
foreach($reason in @('CLIENTHELLO_INCOMPLETE','SNI_NOT_FOUND','DOMAIN_NOT_MATCHED')){
 $f.local_inspection=[pscustomobject]@{reason=$reason;domain='www.youtube.com'};$d=Diagnose
 Check ($d.classifications -contains $reason -and $d.classifications -contains 'NO_TRANSFORM') "Missing passive reason $reason"
 Check ($d.flows[0].observed_domain -eq 'www.youtube.com') 'Observed SNI lost'
}
$f.counters.direct_plus_packets=1;$f.counters.direct_plus_bytes=1200;$f.counters.fake_tls_packets=1;$f.selected_route='DIRECT_PLUS'
$d=Diagnose;Check ($d.classification -eq 'TRANSFORM_APPLIED_CONNECTION_FAILED' -and $d.transform_status -eq 'APPLIED' -and $d.classifications -contains 'NETWORK_TIMEOUT') 'Applied-but-failed timeout not distinguished'
Check ($d.counters.fake_tls_packets -eq 1 -and $d.counters.relayed_bytes -eq 0) 'Actual counters lost'
$d=Diagnose $false 'CDP/INSTRUMENTATION_FAILURE';Check ($d.classification -eq 'CDP/INSTRUMENTATION_FAILURE' -and $d.transform_status -eq 'APPLIED' -and $d.classifications -notcontains 'TRANSFORM_APPLIED_CONNECTION_FAILED' -and $d.classifications -notcontains 'NETWORK_TIMEOUT') 'CDP cancellation invented connection failure'
$f=New-DiagnosticFlow;$f.protocol='udp';$f.counters.quic_fallback_packets=3;$capture.flows=@($f)
$d=Diagnose;Check ($d.classifications -contains 'QUIC_FALLBACK_APPLIED' -and $d.transform_status -ne 'APPLIED') 'QUIC suppression incorrectly proves TCP transform'
$capture.truncated=$true;$f.counters.quic_fallback_packets=0;$d=Diagnose;Check ($d.classifications -notcontains 'NO_TRANSFORM' -and $d.transform_status -eq 'UNKNOWN') 'Truncation invented negative proof'
$f.protocol='tcp';$f.counters.direct_plus_packets=1;$f.counters.direct_plus_bytes=100;$d=Diagnose;Check ($d.transform_status -eq 'APPLIED' -and !$d.evidence_complete) 'Positive proof lost in truncated snapshot'
$capture.truncated=$false;$f.creation_time=101;$d=Diagnose;Check ($null -eq $d.counters.captured_packets -and $d.transform_status -eq 'UNKNOWN') 'PID reuse borrowed counters'
$f.creation_time=100;$f=New-DiagnosticFlow 8443;$capture.flows=@($f);$d=Diagnose;Check ($d.flows.Count -eq 0) 'Other target supplied proof'
$d=Get-V2TrialDiagnostic $null @() $exe $obs.destination 'DIRECT_PLUS' $false $false 'CDP/INSTRUMENTATION_FAILURE' $candidate
Check ($null -eq $d.counters.direct_plus_packets -and $d.classifications -notcontains 'NO_TRANSFORM') 'Missing backend invented zero counters'
Write-V2TrialDiagnostic $d

# Execute the production CDP wrapper with a real canceled .NET Task. Classification
# must use exception metadata/inner types, never localized GetResult text.
class V2CancelledSocket {
 [Threading.Tasks.Task] SendAsync([object]$Buffer,[object]$Kind,[bool]$End,[Threading.CancellationToken]$Token){return [Threading.Tasks.Task]::FromCanceled([Threading.CancellationToken]::new($true))}
}
$scriptFile=Join-Path $PSScriptRoot '..\..\tools\windows\strategy-tester-v2.ps1';$tokens=$null;$parseErrors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $scriptFile),[ref]$tokens,[ref]$parseErrors)
Check (!$parseErrors.Count) 'Tester script parse failed'
$cdpAst=$tree.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'CDP'},$true)
Invoke-Expression $cdpAst.Extent.Text
$script:socket=[V2CancelledSocket]::new();$script:cdpID=0;$caught=$null
try{CDP 'Browser.getVersion' @{}}catch{$caught=$_.Exception}
Check ($null -ne $caught -and (Get-V2ExceptionKind $caught) -eq 'CDP/INSTRUMENTATION_FAILURE') 'GetResult cancellation not identified by typed exception metadata'
$chain=@(Get-V2ExceptionDetails $caught);Check (@($chain|Where-Object{$_.type -match 'CanceledException'}).Count -gt 0) 'Inner cancellation type missing'
$script:socket=$null
Write-Host 'PASS v2 failure taxonomy: no transform, applied failure, incomplete CH, missing SNI, domain mismatch, QUIC, network timeout, typed CDP cancellation, unknown/truncated/foreign evidence'

# Exercise the actual Trial catch/finally with mocked OS/IPC startup: every
# failed trial must retain diagnostics and write proof even without navigation.
function Get-V2TrialIdentities($Exe,$NotBefore){return $ids}
function Get-V2ScopedCapture($Marker,$Identities,$Destination){return [pscustomobject]@{truncated=$false;flows=@($fixtureFlow)}}
$trialAst=$tree.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'Trial'},$true)
Invoke-Expression $trialAst.Extent.Text
$Automatic=$false;$StartupTimeoutSeconds=45
$AppPath=$exe;$URL='https://www.youtube.com/';$uri=[Uri]$URL;$TargetIPv4='203.0.113.9';$targetDestination=$obs.destination
$network=[pscustomobject]@{fingerprint='frozen';observed_at=[DateTimeOffset]::UtcNow.ToString('o');vpn=@();conflicts=@()}
$run=[Guid]::NewGuid().ToString('N');$profileID='!fixture';$candidates=@($candidate);$TimeoutSeconds=5;$script:socket=$null
$ReportDirectory=Join-Path ([IO.Path]::GetTempPath()) ('v2-diagnostic-fixture-'+$run);[void](New-Item -ItemType Directory $ReportDirectory)
$fixtureMarker=$marker
$fixtureFlow=New-DiagnosticFlow;$fixtureFlow.local_inspection=[pscustomobject]@{reason='CLIENTHELLO_INCOMPLETE';payload_bytes=100;record_bytes=1600}
function Invoke-ServiceIPC($Method,$Payload){switch($Method){
 'capture.marker' {return $fixtureMarker}
 'local.network' {return $network}
 'profile.set' {return $null}
 'status' {return [pscustomobject]@{}}
 'processes' {return @()}
 'capture.diagnostics' {return [pscustomobject]@{truncated=$false;flows=@($fixtureFlow)}}
 'local.record' {throw 'An instrumentation failure must not enter network cache'}
 default {throw "Unexpected method $Method"}
}}
function Get-AcceptanceProfile($Status,$Path){return [pscustomobject]@{id=$profileID;mode='DIRECT_PLUS'}}
function Start-Process($FilePath,$ArgumentList,[switch]$PassThru){$p=[pscustomobject]@{HasExited=$true;Handle=0};$p|Add-Member ScriptMethod Dispose {};return $p}
function Wait-AcceptanceReadiness($TimeoutMS,$PollMS,$GetSnapshot,$Evaluate){throw 'Unsupported launcher fixture (not an ISP failure)'}
try{
 $r=Trial 'DIRECT_PLUS' 'fake5' 0
 Check ($r.reason -like '*Unsupported launcher fixture*') 'Fixture failed before reaching the intended startup boundary'
 Check (!$r.success -and $r.instrumentation_failure -and !$r.measurement_recorded -and !$r.measurement_valid -and $null -eq $r.measurement) 'Startup failure was learned as network loss'
 Check ($r.classification -eq 'CDP/INSTRUMENTATION_FAILURE' -and $r.classifications -contains 'CLIENTHELLO_INCOMPLETE') 'Trial lost combined classifications'
 $proof=Get-Content (Join-Path $ReportDirectory "$run-0-proof.json") -Raw|ConvertFrom-Json
 Check ($proof.diagnostic.counters.captured_packets -eq 4 -and $proof.phase -eq 'browser_startup' -and $proof.exception_chain.Count -gt 0) 'Trial catch/finally did not save counters/phase/typed exception'
}finally{Remove-Item $ReportDirectory -Recurse -Force}
Write-Host 'PASS actual Trial catch/finally preserves counters and reason metadata and excludes instrumentation from learning'
$f=New-DiagnosticFlow;$f.local_inspection=[pscustomobject]@{reason='TRANSFORM_SEND_FAILED';output_packets_sent=1;send_failed=$true};$capture=[pscustomobject]@{truncated=$false;flows=@($f)}
$d=Diagnose;Check ($d.transform_status -eq 'PARTIAL_OUTPUT' -and $d.classifications -notcontains 'NO_TRANSFORM') 'Partial sends mislabeled as no transform'
$f.counters.direct_plus_packets=1;$f.counters.direct_plus_bytes=100;$d=Diagnose $true 'APPLICATION_RESPONSE_FAILURE'
Check ($d.transform_status -eq 'APPLIED' -and $d.classifications -notcontains 'TRANSFORM_APPLIED_CONNECTION_FAILED') 'Completed HTTP response mislabeled as connection failure'
Write-Host 'PASS partial output and HTTP/evidence failures do not invent transport failure or successful application'

# Distinct OS refresh cycles, rather than repeated IPC reads of one cache entry.
$state=@{last_refresh='';fingerprint='';cycles=0}
$n=[pscustomobject]@{fingerprint='isp';observed_at=[DateTimeOffset]::UtcNow.AddSeconds(-30).ToString('o');vpn=@();conflicts=@()}
Check (!(Test-V2NetworkCycle $n $state)) 'First snapshot accepted as stable'
Check (!(Test-V2NetworkCycle $n $state)) 'Cached IPC snapshot counted as another OS refresh'
$n.observed_at=[DateTimeOffset]::UtcNow.ToString('o');Check (Test-V2NetworkCycle $n $state) 'Second fresh equal fingerprint rejected'
$baseline=$n.PSObject.Copy();$n.fingerprint='changed';Reject {Assert-V2FrozenNetwork $baseline $n}
$n.fingerprint='isp';$n.vpn=@('HappTunnel');Reject {Assert-V2FrozenNetwork $baseline $n}
$state=@{last_refresh='';fingerprint='';cycles=0};Reject {Test-V2NetworkCycle $n $state}
$n.vpn=@();$n.observed_at=[DateTimeOffset]::UtcNow.AddMinutes(-2).ToString('o');Reject {Test-V2NetworkCycle $n $state}
foreach($missing in @($null,[pscustomobject]@{},[pscustomobject]@{frameTree=[pscustomobject]@{}},[pscustomobject]@{frameTree=[pscustomobject]@{frame=[pscustomobject]@{}}})){Reject {Get-V2MainFrame $missing}}
Check ((Get-V2MainFrame ([pscustomobject]@{frameTree=[pscustomobject]@{frame=[pscustomobject]@{id='main'}}})) -eq 'main') 'Frame identity lost'
foreach($field in @('result','instrumentation_failure','phase','success','mode','strategy')){Check ($null -eq (Get-V2Value ([pscustomobject]@{}) $field)) ('Unsafe optional property '+$field)}
# Exercise cleanup against native stderr/child-exit races under both PS5.1/7.
function taskkill.exe {throw 'The process no longer exists (simulated native stderr)'}
$p=[pscustomobject]@{HasExited=$false;Id=123}
$p|Add-Member ScriptMethod WaitForExit {param($ms) throw 'Already exited'}
$p|Add-Member ScriptMethod Dispose {throw 'Disposed after exit race'}
$script:socket=$null
$issues=@(Stop-V2TrialBrowser $p (Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))))
Check ($issues.Count -eq 3) 'Cleanup race escaped trial or was silently discarded'
Write-Host 'PASS network refresh boundaries, frozen ISP guard, optional CDP/frame/result access and nonfatal cleanup races'
if($env:OS -eq 'Windows_NT'){
 $nativeDir=Join-Path ([IO.Path]::GetTempPath()) ('v2-native-'+[Guid]::NewGuid().ToString('N'));[void](New-Item -ItemType Directory $nativeDir)
 $stdout=Join-Path $nativeDir 'stdout.txt';$stderr=Join-Path $nativeDir 'stderr.txt'
 $native=Microsoft.PowerShell.Management\Start-Process -FilePath $env:ComSpec -ArgumentList '/d /c "echo v2-out & echo v2-err 1>&2"' -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
 try{
  [void]$native.Handle # Retain the real exit handle before PS5.1 can lose it.
  Check ($native.WaitForExit(10000)) 'Redirected child did not exit';$native.WaitForExit();$native.Refresh()
  Check ($native.ExitCode -eq 0 -and (Get-Content $stdout -Raw) -match 'v2-out' -and (Get-Content $stderr -Raw) -match 'v2-err') 'Real Windows redirected process evidence invalid'
  $issues=@(Stop-V2TrialBrowser $native $nativeDir);Check (!$issues.Count) 'Already exited redirected Windows child cleanup failed'
 }finally{if(Test-Path $nativeDir){Remove-Item $nativeDir -Recurse -Force}}
 Write-Host 'PASS real redirected Windows Start-Process and already exited process cleanup'
}
class V2OptionalReplySocket {
 [Threading.Tasks.Task] SendAsync([object]$Buffer,[object]$Kind,[bool]$End,[Threading.CancellationToken]$Token){return [Threading.Tasks.Task]::CompletedTask}
 [Threading.Tasks.Task[Net.WebSockets.WebSocketReceiveResult]] ReceiveAsync([object]$Buffer,[Threading.CancellationToken]$Token){
  $bytes=[Text.Encoding]::UTF8.GetBytes('{"id":1}')
  [Array]::Copy($bytes,0,$Buffer.Array,$Buffer.Offset,$bytes.Length)
  $done=[Threading.Tasks.TaskCompletionSource[Net.WebSockets.WebSocketReceiveResult]]::new()
  $done.SetResult([Net.WebSockets.WebSocketReceiveResult]::new($bytes.Length,[Net.WebSockets.WebSocketMessageType]::Text,$true))
  return $done.Task
 }
}
$script:socket=[V2OptionalReplySocket]::new();$script:cdpID=0;$script:navID=-2
try{$optional=CDP 'Browser.getVersion' @{};Check ($null -eq $optional) 'Optional CDP result invented data'}finally{$script:socket=$null}
Write-Host 'PASS actual CDP roundtrip with absent result under StrictMode Latest'
$complete=[pscustomobject]@{remoteIPAddress='203.0.113.9';remotePort=443;status=200;securityState='secure';protocol='h2'}
$meta=Get-V2HTTPSObservation $complete 12.5
Check ($meta.success -and $meta.tls -and $meta.destination -eq '203.0.113.9:443') 'Valid HTTPS evidence lost'
foreach($field in @('remoteIPAddress','remotePort','status','securityState','protocol')){
 $missing=$complete.PSObject.Copy();$missing.PSObject.Properties.Remove($field);$caught=$null
 try{Get-V2HTTPSObservation $missing 12.5|Out-Null}catch{$caught=$_.Exception}
 Check ($null -ne $caught -and (Get-V2ExceptionKind $caught) -eq 'CDP/INSTRUMENTATION_FAILURE') ('Missing response property learned as loss: '+$field)
}
Write-Host 'PASS optional CDP response fields are instrumentation failures, not network-loss measurements'
# JSON dates differ across PS5.1/7. Preserve the instant and UTC kind, regardless
# of Windows culture/time zone; stringifying DateTime first loses that evidence.
foreach($representation in @('json','datetime','datetimeoffset')){
 $state=@{last_refresh='';fingerprint='';cycles=0}
 $stamp=[DateTimeOffset]::UtcNow.AddSeconds(-30)
 $n=[pscustomobject]@{fingerprint='isp';observed_at=$stamp.ToString('o');vpn=@();conflicts=@()}
 switch($representation){'json'{$n=$n|ConvertTo-Json|ConvertFrom-Json};'datetime'{$n.observed_at=$stamp.UtcDateTime};'datetimeoffset'{$n.observed_at=$stamp.ToOffset([TimeSpan]::FromHours(3))}}
 Check (!(Test-V2NetworkCycle $n $state)) ('Typed date accepted first refresh: '+$representation)
 # The same instant with an explicit +03 offset remains the SAME refresh.
 $n.observed_at=$stamp.ToOffset([TimeSpan]::FromHours(3)).ToString('o')
 Check (!(Test-V2NetworkCycle $n $state)) 'Offset formatting counted as a new OS refresh'
 $n.observed_at=[DateTime]::UtcNow
 Check (Test-V2NetworkCycle $n $state) ('Typed UTC date rejected: '+$representation)
}
Write-Host 'PASS JSON/string/DateTime/DateTimeOffset UTC refresh identity without culture or timezone loss'

. (Join-Path $PSScriptRoot '..\..\tools\windows\strategy-v2-correlation.ps1')

# Target-aware validation keeps the mixed-route check, but unknown/OTHER SNI is
# never automatically assigned to the main-frame response. The exact source
# binding is mandatory, independent of the number of apparent target flows.
$target=$flow.PSObject.Copy();$currentMarker=[pscustomobject]@{ledger_id='trial';after_flow_id=20;lost_records=0}
$capture=[pscustomobject]@{flows=@($target);truncated=$false;since=$marker;marker=$currentMarker}
$unknown=$target.PSObject.Copy();$unknown.flow_id=12;$unknown.source='192.0.2.1:55001';$unknown.domain='';$unknown.local_inspection=$null;$unknown.selected_route='DIRECT';$unknown.strategy=''
$capture.flows=@($target,$unknown)
[void](Assert-V2BrowserEvidence $obs $capture $ids $exe 'DIRECT_PLUS' 'fake5')
$unknown.domain='other.google.com';[void](Assert-V2BrowserEvidence $obs $capture $ids $exe 'DIRECT_PLUS' 'fake5')
$unknown.domain='www.youtube.com';$caught=$null
try{Assert-V2BrowserEvidence $obs $capture $ids $exe 'DIRECT_PLUS' 'fake5'|Out-Null}catch{$caught=$_.Exception}
Check ((Get-V2ExceptionKind $caught) -eq 'TARGET_FLOW_AMBIGUOUS') 'Target-hostname mixed route did not remain ambiguous FAIL'
# Older trial generations and reused PIDs cannot supply a conflicting target.
$unknown.flow_id=9;[void](Assert-V2BrowserEvidence $obs $capture $ids $exe 'DIRECT_PLUS' 'fake5')
$unknown.flow_id=12;$unknown.creation_time=101;[void](Assert-V2BrowserEvidence $obs $capture $ids $exe 'DIRECT_PLUS' 'fake5');$unknown.creation_time=100
$unknown.domain='';$savedBinding=$obs.socket_binding;$obs.socket_binding=$null;$caught=$null
try{Assert-V2BrowserEvidence $obs $capture $ids $exe 'DIRECT_PLUS' 'fake5'|Out-Null}catch{$caught=$_.Exception}
Check ((Get-V2ExceptionKind $caught) -eq 'TARGET_FLOW_AMBIGUOUS') 'SNI-only candidate invented exact response socket PASS';$obs.socket_binding=$savedBinding
# Exact socket binding cannot rescue two observed target-domain routes.
$unknown.domain='www.youtube.com';$unknown.source=$target.source
Reject {Assert-V2BrowserEvidence $obs $capture $ids $exe 'DIRECT_PLUS' 'fake5'}
$unknown.selected_route='DIRECT_PLUS';$unknown.strategy='fake5';$unknown.local_inspection=$target.local_inspection
Reject {Assert-V2BrowserEvidence $obs $capture $ids $exe 'DIRECT_PLUS' 'fake5'}
$diag=Get-V2TrialDiagnostic $capture $ids $exe $obs.destination 'DIRECT_PLUS' $false $false 'TARGET_FLOW_AMBIGUOUS' $candidate
Check ($diag.classification -eq 'TARGET_FLOW_AMBIGUOUS' -and $diag.classifications -notcontains 'CDP/INSTRUMENTATION_FAILURE') 'Evidence ambiguity mislabeled as CDP failure'
Check ((Format-V2EvidenceValue @{reassembly_ms=0} 'reassembly_ms') -eq '0') 'Actual zero-ms elapsed lost'
Check ((Format-V2EvidenceValue @{} 'reassembly_ms') -eq 'UNKNOWN') 'Missing elapsed printed blank'
Check ((Format-V2EvidenceValue @{reassembly_ms=$null} 'reassembly_ms') -eq 'UNKNOWN') 'Null elapsed printed blank'
Write-Host 'PASS target-aware unknown/other SNI, positive target conflict, exact socket requirement, old generations, PID reuse and ambiguity classification'

# Real query shape: each current PID AND creation time AND marker before limits.
$scopedMarker=[pscustomobject]@{ledger_id='scope';after_flow_id=100;lost_records=0};$queryLog=[Collections.Generic.List[object]]::new()
$rows=@()
foreach($n in 1..70){$rows+=@{pid=42;creation_time=100;flow_id=$n;source=('192.0.2.1:'+(3000+$n));destination=$obs.destination;started_at='old';domain='www.youtube.com'}}
foreach($n in 1..40){$rows+=@{pid=42;creation_time=99;flow_id=(200+$n);source=('192.0.2.1:'+(4000+$n));destination=$obs.destination;started_at='PID reused';domain='www.youtube.com'}}
$rows+=@{pid=42;creation_time=100;flow_id=500;exe=$exe;protocol='tcp';source='192.0.2.1:55000';destination=$obs.destination;started_at=[DateTimeOffset]::UtcNow.ToString('o');domain='';selected_route='RELAY';relay_id='VPS-01';counters=@{relayed_bytes=10655;relay_reply_bytes=4096;captured_packets=9}}
function Invoke-ServiceIPC($Method,$Payload){
 if($Method -ne 'capture.diagnostics'){throw 'Unexpected query method'}
 $queryLog.Add($Payload)
 $matching=@($rows|Where-Object{$_.pid -eq $Payload.pid -and $_.creation_time -eq $Payload.creation_time -and $_.flow_id -gt $Payload.since.after_flow_id -and $_.destination -eq $Payload.destination})
 if($Payload.ContainsKey('domain')){$matching=@($matching|Where-Object{$_.domain -eq $Payload.domain})}
 if($Payload.ContainsKey('source')){$matching=@($matching|Where-Object{$_.source -eq $Payload.source})}
 return @{flows=@($matching|Select-Object -First 32);truncated=($matching.Count -gt 32);since=$Payload.since;marker=@{ledger_id='scope';after_flow_id=600;lost_records=0}}
}
$scopedIDs=@([pscustomobject]@{PID=42;CreationTime=100},[pscustomobject]@{PID=43;CreationTime=200})
$scoped=Get-V2ScopedCapture $scopedMarker $scopedIDs $obs.destination
Check (!$scoped.truncated -and $scoped.flows.Count -eq 1 -and $queryLog.Count -eq 2) 'MANUAL contaminated by >32 stale/reused PID flows'
foreach($query in $queryLog){Check ($query.pid -gt 0 -and $query.creation_time -gt 0 -and $query.since.ledger_id -eq 'scope') 'Destination-only query reintroduced'}
$scopedProof=Get-V2ProofCapture $scopedMarker $scopedIDs $obs.destination $obs.hostname $obs.socket_binding
[void](Assert-V2BrowserEvidence $obs $scopedProof $scopedIDs $exe 'RELAY' '')
Write-Host 'PASS MANUAL/current-PID scoped query ignores >32 previous-trial flows before frame limits'
$oldIPC=(Get-Item Function:Invoke-ServiceIPC).ScriptBlock
try{
 function Invoke-ServiceIPC($Method,$Payload){return @([pscustomobject]@{PID=1;CreationTime=99;Path=$exe},[pscustomobject]@{PID=2;CreationTime=100;Path=$exe},[pscustomobject]@{PID=3;CreationTime=101;Path='C:\other.exe'})}
 $current=@(Get-V2TrialIdentities $exe 100)
 Check ($current.Count -eq 1 -and $current[0].PID -eq 2) 'Process birth/executable filter borrowed a stale or foreign PID'
}finally{Set-Item Function:Invoke-ServiceIPC $oldIPC}

# Independent, bounded Chromium metadata parser. Never choose a nearby socket
# or infer local source port from SNI, response timing or newest tuple.
$rawDir=Join-Path ([IO.Path]::GetTempPath()) ('v2-socket-fixture-'+[Guid]::NewGuid().ToString('N'));[void](New-Item -ItemType Directory $rawDir);$rawPath=Join-Path $rawDir 'private.json'
try{
 $log=@{constants=@{logSourceType=@{SOCKET=1};logEventTypes=@{TCP_CONNECT=2;TCP_CONNECT_ATTEMPT=3};logEventPhase=@{PHASE_END=2}};events=@(
  @{source=@{id=99;type=1};type=2;phase=1;params=@{address_list=@('203.0.113.9:443')}},
  @{source=@{id=99;type=1};type=3;phase=2;params=@{local_address='192.0.2.1:55000';remote_address='203.0.113.9:443';headers='Cookie: secret-sentinel';data='raw-sentinel'}},
  @{source=@{id=99;type=1};type=2;phase=2;params=@{source_address='192.0.2.1:55000'}}
 )}
 $log|ConvertTo-Json -Depth 12|Set-Content $rawPath -Encoding UTF8
 $bound=Read-V2SocketBinding $rawPath 99 '203.0.113.9:443'
 Check ($bound.status -eq 'BOUND' -and $bound.source -eq '192.0.2.1:55000') 'Exact NetLog source ID/endpoint not correlated'
 Check (($bound|ConvertTo-Json) -notmatch 'sentinel|headers|Cookie') 'Raw/private metadata escaped into proof'
 # Current Chromium reports the address pair on TCP_CONNECT END; the nested
 # attempt can end without params (both Windows and POSIX implementations).
 $savedAttempt=$log.events[1].params;$savedEnd=$log.events[2].params
 $log.events[1].params=@{};$log.events[2].params=@{local_address='192.0.2.1:55000';remote_address='203.0.113.9:443'}
 $log|ConvertTo-Json -Depth 12|Set-Content $rawPath -Encoding UTF8
 Check ((Read-V2SocketBinding $rawPath 99 '203.0.113.9:443').status -eq 'BOUND') 'Current Chromium TCP_CONNECT address-pair schema rejected'
 $log.events[1].params=$savedAttempt;$log.events[2].params=$savedEnd
 $log|ConvertTo-Json -Depth 12|Set-Content $rawPath -Encoding UTF8

 Check ((Read-V2SocketBinding $rawPath 100 '203.0.113.9:443').status -eq 'UNAVAILABLE') 'Wrong CDP socket ID accepted'
 Check ((Read-V2SocketBinding $rawPath 99 '203.0.113.10:443').status -eq 'UNAVAILABLE') 'Wrong destination accepted'
 $log.events[1].params.remote_address='203.0.113.10:443';$log|ConvertTo-Json -Depth 12|Set-Content $rawPath -Encoding UTF8
 Check ((Read-V2SocketBinding $rawPath 99 '203.0.113.9:443').status -eq 'UNAVAILABLE') 'Contradictory actual peer accepted from address list'
 $log.events[1].params.remote_address='203.0.113.9:443'
 $log.events+=@{source=@{id=99;type=1};type=2;phase=2;params=@{source_address='192.0.2.1:55001'}};$log|ConvertTo-Json -Depth 12|Set-Content $rawPath -Encoding UTF8
 Check ((Read-V2SocketBinding $rawPath 99 '203.0.113.9:443').status -eq 'UNAVAILABLE') 'Ambiguous local endpoint accepted'
 [IO.File]::WriteAllText($rawPath,'{"constants":')
 Check ((Read-V2SocketBinding $rawPath 99 '203.0.113.9:443').status -eq 'UNAVAILABLE') 'Incomplete raw metadata invented socket proof'
 $stream=[IO.File]::OpenWrite($rawPath);try{$stream.SetLength(8MB+1)}finally{$stream.Dispose()}
 Check ((Read-V2SocketBinding $rawPath 99 '203.0.113.9:443').status -eq 'UNAVAILABLE') 'Oversize metadata bypassed parser bound'
}finally{Remove-Item $rawDir -Recurse -Force}
Write-Host 'PASS exact socket ID, peer/local endpoint ambiguity, missing/incomplete/oversized metadata and privacy allowlist'
