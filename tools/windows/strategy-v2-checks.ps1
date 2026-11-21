Set-StrictMode -Version Latest
function Assert-V2BrowserEvidence($Observation,$Capture,$Identities,[string]$Exe,[string]$Route,[string]$Strategy){
 if(!(Get-V2Value $Observation 'success' $false) -or (Get-V2Value $Observation 'status' 0) -lt 200 -or (Get-V2Value $Observation 'status' 0) -ge 400 -or !(Get-V2Value $Observation 'tls' $false) -or !(Get-V2Value $Observation 'completed' $false)){throw 'No completed certificate-validated HTTPS response'}
 if((Get-V2Value $Observation 'from_cache' $false) -or (Get-V2Value $Observation 'from_service_worker' $false)){Throw-V2Ambiguous 'Cached/service-worker response cannot prove current socket routing'}
 if((Get-V2Value $Observation 'protocol' '') -notin @('h2','http/1.1','http/1.0')){throw 'TCP strategy requires a real TCP HTTPS response, not HTTP/3 inference'}
 if((Get-V2Value $Capture 'truncated' $true) -or (Get-V2Value $Capture 'evidence_lost' $false)){Throw-V2Ambiguous 'Current target capture truncated or lost; no complete target route proof'}
 $since=Get-V2Value $Capture 'since';$epoch=[string](Get-V2Value $since 'ledger_id' '')
 if(!$epoch -or (Get-V2Value (Get-V2Value $Capture 'marker') 'ledger_id' '') -ne $epoch){Throw-V2Ambiguous 'No capture-lifetime/trial scope'}
 $hostName=([string](Get-V2Value $Observation 'hostname' '')).ToLowerInvariant().TrimEnd('.')
 if(!$hostName){Throw-V2Ambiguous 'Main-frame hostname missing'}
 $flows=@(Get-V2Value $Capture 'flows' @()|Where-Object{
  $f=$_
  (Get-V2Value $f 'exe' '') -ieq $Exe -and (Get-V2Value $f 'destination' '') -eq (Get-V2Value $Observation 'destination' '') -and (Get-V2Value $f 'protocol' '') -eq 'tcp' -and (Get-V2Value $f 'flow_id' 0) -gt (Get-V2Value $since 'after_flow_id' 0) -and @( $Identities|Where-Object{(Get-V2Value $_ 'PID' -1) -eq (Get-V2Value $f 'pid' -2) -and (Get-V2Value $_ 'CreationTime' -1) -eq (Get-V2Value $f 'creation_time' -2)}).Count -gt 0
 })
 if(!$flows.Count){Throw-V2Ambiguous 'No current exact app identity/destination flow'}
 # Unknown or OTHER SNI is not proof that this hostname used another route.
 # A positively observed target-hostname conflict remains a strict rejection.
 $target=@($flows|Where-Object{(Get-V2ObservedDomain $_) -eq $hostName})
 if(@($target|Where-Object{(Get-V2Value $_ 'selected_route' '') -ne $Route}).Count){Throw-V2Ambiguous 'Target hostname used mixed routes in this trial'}
 $binding=Get-V2Value $Observation 'socket_binding'
 if((Get-V2Value $binding 'status' '') -ne 'BOUND' -or (Get-V2Value $binding 'method' '') -ne 'chromium_netlog_socket_id' -or (Get-V2Value $binding 'connection_id' 0) -le 0 -or (Get-V2Value $binding 'connection_id' -1) -ne (Get-V2Value $Observation 'connection_id' -2) -or (Get-V2Value $binding 'destination' '') -ne $Observation.destination){Throw-V2Ambiguous 'Completed response lacks exact CDP connectionId -> local endpoint binding; unknown same-IP flows are not classified as DIRECT target traffic'}
 $source=[string](Get-V2Value $binding 'source' '')
 $exact=@($flows|Where-Object{(Get-V2Value $_ 'source' '') -eq $source -and $source})
 if($exact.Count -ne 1){Throw-V2Ambiguous 'Main-frame source endpoint has zero or multiple current flow generations'}
 $f=$exact[0];$c=Get-V2Value $f 'counters';$i=Get-V2Value $f 'local_inspection'
 if((Get-V2Value $c 'captured_packets' 0) -le 0){Throw-V2Ambiguous 'Exact main-frame flow has no captured packet evidence'}
 if(!(Get-V2Value $f 'started_at') -or (Get-V2Value $f 'selected_route' '') -ne $Route){Throw-V2Ambiguous 'Exact main-frame flow route/birth evidence differs from expected'}
 if($Route -eq 'DIRECT_PLUS'){
  if((Get-V2ObservedDomain $f) -ne $hostName -or (Get-V2Value $f 'strategy' '') -ne $Strategy -or (Get-V2Value $i 'reason' '') -ne 'REASSEMBLY_COMPLETE' -or !(Get-V2Value $i 'transform_applied' $false) -or (Get-V2Value $c 'direct_plus_packets' 0) -le 0 -or (Get-V2Value $c 'direct_plus_bytes' 0) -le 0 -or (Get-V2Value $c 'relayed_packets' -1) -ne 0 -or (Get-V2Value $c 'relayed_bytes' -1) -ne 0){Throw-V2Ambiguous 'Exact target flow lacks completed reassembly/SNI/current strategy/committed transform/zero-relay proof'}
 }elseif($Route -eq 'RELAY'){
  if((Get-V2Value $f 'relay_id' '') -ne 'VPS-01' -or (Get-V2Value $c 'relayed_bytes' 0) -le 0 -or (Get-V2Value $c 'relay_reply_bytes' 0) -le 0){Throw-V2Ambiguous 'Exact response socket lacks authenticated RELAY request/reply counters'}
 }else{
  if((Get-V2Value $c 'direct_packets' 0) -le 0 -or (Get-V2Value $c 'relayed_packets' -1) -ne 0 -or (Get-V2Value $c 'direct_plus_packets' -1) -ne 0){Throw-V2Ambiguous 'Exact response socket lacks exclusive DIRECT counters'}
 }
 return $f
}

# Diagnostics are independent of PASS validation. Missing evidence is UNKNOWN,
# not zero; positive counters survive truncated snapshots, negative claims do not.
function Get-V2Value($Object,[string]$Name,$Default=$null){
 if($null -eq $Object){return $Default}
 if($Object -is [Collections.IDictionary]){if($Object.Contains($Name)){return $Object[$Name]};return $Default}
 $p=$Object.PSObject.Properties[$Name];if($null -ne $p){return $p.Value};return $Default
}
function Get-V2ExceptionDetails([Exception]$ErrorObject){
 $out=@();$e=$ErrorObject
 for($i=0;$null -ne $e -and $i -lt 8;$i++){$out+=@{type=$e.GetType().FullName;message=$e.Message};$e=$e.InnerException}
 return $out
}
function Get-V2TrialDiagnostic($Capture,$Identities,[string]$Exe,[string]$Destination,[string]$Mode,[bool]$Success,[bool]$MeasurementValid,[string]$FailureKind,$Candidate,[string]$Hostname=''){
 $flows=@(Get-V2Value $Capture 'flows' @()|Where-Object{
  $f=$_
  (Get-V2Value $f 'exe' '') -ieq $Exe -and (Get-V2Value $f 'destination' '') -eq $Destination -and @($Identities|Where-Object{(Get-V2Value $_ 'PID' -1) -eq (Get-V2Value $f 'pid' -2) -and (Get-V2Value $_ 'CreationTime' -1) -eq (Get-V2Value $f 'creation_time' -2)}).Count -gt 0
 })
 $complete=$null -ne $Capture -and !(Get-V2Value $Capture 'truncated' $true) -and $flows.Count -gt 0
 $totals=@{};$details=@();$tags=@();$applied=$false;$partial=$false;$quic=$false
 $names=@('captured_packets','direct_plus_packets','direct_plus_bytes','fake_tls_packets','quic_fallback_packets','relayed_bytes')
 foreach($n in $names){$totals[$n]=0L}
 foreach($f in $flows){
  $c=Get-V2Value $f 'counters';$row=@{}
  foreach($n in $names){$v=Get-V2Value $c $n;$row[$n]=$v;if($null -eq $v){$totals[$n]=$null;$complete=$false}elseif($null -ne $totals[$n]){$totals[$n]+=[long]$v}}
  $inspection=Get-V2Value $f 'local_inspection';$why=[string](Get-V2Value $inspection 'reason' '')
  if($why -eq 'TRANSFORM_SEND_FAILED'){$tags+=$why;if((Get-V2Value $inspection 'output_packets_sent' 0) -gt 0){$partial=$true}}
  if($why -in @('CLIENTHELLO_INCOMPLETE','SNI_NOT_FOUND','DOMAIN_NOT_MATCHED','REASSEMBLY_STARTED','REASSEMBLY_WAITING','REASSEMBLY_COMPLETE','REASSEMBLY_TIMEOUT','REASSEMBLY_LIMIT','REASSEMBLY_OUT_OF_ORDER')){$tags+=$why}
  $domain=Get-V2ObservedDomain $f
  $strategy=Get-V2Value $f 'strategy' ''; $candidateID=Get-V2Value $Candidate 'id' ''
  if((Get-V2Value $f 'protocol' '') -eq 'tcp' -and (!$Hostname -or $domain -eq $Hostname.ToLowerInvariant().TrimEnd('.')) -and $strategy -eq $candidateID -and $candidateID -ne '' -and $null -ne $row.direct_plus_packets -and $null -ne $row.direct_plus_bytes -and $row.direct_plus_packets -gt 0 -and $row.direct_plus_bytes -gt 0){$applied=$true}
  if($null -ne $row.quic_fallback_packets -and $row.quic_fallback_packets -gt 0){$quic=$true}
  $details+=@{flow_id=(Get-V2Value $f 'flow_id');started_at=(Get-V2Value $f 'started_at');source=(Get-V2Value $f 'source');pid=(Get-V2Value $f 'pid');creation_time=(Get-V2Value $f 'creation_time');exe=(Get-V2Value $f 'exe');destination=(Get-V2Value $f 'destination');protocol=(Get-V2Value $f 'protocol');selected_route=(Get-V2Value $f 'selected_route');strategy=$strategy;observed_domain=$domain;target_relation=$(if(!$Hostname){'UNSCOPED'}elseif(!$domain){'UNKNOWN_DOMAIN'}elseif($domain -eq $Hostname.ToLowerInvariant().TrimEnd('.')){'TARGET_SNI'}else{'OTHER_SNI'});chain=(Get-V2Value $f 'chain');fake_ttl=(Get-V2Value $f 'fake_ttl');counters=$row;inspection=$inspection}
 }
 if(!$flows.Count){foreach($n in $names){$totals[$n]=$null};$tags+='NO_CAPTURE_EVIDENCE'}
 $connectionFailed=(!$Success -and $MeasurementValid -and $FailureKind -in @('NETWORK_TIMEOUT','BROWSER_NETWORK_FAILURE'))
 $state='UNKNOWN'
 if($applied){$state='APPLIED';if($connectionFailed){$tags+='TRANSFORM_APPLIED_CONNECTION_FAILED'}}
 elseif($partial){$state='PARTIAL_OUTPUT'}
 elseif($Mode -eq 'DIRECT_PLUS' -and $complete -and $totals.captured_packets -gt 0 -and $totals.direct_plus_packets -eq 0){$state='NOT_OBSERVED';$tags+='NO_TRANSFORM'}
 if($quic){$tags+='QUIC_FALLBACK_APPLIED'}
 if(!$Success){if($FailureKind){$tags+=$FailureKind};if(!$MeasurementValid -and $FailureKind -notin @('TARGET_FLOW_AMBIGUOUS','EVIDENCE_VALIDATION_FAILURE','NETWORK_CHANGED')){$tags+='CDP/INSTRUMENTATION_FAILURE'}}
 if($Success){$primary='PASS'}elseif($FailureKind -in @('TARGET_FLOW_AMBIGUOUS','EVIDENCE_VALIDATION_FAILURE','NETWORK_CHANGED')){$primary=$FailureKind}elseif(!$MeasurementValid){$primary='CDP/INSTRUMENTATION_FAILURE'}elseif($applied -and $connectionFailed){$primary='TRANSFORM_APPLIED_CONNECTION_FAILED'}elseif($tags.Count){$primary=$tags[0]}else{$primary='CONNECTION_FAILED'}
 $configuredChain=@(Get-V2Value $Candidate 'actions' @()|ForEach-Object{Get-V2Value $_ 'kind' ''}) -join ' + '
 $configuredTTL=@(Get-V2Value $Candidate 'actions' @()|Where-Object{(Get-V2Value $_ 'kind' '') -eq 'fake-tls'}|ForEach-Object{Get-V2Value $_ 'ttl'})
 return @{classification=$primary;classifications=@($tags|Select-Object -Unique);transform_status=$state;evidence_complete=[bool]$complete;counters=$totals;flows=$details;configured_chain=$configuredChain;configured_fake_ttl=$configuredTTL;target_hostname=$Hostname}
}
function Write-V2TrialDiagnostic($Diagnostic){
 Write-Host ('  classification={0}; tags={1}; TCP transform={2}; complete={3}' -f $Diagnostic.classification,($Diagnostic.classifications -join ','),$Diagnostic.transform_status,$Diagnostic.evidence_complete)
 $pairs=@();foreach($n in @('captured_packets','direct_plus_packets','direct_plus_bytes','fake_tls_packets','quic_fallback_packets','relayed_bytes')){$v=$Diagnostic.counters[$n];if($null -eq $v){$v='UNKNOWN'};$pairs+="$n=$v"};Write-Host ('  '+($pairs -join '; '))
 foreach($f in $Diagnostic.flows){Write-Host ('  flow_id={0}; source={1}; destination={2}; started_at={3}' -f (Get-V2Value $f 'flow_id' 'UNKNOWN'),(Get-V2Value $f 'source' 'UNKNOWN'),(Get-V2Value $f 'destination' 'UNKNOWN'),(Get-V2Value $f 'started_at' 'UNKNOWN'));$display=@{};foreach($field in @('observed_domain','chain','fake_ttl')){$display[$field]=$f[$field];if($null -eq $display[$field] -or [string]$display[$field] -eq ''){$display[$field]='NOT_OBSERVED'}};Write-Host ('  PID={0}; protocol={1}; route={2}; SNI/domain={3}; applied_chain={4}; applied_fake_TTL={5}; inspection={6}' -f $f.pid,$f.protocol,$f.selected_route,$display.observed_domain,$display.chain,$display.fake_ttl,(Get-V2Value $f.inspection 'reason' 'UNAVAILABLE'));Write-Host ('    hello_payload={0}; record={1}; handshake={2}; plan_sent={3}/{4}; detail={5}' -f (Get-V2Value $f.inspection 'payload_bytes' 'UNKNOWN'),(Get-V2Value $f.inspection 'record_bytes' 'UNKNOWN'),(Get-V2Value $f.inspection 'handshake_bytes' 'UNKNOWN'),(Get-V2Value $f.inspection 'output_packets_sent' 'UNKNOWN'),(Get-V2Value $f.inspection 'output_packets_planned' 'UNKNOWN'),(Get-V2Value $f.inspection 'detail' 'UNAVAILABLE'))}
 foreach($f in $Diagnostic.flows){$i=$f.inspection;if((Get-V2Value $i 'segments_seen' 0) -gt 0){Write-Host ('    segments_seen={0}; segments_buffered={1}; bytes_buffered={2}; expected_clienthello_bytes={3}; reassembly_ms={4}; reassembled_sni={5}; transform_applied={6}' -f (Get-V2Value $i 'segments_seen'),(Get-V2Value $i 'segments_buffered'),(Get-V2Value $i 'bytes_buffered'),(Get-V2Value $i 'expected_clienthello_bytes'),(Format-V2EvidenceValue $i 'reassembly_ms'),(Get-V2Value $i 'reassembled_sni'),(Get-V2Value $i 'transform_applied')) }}
 Write-Host ('  configured_chain={0}; configured_fake_TTL={1} (configuration is not application evidence)' -f $Diagnostic.configured_chain,($Diagnostic.configured_fake_ttl -join ','))
}
function Get-V2ExceptionKind([Exception]$ErrorObject){
 $e=$ErrorObject
 for($i=0;$null -ne $e -and $i -lt 8;$i++){if($e.Data.Contains('v2_failure_kind')){return [string]$e.Data['v2_failure_kind']};$e=$e.InnerException}
 return ''
}

# observed_at is assigned only when InspectNetwork finishes a fresh OS scan.
# Re-reading local.network's cached snapshot never advances the stable count.
function Test-V2NetworkCycle($Snapshot,$State){
 $vpn=@(Get-V2Value $Snapshot 'vpn' @());if($vpn.Count){throw ('VPN present in network snapshot: '+($vpn -join ', ')+'. Turn Happ OFF and wait for a fresh service scan (up to 30 seconds).')}
 if((Get-V2Value $Snapshot 'error' '') -or !(Get-V2Value $Snapshot 'fingerprint' '') -or @(Get-V2Value $Snapshot 'conflicts' @()).Count){throw 'Valid network fingerprint without capture conflicts required'}
 $value=Get-V2Value $Snapshot 'observed_at' ''
 $parsed=[DateTimeOffset]::MinValue;$valid=$false
 # PS7 ConvertFrom-Json can return DateTime; casting that to string drops its
 # UTC kind and then TryParse would reinterpret it in the Windows local zone.
 if($value -is [DateTimeOffset]){$parsed=$value;$valid=$true}
 elseif($value -is [DateTime]){if($value.Kind -ne [DateTimeKind]::Unspecified){$parsed=[DateTimeOffset]$value;$valid=$true}}
 else{$valid=[DateTimeOffset]::TryParse([string]$value,[ref]$parsed)}
 if(!$valid -or ([DateTimeOffset]::UtcNow-$parsed).TotalSeconds -gt 45 -or $parsed -gt [DateTimeOffset]::UtcNow.AddSeconds(5)){throw 'Fresh network refresh timestamp required'}
 $stamp=$parsed.ToUniversalTime().ToString('o',[Globalization.CultureInfo]::InvariantCulture)
 if($stamp -ne $State.last_refresh){
  if($State.last_refresh -and $parsed -le [DateTimeOffset]::Parse($State.last_refresh)){throw 'Network refresh timestamp moved backwards'}
  if($State.fingerprint -eq $Snapshot.fingerprint){$State.cycles++}else{$State.fingerprint=$Snapshot.fingerprint;$State.cycles=1}
  $State.last_refresh=$stamp
 }
 return ($State.cycles -ge 2)
}
function Wait-V2StableNetwork([int]$TimeoutSeconds=100,[scriptblock]$GetSnapshot={Invoke-ServiceIPC 'local.network'}){
 $state=@{last_refresh='';fingerprint='';cycles=0};$watch=[Diagnostics.Stopwatch]::StartNew()
 while($true){$n=&$GetSnapshot;if(Test-V2NetworkCycle $n $state){return $n};if($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds){throw 'Network preflight timeout: two equal fingerprints from different fresh OS refresh cycles required'};Start-Sleep -Milliseconds 250}
}
function Assert-V2FrozenNetwork($Frozen,$Current){
 $scratch=@{last_refresh='';fingerprint='';cycles=0};[void](Test-V2NetworkCycle $Current $scratch)
 if((Get-V2Value $Frozen 'fingerprint' '') -ne (Get-V2Value $Current 'fingerprint' '')){throw 'Network changed during test; discard trial measurements and restart preflight'}
}
function Get-V2MainFrame($Response){
 $id=[string](Get-V2Value (Get-V2Value (Get-V2Value $Response 'frameTree') 'frame') 'id' '')
 if(!$id){throw 'CDP Page.getFrameTree returned no main-frame identity; instrumentation unavailable'}
 return $id
}
function Stop-V2TrialBrowser($Browser,[string]$Data){
 # Cleanup is best-effort and never overwrites a trial result. taskkill can
 # race Chrome's normal exit; PS5.1 turns native stderr into terminating errors.
 $issues=@()
 if($script:socket){try{$script:socket.Dispose()}catch{$issues+=$_.Exception.Message};$script:socket=$null}
 if($Browser){
  try{if(!$Browser.HasExited){& taskkill.exe /PID $Browser.Id /T /F 2>&1|Out-Null}}catch{$issues+=$_.Exception.Message}
  try{if(!$Browser.HasExited){[void]$Browser.WaitForExit(3000)}}catch{$issues+=$_.Exception.Message}
  try{$Browser.Dispose()}catch{$issues+=$_.Exception.Message}
 }
 try{if(Test-Path $Data){Remove-Item $Data -Recurse -Force -ErrorAction Stop}}catch{$issues+='Temporary browser profile remains; delete privately, never share: '+$Data}
 return $issues
}
function Get-V2HTTPSObservation($Response,[double]$ElapsedMS){
 try{
  foreach($field in @('remoteIPAddress','remotePort','status','securityState','protocol')){if($null -eq (Get-V2Value $Response $field) -or [string](Get-V2Value $Response $field) -eq ''){throw ('CDP response evidence missing '+$field)}}
  $ip=[Net.IPAddress]::Parse([string](Get-V2Value $Response 'remoteIPAddress' ''))
  $port=[int](Get-V2Value $Response 'remotePort' 0);$status=[int](Get-V2Value $Response 'status' 0)
  if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $port -lt 1 -or $port -gt 65535 -or $status -lt 100 -or $status -gt 599){throw 'Invalid or unsupported IPv4 CDP response evidence'}
  return @{connection_id=(Get-V2Value $Response 'connectionId' 0);from_cache=[bool](Get-V2Value $Response 'fromDiskCache' $false);from_service_worker=[bool](Get-V2Value $Response 'fromServiceWorker' $false);success=($status -ge 200 -and $status -lt 400);status=$status;tls=((Get-V2Value $Response 'securityState' '') -eq 'secure');protocol=[string](Get-V2Value $Response 'protocol' '');destination=($ip.ToString()+':'+$port);response_ms=$ElapsedMS}
 }catch{$failure=[InvalidOperationException]::new($_.Exception.Message,$_.Exception);$failure.Data['v2_failure_kind']='CDP/INSTRUMENTATION_FAILURE';throw $failure}
}

. (Join-Path $PSScriptRoot 'strategy-v2-correlation.ps1')
function Format-V2EvidenceValue($Object,[string]$Name){$v=Get-V2Value $Object $Name;if($null -eq $v -or [string]$v -eq ''){return 'UNKNOWN'};return [string]$v}
