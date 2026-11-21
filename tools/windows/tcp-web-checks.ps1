# Evidence checks shared by live acceptance and deterministic regressions.
function Assert-TcpWebProof($Report,$Evidence,[uint32]$PIDValue,[string]$Exe,[string]$Route,[string]$RelayEgress,[string]$Mode,[int]$ExpectedCount) {
 if($Report.pid -ne $PIDValue -or $Report.exe -ine $Exe -or $Report.creation_time -le 0){throw 'TCP client identity mismatch'}
 $errorProperty=$Report.PSObject.Properties['error']
 if($null -ne $errorProperty -and ![string]::IsNullOrWhiteSpace([string]$errorProperty.Value)){throw "Client failed: $($errorProperty.Value)"}
 if(@($Report.attempts).Count -ne $ExpectedCount){throw 'Missing connection attempts'}
 foreach($attempt in $Report.attempts){
  if(!$attempt.success){throw 'TCP connection failed; inspect attempt error'}
  if($Mode -in @('https','http2','websocket') -and !$attempt.tls){throw 'Expected end-to-end TLS'}
  if($Mode -eq 'http2' -and $attempt.protocol -ne 'HTTP/2.0'){throw 'HTTP/2 was not negotiated'}
  if(($Route -eq 'RELAY' -and $attempt.response_source -ne $RelayEgress) -or ($Route -eq 'DIRECT' -and $attempt.response_source -eq $RelayEgress) -or [string]::IsNullOrWhiteSpace($attempt.response_source)){throw 'Destination-observed source does not prove route'}
  $flows=@($Evidence.flows | Where-Object {$_.pid -eq $PIDValue -and $_.creation_time -eq $Report.creation_time -and $_.exe -ieq $Exe -and $_.protocol -eq 'tcp' -and $_.ip_version -eq 'IPv4' -and $_.destination -eq $attempt.destination})
  if($flows.Count -eq 0){throw "Missing TCP capture evidence: $($attempt.destination)"}
  foreach($flow in $flows){
   $c=$flow.counters
   if($flow.selected_route -ne $Route -or $c.captured_packets -le 0 -or $c.captured_bytes -le 0){throw 'Route/capture evidence missing'}
   if($Route -eq 'RELAY'){
    if($flow.relay_id -ne 'VPS-01' -or $c.relayed_packets -le 0 -or $c.relayed_bytes -le 0 -or $c.relay_reply_packets -le 0 -or $c.relay_reply_bytes -le 0 -or $c.direct_packets -ne 0 -or $c.direct_bytes -ne 0){throw 'Incomplete RELAY TCP evidence'}
   } elseif($c.direct_packets -le 0 -or $c.direct_bytes -le 0 -or $c.relayed_packets -ne 0 -or $c.relayed_bytes -ne 0){throw 'Incomplete DIRECT TCP evidence'}
  }
 }
}
