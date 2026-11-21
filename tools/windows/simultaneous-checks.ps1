Set-StrictMode -Version Latest
function Get-SimValue($Object,[string]$Name,$Default=$null){
 if($null -eq $Object){return $Default}
 if($Object -is [System.Collections.IDictionary]){if($Object.Contains($Name)){return $Object[$Name]};return $Default}
 $p=$Object.PSObject.Properties[$Name];if($null -ne $p){return $p.Value};return $Default
}
function Test-SimHas($Object,[string]$Name){
 if($null -eq $Object){return $false}
 if($Object -is [System.Collections.IDictionary]){return $Object.Contains($Name)}
 return $null -ne $Object.PSObject.Properties[$Name]
}
function Merge-SimPage($State,$Page){
 $cursor=Get-SimValue $Page 'cursor';$ledger=[string](Get-SimValue $cursor 'ledger_id' '')
 $next=[uint64](Get-SimValue $cursor 'after_update' -1)
 if($ledger -ne $State.Cursor.ledger_id -or $next -lt $State.Cursor.after_update){throw 'Capture cursor changed/restarted or moved backwards'}
 if([bool](Get-SimValue $Page 'evidence_lost' $true)){$State.Lost=$true;throw 'Capture consumer lagged bounded history: no complete/no-leak claim allowed'}
 $more=[bool](Get-SimValue $Page 'more' $true)
 if($more -and $next -le $State.Cursor.after_update){throw 'Capture pagination made no progress'}
 if($Page -is [System.Collections.IDictionary]){if(!$Page.Contains('flows')){throw 'Missing flow page'}}elseif($null -eq $Page.PSObject.Properties['flows']){throw 'Missing flow page'}
 $flows=@(Get-SimValue $Page 'flows' @())
 if($flows.Count -gt 32){throw 'Capture page exceeded bound'}
 foreach($flow in $flows){
  $id=[uint64](Get-SimValue $flow 'flow_id' 0)
  if(!$id -or !(Get-SimValue $flow 'pid' 0) -or !(Get-SimValue $flow 'creation_time' 0) -or !(Get-SimValue $flow 'exe' '')){throw 'Unversioned/unattributed flow evidence'}
  $key=[string]$id
  if(!$State.Flows.ContainsKey($key) -and $State.Flows.Count -ge 8192){throw 'Capture flow accumulator limit exceeded'}
  # Cumulative snapshots replace each other. Summing would invent bytes/packets.
  $State.Flows[$key]=$flow
 }
 $State.Cursor=[pscustomobject]@{ledger_id=$ledger;after_update=$next}
 return $more
}
function Test-SimDisorder($Flow){
 # Strategy is a configured profile ID, not necessarily an action name.
 # New evidence records the applied action chain. Exact tokens avoid accepting
 # a profile merely because its ID contains the word disorder.
 $chain=[string](Get-SimValue $Flow 'chain' '')
 if($chain){return $chain -match '(^|\s*\+\s*)tcp-disorder($|\s*\+\s*)'}
 return (Get-SimValue $Flow 'strategy' '') -eq 'disorder'
}
function Add-SimDropGates($Proof,$Before,$After){
 foreach($name in @('capture_queue_drops','worker_saturation_drops')){
  $start=Get-SimValue (Get-SimValue (Get-SimValue $Before 'capture') $name) 'count' -1
  $end=Get-SimValue (Get-SimValue (Get-SimValue $After 'capture') $name) 'count' -1
  if($start -lt 0 -or $end -lt $start){throw "Drop baseline unavailable or service restarted: $name"}
  $delta=$end-$start
  $Proof|Add-Member -NotePropertyName ($name+'_delta') -NotePropertyValue $delta
  if($delta -ne 0){$Proof.transport_evidence_pass=$false}
 }
}
function Get-SimProof($State,[string[]]$RequiredProcesses){
 if($State.Lost){throw 'Incomplete capture cannot establish no leaks'}
 $all=@($State.Flows.Values);$required=@($all|Where-Object{
  $policy=Get-SimValue $_ 'policy'
  (Get-SimValue $policy 'action' '') -eq 'RELAY_REQUIRED' -or (Get-SimValue $policy 'fallback' '') -eq 'RELAY_REQUIRED'
 })
 foreach($f in $required){$c=Get-SimValue $f 'counters';foreach($name in @('direct_bytes','direct_packets','relayed_bytes','relay_reply_bytes')){if(!(Test-SimHas $c $name)){throw "Missing protected counter: $name"}}}
 $mediaFailures=@($all|Where-Object{
  (Get-SimValue (Get-SimValue $_ 'policy') 'fallback' '') -eq 'FLOW_RELAY_FALLBACK' -and ((Get-SimValue $_ 'selected_route' '') -like 'BLOCK*' -or (Get-SimValue $_ 'fallback_reason' '') -eq 'TRANSPORT_FAILED')
 })
 $leaks=@($required|Where-Object{[uint64](Get-SimValue (Get-SimValue $_ 'counters') 'direct_bytes' 0) -gt 0 -or [uint64](Get-SimValue (Get-SimValue $_ 'counters') 'direct_packets' 0) -gt 0})
 $failures=@($required|Where-Object{
  $open=Get-SimValue $_ 'relay_open'
  (Get-SimValue $_ 'selected_route' '') -like 'BLOCK*' -or [bool](Get-SimValue $_ 'relay_required_blocked' $false) -or (Get-SimValue $_ 'fallback_reason' '') -in @('RELAY_OPEN_FAILED','TRANSPORT_FAILED') -or (Get-SimValue $open 'failure_reason' '') -or (Get-SimValue $_ 'failure_cause' '')
 })
 $apps=@();foreach($name in $RequiredProcesses){
  $flows=@($required|Where-Object{([string](Get-SimValue $_ 'exe' '')).Replace('\','/').Split('/')[-1] -ieq $name})
  $bytes=[uint64]0;$reply=[uint64]0
  foreach($f in $flows){$c=Get-SimValue $f 'counters';$bytes += [uint64](Get-SimValue $c 'relayed_bytes' 0);$reply += [uint64](Get-SimValue $c 'relay_reply_bytes' 0)}
  $apps+=@{exe=$name;flows=$flows.Count;relayed_bytes=$bytes;reply_bytes=$reply;responding=($flows.Count -gt 0 -and $bytes -gt 0 -and $reply -gt 0)}
 }
 $youtube=@($all|Where-Object{
  $exe=([string](Get-SimValue $_ 'exe' '')).Replace('\','/').Split('/')[-1]
  $hostName=[string](Get-SimValue $_ 'domain' '')
  $exe -ieq 'chrome.exe' -and (Get-SimValue $_ 'protocol' '') -eq 'tcp' -and $hostName -match '(^|\.)(youtube\.com|googlevideo\.com|ytimg\.com)$'
 })
 $badYouTube=@($youtube|Where-Object{
  $c=Get-SimValue $_ 'counters';$p=Get-SimValue $_ 'policy'
  (Get-SimValue $_ 'selected_route' '') -ne 'DIRECT_PLUS' -or !(Test-SimDisorder $_) -or (Get-SimValue $p 'source' '') -ne 'configured_baseline' -or [uint64](Get-SimValue $c 'direct_plus_packets' 0) -eq 0 -or [uint64](Get-SimValue $c 'relayed_bytes' 0) -ne 0
 })
 return [pscustomobject]@{complete_evidence=$true;flow_records=$all.Count;required_flows=$required.Count;direct_leaks=$leaks.Count;protected_failures=$failures.Count;media_transport_failures=$mediaFailures.Count;applications=$apps;youtube_flows=$youtube.Count;youtube_invalid=$badYouTube.Count;transport_evidence_pass=($required.Count -gt 0 -and $leaks.Count -eq 0 -and $failures.Count -eq 0 -and $mediaFailures.Count -eq 0 -and @($apps|Where-Object{!$_.responding}).Count -eq 0 -and $youtube.Count -gt 0 -and $badYouTube.Count -eq 0);application_acceptance='OPERATOR_OBSERVATION_REQUIRED'}
}
