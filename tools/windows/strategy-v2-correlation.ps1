Set-StrictMode -Version Latest

function Throw-V2Ambiguous([string]$Message){
 $e=[InvalidOperationException]::new(('TARGET_FLOW_AMBIGUOUS: '+$Message))
 $e.Data['v2_failure_kind']='TARGET_FLOW_AMBIGUOUS';throw $e
}
function Get-V2ObservedDomain($Flow){
 $i=Get-V2Value $Flow 'local_inspection'
 foreach($v in @((Get-V2Value $Flow 'domain' ''),(Get-V2Value $i 'observed_sni' ''),(Get-V2Value $i 'domain' ''))){if([string]$v -and [string]$v -ne 'NOT_OBSERVED'){return ([string]$v).TrimEnd('.').ToLowerInvariant()}}
 return ''
}
function Get-V2TrialIdentities([string]$Exe,[long]$NotBefore){
 $q=@{executables=@($Exe)}
 $rootVar=Get-Variable -Name trialRoot -Scope Script -ErrorAction SilentlyContinue
 if($rootVar -and $rootVar.Value){$q.root_pid=$rootVar.Value.PID;$q.root_creation_time=$rootVar.Value.CreationTime}
 $items=@(Invoke-ServiceIPC 'processes' $q|Where-Object{
  (Get-V2Value $_ 'Path' '') -ieq $Exe -and [long](Get-V2Value $_ 'CreationTime' 0) -ge $NotBefore -and [long](Get-V2Value $_ 'PID' 0) -gt 0
 }|Sort-Object PID,CreationTime -Unique)
 if($items.Count -gt 128){Throw-V2Ambiguous 'Trial process identity bound exceeded'}
 return $items
}
function Get-V2ScopedCapture($Marker,$Identities,[string]$Destination,[string]$Domain='',[string]$Source=''){
 if(!$Marker -or !(Get-V2Value $Marker 'ledger_id' '')){Throw-V2Ambiguous 'Service capture marker unavailable; update service'}
 $flows=@{};$truncated=$false;$lost=$false;$queries=0;$now=$Marker
 foreach($id in @($Identities)){
  $pidValue=[long](Get-V2Value $id 'PID' 0);$created=[long](Get-V2Value $id 'CreationTime' 0)
  if($pidValue -le 0 -or $created -le 0){Throw-V2Ambiguous 'Invalid exact process identity'}
  if(++$queries -gt 128){Throw-V2Ambiguous 'Trial identity bound exceeded'}
  $q=@{pid=$pidValue;creation_time=$created;destination=$Destination;since=$Marker}
  if($Domain){$q.domain=$Domain};if($Source){$q.source=$Source}
  $s=Invoke-ServiceIPC 'capture.diagnostics' $q
  $since=Get-V2Value $s 'since';$now=Get-V2Value $s 'marker'
  if((Get-V2Value $since 'ledger_id' '') -ne $Marker.ledger_id -or (Get-V2Value $since 'after_flow_id' -1) -ne $Marker.after_flow_id -or (Get-V2Value $now 'ledger_id' '') -ne $Marker.ledger_id){Throw-V2Ambiguous 'Capture lifetime changed or service did not apply trial marker'}
  $truncated=$truncated -or [bool](Get-V2Value $s 'truncated' $true);$lost=$lost -or [bool](Get-V2Value $s 'evidence_lost' $false)
  foreach($f in @(Get-V2Value $s 'flows' @())){
   if((Get-V2Value $f 'pid' 0) -ne $pidValue -or (Get-V2Value $f 'creation_time' 0) -ne $created -or (Get-V2Value $f 'destination' '') -ne $Destination -or (Get-V2Value $f 'flow_id' 0) -le $Marker.after_flow_id -or !(Get-V2Value $f 'source' '') -or !(Get-V2Value $f 'started_at')){Throw-V2Ambiguous 'Service returned foreign or unversioned flow evidence'}
   if($Domain -and (Get-V2ObservedDomain $f) -ne $Domain.ToLowerInvariant().TrimEnd('.')){Throw-V2Ambiguous 'Service did not apply target-domain filter'}
   if($Source -and (Get-V2Value $f 'source' '') -ne $Source){Throw-V2Ambiguous 'Service did not apply source-endpoint filter'}
   $key=[string]$f.flow_id
   if(!$flows.ContainsKey($key) -and $flows.Count -ge 256){Throw-V2Ambiguous 'Merged trial evidence bound exceeded'}
   $flows[$key]=$f
  }
 }
 return [pscustomobject]@{flows=@($flows.Values|Sort-Object flow_id);truncated=$truncated;evidence_lost=$lost;since=$Marker;marker=$now;query_count=$queries;domain_filter=$Domain;source_filter=$Source}
}

# Default mode strips private information and socket bytes. The bounded raw log
# exists only inside this fresh, disposable browser profile and is NEVER a proof
# attachment. Only the selected socket ID and endpoint strings leave this reader.
function Read-V2SocketBinding([string]$Path,[long]$ConnectionID,[string]$Destination){
 $unknown=@{status='UNAVAILABLE';connection_id=$ConnectionID;source=$null;destination=$Destination;method='chromium_netlog_socket_id';reason='No exact completed TCP_CONNECT for the CDP connection ID'}
 if($ConnectionID -le 0 -or !(Test-Path -LiteralPath $Path -PathType Leaf)){return $unknown}
 $file=Get-Item -LiteralPath $Path -Force
 if($file.Length -gt 8MB){$unknown.reason='Socket metadata file exceeds 8 MiB parser bound';return $unknown}
 try{$log=[IO.File]::ReadAllText($file.FullName)|ConvertFrom-Json}catch{$unknown.reason='Socket metadata incomplete/unavailable after browser close';return $unknown}
 $constants=Get-V2Value $log 'constants';$types=Get-V2Value $constants 'logEventTypes';$sourceTypes=Get-V2Value $constants 'logSourceType'
 $socketType=Get-V2Value $sourceTypes 'SOCKET' -1;$tcp=Get-V2Value $types 'TCP_CONNECT' -1;$attempt=Get-V2Value $types 'TCP_CONNECT_ATTEMPT' -1
 $end=Get-V2Value (Get-V2Value $constants 'logEventPhase') 'PHASE_END' 2
 if($socketType -lt 0 -or $tcp -lt 0 -or $attempt -lt 0){$unknown.reason='Unsupported Chromium socket metadata schema';return $unknown}
 $events=@(Get-V2Value $log 'events' @());if($events.Count -gt 32768){$unknown.reason='Socket metadata event bound exceeded';return $unknown}
 $locals=@{};$peers=@{};$actualPeers=@{};$connected=$false;$matching=0
 foreach($ev in $events){
  $src=Get-V2Value $ev 'source'
  if((Get-V2Value $src 'id' -1) -ne $ConnectionID -or (Get-V2Value $src 'type' -1) -ne $socketType){continue}
  $matching++
  $kind=Get-V2Value $ev 'type' -1;$phase=Get-V2Value $ev 'phase' -1;$p=Get-V2Value $ev 'params'
  if($kind -eq $tcp -and $phase -eq 1){foreach($a in @(Get-V2Value $p 'address_list' @())){$peers[[string]$a]=$true}}
  if($phase -ne $end -or (Get-V2Value $p 'net_error' 0) -ne 0){continue}
  if($kind -eq $tcp){$local=[string](Get-V2Value $p 'source_address' (Get-V2Value $p 'local_address' ''));$peer=[string](Get-V2Value $p 'remote_address' '');if($local){$locals[$local]=$true;$connected=$true};if($peer){$peers[$peer]=$true;$actualPeers[$peer]=$true}}
  if($kind -eq $attempt){$local=[string](Get-V2Value $p 'local_address' '');$peer=[string](Get-V2Value $p 'remote_address' '');if($local -and $peer){$locals[$local]=$true;$peers[$peer]=$true;$actualPeers[$peer]=$true;$connected=$true}}
 }
 if(!$connected -or $locals.Count -ne 1 -or !$peers.ContainsKey($Destination) -or ($actualPeers.Count -gt 0 -and ($actualPeers.Count -ne 1 -or !$actualPeers.ContainsKey($Destination)))){$unknown.reason=('Socket mapping unavailable/ambiguous: matching events={0}, local endpoints={1}, target peer observed={2}' -f $matching,$locals.Count,$peers.ContainsKey($Destination));return $unknown}
 $source=[string]@($locals.Keys)[0];$match=[regex]::Match($source,'^([0-9.]+):([0-9]{1,5})$');$ip=$null
 if(!$match.Success -or ![Net.IPAddress]::TryParse($match.Groups[1].Value,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or [int]$match.Groups[2].Value -lt 1 -or [int]$match.Groups[2].Value -gt 65535){$unknown.reason='Invalid or unsupported socket local endpoint';return $unknown}
 return @{status='BOUND';connection_id=$ConnectionID;source=($ip.ToString()+':'+[int]$match.Groups[2].Value);destination=$Destination;method='chromium_netlog_socket_id';reason='CDP connectionId equals completed Chromium TCP socket NetLog source ID'}
}
function Merge-V2ScopedCapture($A,$B){
 $items=@{};foreach($s in @($A,$B)){foreach($f in @(Get-V2Value $s 'flows' @())){$items[[string]$f.flow_id]=$f;if($items.Count -gt 256){Throw-V2Ambiguous 'Merged proof evidence bound exceeded'}}}
 return [pscustomobject]@{flows=@($items.Values|Sort-Object flow_id);truncated=([bool](Get-V2Value $A 'truncated' $true) -or [bool](Get-V2Value $B 'truncated' $true));evidence_lost=([bool](Get-V2Value $A 'evidence_lost' $false) -or [bool](Get-V2Value $B 'evidence_lost' $false));since=$A.since;marker=$B.marker}
}
function Get-V2ProofCapture($Marker,$Identities,[string]$Destination,[string]$Hostname,$Binding){
 $target=Get-V2ScopedCapture $Marker $Identities $Destination $Hostname
 if((Get-V2Value $Binding 'status' '') -eq 'BOUND'){
  $socket=Get-V2ScopedCapture $Marker $Identities $Destination '' ([string]$Binding.source)
  return Merge-V2ScopedCapture $target $socket
 }
 return $target
}
function Assert-V2SocketLogBound([string]$Path){
 $size=0L;$count=0
 if(Test-Path -LiteralPath $Path){$size+=(Get-Item -LiteralPath $Path -Force).Length}
 $pending=$Path+'.inprogress'
 if(Test-Path -LiteralPath $pending){foreach($file in @(Get-ChildItem -LiteralPath $pending -File -Recurse -Force)){$size+=$file.Length;$count++;if($count -gt 16){throw 'Bounded browser socket metadata file-count exceeded'}}}
 if($size -gt 8MB){throw 'Bounded browser socket metadata size exceeded'}
}

function Merge-V2TrialIdentities($A,$B){$out=@(@($A)+@($B)|Sort-Object PID,CreationTime -Unique);if($out.Count -gt 128){Throw-V2Ambiguous 'Trial identity history bound exceeded'};return $out}
