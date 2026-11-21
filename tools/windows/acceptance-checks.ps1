# Pure checks shared by real acceptance and regression fixtures (no network simulation).
function Assert-AcceptanceRoute($Data,$Evidence,[string]$Exe,[string]$Target,[string]$Route,[string]$RelayEgress) {
 if($Evidence.truncated){throw 'Capture evidence truncated; cannot prove exclusive routing'}
 $flows=@($Evidence.flows|Where-Object {$_.pid -eq $Data.pid -and $_.creation_time -eq $Data.creation_time -and $_.exe -ieq $Exe -and $_.destination -eq $Target})
 if(!$flows.Count){throw "${Route}: no capture evidence for this PID, creation time, executable and destination"}
 $counts=@{}
 foreach($key in @('captured_packets','relayed_packets','direct_packets','relay_reply_packets')) {
  $counts[$key]=[double](($flows|ForEach-Object {$_.counters.$key}|Measure-Object -Sum).Sum)
 }
 if($counts.captured_packets -lt $Data.Sent){throw "$Route capture count is below measured sent count"}
 if(@($Data.observed_sources).Count -ne 1){throw "${Route}: expected exactly one authenticated observed source"}
 foreach($flow in $flows) {
  if($flow.selected_route -ne $Route){throw "${Route}: selected_route mismatch"}
  $relay=$flow.PSObject.Properties['relay_id']
  if($Route -eq 'RELAY' -and ($null -eq $relay -or $relay.Value -ne 'VPS-01')){throw 'RELAY: relay_id mismatch'}
  if($Route -eq 'DIRECT' -and $null -ne $relay -and $relay.Value){throw 'DIRECT: unexpected relay_id'}
 }
 if($Route -eq 'RELAY') {
  if($Data.observed_sources[0] -ne $RelayEgress -or $counts.relayed_packets -lt $Data.Sent -or $counts.direct_packets -ne 0 -or $counts.relay_reply_packets -lt $Data.Received){throw 'RELAY: source/counter exclusivity or reply reinjection proof failed'}
 } else {
  if($Data.observed_sources[0] -eq $RelayEgress -or $counts.direct_packets -lt $Data.Sent -or $counts.relayed_packets -ne 0 -or $counts.relay_reply_packets -ne 0){throw 'DIRECT: source/counter exclusivity proof failed'}
 }
 return [pscustomobject]$counts
}
function Assert-AcceptanceLoss($Data) {
 if($Data.Sent -le 0 -or $Data.Received -le 0 -or $Data.Received -gt $Data.Sent){throw 'Invalid sent/received counters or zero authenticated replies'}
 $loss=1.0-[double]$Data.Received/[double]$Data.Sent
 if([Math]::Abs($Data.Loss-$loss) -gt 0.000001 -or ($Data.Sent-$Data.Received)*10 -gt $Data.Sent){throw 'Echo loss exceeds the acceptance limit (10%) or report is inconsistent'}
}
function Get-AcceptanceProfile($Snapshot,[string]$Exe) {
 # Registry uses custom first, then ordinal ID; do not silently trust profile.set.
 $matches=@((Get-AcceptanceValue $Snapshot 'profiles' @())|Where-Object {
  $p=$_;@((Get-AcceptanceValue $p 'executables' @())|Where-Object { $null -ne $_ -and ($_.Replace('\','/') -ieq $Exe.Replace('\','/') -or $_ -ieq [IO.Path]::GetFileName($Exe)) }).Count -gt 0
 })
 $winner=$null
 foreach($p in $matches){if($null -eq $winner -or ($p.custom -and !$winner.custom) -or ($p.custom -eq $winner.custom -and [string]::CompareOrdinal($p.id,$winner.id) -lt 0)){$winner=$p}}
 return $winner
}
function Get-AcceptanceValue($Object,[string]$Name,$Default=$null) {
 if($null -eq $Object){return $Default}
 if($Object -is [Collections.IDictionary]){if($Object.Contains($Name)){return $Object[$Name]};return $Default}
 $property=$Object.PSObject.Properties[$Name]
 if($null -eq $property){return $Default}
 return $property.Value
}
function Get-AcceptanceReadiness($Snapshot,[string]$Game,[string]$Control,[string]$SelectedId,[string]$ControlId,[ValidateSet('MANUAL','AUTO')][string]$Mode) {
 $missing=[Collections.Generic.List[string]]::new()
 if((Get-AcceptanceValue $Snapshot 'connected' $false) -ne $true){$missing.Add('service connected')}
 if((Get-AcceptanceValue $Snapshot 'optimizing' $false) -ne $true){$missing.Add('optimizing')}
 if((Get-AcceptanceValue (Get-AcceptanceValue $Snapshot 'backend') 'ready' $false) -ne $true){$missing.Add('backend')}
 $selected=Get-AcceptanceProfile $Snapshot $Game;$direct=Get-AcceptanceProfile $Snapshot $Control
 if($null -eq $selected -or $selected.id -ne $SelectedId -or $selected.mode -ne $Mode -or ($Mode -eq 'MANUAL' -and (Get-AcceptanceValue $selected 'relay_id' '') -ne 'VPS-01')){$missing.Add('selected profile: temporary profile is not effective')}
 if($null -eq $direct -or $direct.id -ne $ControlId -or $direct.mode -ne 'DIRECT'){$missing.Add('control profile: temporary DIRECT profile is not effective')}
 $transport=Get-AcceptanceValue $Snapshot 'relay_transport'
 if((Get-AcceptanceValue $transport 'relay_id' '') -ne 'VPS-01' -or (Get-AcceptanceValue $transport 'connected' $false) -ne $true -or (Get-AcceptanceValue $transport 'flow_open' $false) -ne $true){
  $reason=Get-AcceptanceValue $transport 'reason' 'fresh session/open evidence unavailable; upgrade service for acceptance.readiness'
  $detail=Get-AcceptanceValue $transport 'open_error' ''
  $missing.Add("relay transport: $reason $detail")
 }
 if($Mode -eq 'AUTO') {
  if((Get-AcceptanceValue (Get-AcceptanceValue $Snapshot 'settings') 'automatic' $false) -ne $true){$missing.Add('AUTO eligibility: automatic routing disabled')}
  $route=@((Get-AcceptanceValue $Snapshot 'routes' @())|Where-Object{$null -ne $_ -and (Get-AcceptanceValue $_ 'id' '') -eq 'VPS-01'})|Select-Object -First 1
  $quality=Get-AcceptanceValue $route 'quality'
  $health=Get-AcceptanceValue $quality 'health' 'unavailable'
  $samples=Get-AcceptanceValue $quality 'network_sample_count' 0
  $rounds=Get-AcceptanceValue $quality 'round_count' 0
  if($health -ne 'healthy' -or $samples -lt 20 -or $rounds -lt 3){$missing.Add("quality: health=$health network_samples=$samples rounds=$rounds")}
  $score=Get-AcceptanceValue $route 'score'
  if((Get-AcceptanceValue $route 'status' '') -ne 'healthy' -or $null -eq $score -or [double]::IsNaN([double]$score) -or [double]::IsInfinity([double]$score)){$missing.Add('AUTO eligibility: relay absent from eligible scoring')}
  $primary=Get-AcceptanceValue $Snapshot 'primary' 'unavailable'
  if($primary -ne 'VPS-01'){$missing.Add("AUTO eligibility: natural optimizer primary=$primary; VPS-01 not selected (NOT EXERCISED)")}
 }
 return [pscustomobject]@{ready=($missing.Count -eq 0);missing=$missing.ToArray()}
}
function Test-AcceptanceReady($Snapshot,[string]$Game,[string]$Control,[string]$SelectedId,[string]$ControlId,[string]$Mode) {
 return (Get-AcceptanceReadiness $Snapshot $Game $Control $SelectedId $ControlId $Mode).ready
}
# A final fresh check is always made at/after the deadline. A bounded IPC check
# may complete after that deadline; its actual evidence decides readiness.
function Wait-AcceptanceReadiness([scriptblock]$GetSnapshot,[scriptblock]$Evaluate,[int]$TimeoutMS=60000,[int]$PollMS=500,[scriptblock]$Now=$null,[scriptblock]$Delay=$null) {
 if($TimeoutMS -lt 0 -or $PollMS -lt 1){throw 'Invalid readiness wait budget'}
 if($null -eq $Now){$watch=[Diagnostics.Stopwatch]::StartNew();$Now={return $watch.Elapsed.TotalMilliseconds}.GetNewClosure()}
 if($null -eq $Delay){$Delay={param($ms) Start-Sleep -Milliseconds $ms}}
 $deadline=(& $Now)+$TimeoutMS;$finalCheck=$false;$missing=@('service IPC: no snapshot yet')
 while($true) {
  if((& $Now) -ge $deadline){$finalCheck=$true}
  try {
   $snapshot=& $GetSnapshot
   $state=& $Evaluate $snapshot
   if($state.ready){return $snapshot}
   $missing=@($state.missing)
  }catch{$missing=@("service IPC/readiness evidence: $($_.Exception.Message)")}
  if($finalCheck){throw "Acceptance readiness timeout: $($missing -join '; ')"}
  $remaining=$deadline-(& $Now)
  if($remaining -le 0){$finalCheck=$true;continue}
  & $Delay ([int][Math]::Min($PollMS,[Math]::Ceiling($remaining)))
 }
}
function Assert-AcceptanceOverlap($Selected,$Direct) {
 $startA=[DateTimeOffset]::Parse($Selected.measurement_started.ToString());$endA=[DateTimeOffset]::Parse($Selected.measurement_finished.ToString())
 $startB=[DateTimeOffset]::Parse($Direct.measurement_started.ToString());$endB=[DateTimeOffset]::Parse($Direct.measurement_finished.ToString())
 if($startA -ge $endA -or $startB -ge $endB -or $startA -ge $endB -or $startB -ge $endA){throw 'Measured packet-send windows did not overlap or timestamps are invalid'}
}
