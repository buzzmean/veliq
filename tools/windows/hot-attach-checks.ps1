Set-StrictMode -Version Latest
function Get-HotAttachRoots($Processes,[string[]]$Expected){
 $roots=@()
 foreach($name in $Expected){
  $matches=@($Processes|Where-Object{([string](Get-SimValue $_ 'Path' '')).Replace('\','/').Split('/')[-1] -ieq $name})
  if(!$matches.Count){throw "Start $name before enabling VELIQ"}
  $pids=@{};foreach($p in $matches){$pids[[string](Get-SimValue $p 'PID' 0)]=$true}
  $top=@($matches|Where-Object{!$pids.ContainsKey([string](Get-SimValue $_ 'ParentPID' 0))})
  if(!$top.Count){throw "Cannot identify existing root process: $name"}
  foreach($p in $top){if(!(Get-SimValue $p 'CreationTime' 0)){throw 'Missing native process birth'};$roots+=$p}
 }
 return $roots
}
function Assert-HotAttachRoots($Roots,$Current){
 foreach($root in $Roots){
  $same=@($Current|Where-Object{(Get-SimValue $_ 'PID' 0) -eq (Get-SimValue $root 'PID' -1) -and (Get-SimValue $_ 'CreationTime' 0) -eq (Get-SimValue $root 'CreationTime' -1) -and (Get-SimValue $_ 'Path' '') -ieq (Get-SimValue $root 'Path' 'missing')})
  if($same.Count -ne 1){throw 'An original application root exited/restarted or its identity is unavailable: no HOT ATTACH PASS'}
 }
}
function Get-HotAttachProof($State,$Hot,[uint64]$Epoch,[string[]]$Required){
 if((Get-SimValue $Hot 'state' '') -ne 'HOT_ATTACH_NETWORK_READY' -or [uint64](Get-SimValue $Hot 'epoch' 0) -ne $Epoch){throw 'HOT ATTACH reconciliation incomplete or generation changed'}
 $epochFlows=@{};$fresh=@{}
 foreach($entry in $State.Flows.GetEnumerator()){
  $h=Get-SimValue $entry.Value 'hot_attach'
  if([uint64](Get-SimValue $h 'epoch' 0) -eq $Epoch){
   $epochFlows[$entry.Key]=$entry.Value
   if((Get-SimValue $h 'state' '') -notin @('HOT_ATTACH_PREEXISTING','HOT_ATTACH_RESET_REQUESTED','HOT_ATTACH_RETIRED')){$fresh[$entry.Key]=$entry.Value}
  }
 }
 # All transition evidence must remain leak/failure-free. Application bytes and
 # YouTube transforms must also exist on fresh flows, not just on retired ones.
 $all=Get-SimProof @{Flows=$epochFlows;Lost=$State.Lost} $Required
 $proof=Get-SimProof @{Flows=$fresh;Lost=$State.Lost} $Required
 $proof|Add-Member -NotePropertyName hot_attach_epoch -NotePropertyValue $Epoch
 $proof|Add-Member -NotePropertyName transition_direct_leaks -NotePropertyValue $all.direct_leaks
 $proof.transport_evidence_pass=$proof.transport_evidence_pass -and $all.direct_leaks -eq 0 -and $all.protected_failures -eq 0 -and $all.media_transport_failures -eq 0
 return $proof
}
