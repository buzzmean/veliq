#requires -Version 5.1
# Metadata only. Does not send game datagrams, change profiles or contact VPS.
Set-StrictMode -Version Latest
function Get-GameField($Object,[string]$Name,$Default=$null){
 if($null -eq $Object){return $Default};if($Object -is [Collections.IDictionary]){if($Object.Contains($Name)){return $Object[$Name]};return $Default};$p=$Object.PSObject.Properties[$Name];if($null -ne $p){return $p.Value};return $Default
}
function Get-GameUdpRows($Status){
 foreach($p in @(Get-GameField $Status 'profiles' @())){
  $engine=Get-GameField $p 'engine';foreach($flow in @(Get-GameField $engine 'flows' @())){
   $variant=Get-GameField $flow 'variant';$stage=[string](Get-GameField $flow 'stage' 'UNKNOWN')
   [pscustomobject]@{profile=(Get-GameField $p 'profile_id' '');pid=(Get-GameField $flow 'pid' 0);created=(Get-GameField $flow 'creation_time' 0);exe=(Get-GameField $flow 'exe' '');destination=(Get-GameField $flow 'destination' '');stage=$stage;selection=(Get-GameField $flow 'selection_reason' 'UNKNOWN');variant=$(if($stage -eq 'LOCAL_UDP'){Get-GameField $variant 'id' ''}else{''});fake_packets=(Get-GameField $flow 'fake_packets' 0);fake_bytes=(Get-GameField $flow 'fake_bytes' 0);outbound=(Get-GameField $flow 'outgoing_packets' 0);inbound=(Get-GameField $flow 'inbound_packets' 0);first_reply=$(if((Get-GameField $flow 'inbound_packets' 0) -gt 0){Get-GameField $flow 'first_reply' 'UNKNOWN'}else{'NOT_OBSERVED'});state=(Get-GameField $flow 'state' '');reason=(Get-GameField $flow 'reason' '')}
  }
 }
}
