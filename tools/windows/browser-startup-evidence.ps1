# Definitions only: bounded, secret-free interpretation of native ingress proof.
function Get-BrowserEvidenceField($Object,[string]$Name,$Default=$null){
 if($null -ne $Object){$p=$Object.PSObject.Properties[$Name];if($p){return $p.Value}};return $Default
}
function Test-BrowserNativeStartupEvidence($Profiles,$Native,[string[]]$Executables){
 $Executables=@($Executables|Where-Object {![string]::IsNullOrWhiteSpace($_)})
 $rows=@();$code='READY'
 if((Get-BrowserEvidenceField $Native 'state' '') -ne 'READY_NEW_CONNECTIONS'){$code='NATIVE_NOT_READY'}
 foreach($exe in $Executables){
  $matches=@($Profiles|Where-Object {@(Get-BrowserEvidenceField $_ 'executables' @()) -icontains $exe})
  if($matches.Count -ne 1){$code='BROWSER_PROFILE_MISSING_OR_AMBIGUOUS';continue}
  $p=$matches[0];$id=[string](Get-BrowserEvidenceField $p 'id' '')
  if((Get-BrowserEvidenceField $p 'mode' '') -ne 'AUTO' -or (Get-BrowserEvidenceField $p 'browser_transport' '') -ne 'native'){$code='BROWSER_NOT_NATIVE_AUTO';continue}
  $timings=@((Get-BrowserEvidenceField $Native 'profiles' @())|Where-Object {(Get-BrowserEvidenceField $_ 'profile_id' '') -eq $id})
  if($timings.Count -ne 1){$code='NATIVE_PROFILE_NOT_OBSERVED';continue}
  $m=Get-BrowserEvidenceField $timings[0] 'native_only'
  $exchanges=[long](Get-BrowserEvidenceField $m 'bidirectional_exchanges' 0)
  $accepted=[long](Get-BrowserEvidenceField $m 'accepted' 0);$opened=[long](Get-BrowserEvidenceField $m 'opened' 0)
  $tx=[long](Get-BrowserEvidenceField $m 'sent_bytes' 0);$rx=[long](Get-BrowserEvidenceField $m 'received_bytes' 0)
  $ms=[long](Get-BrowserEvidenceField $m 'enable_to_first_exchange_ms' -1)
  if($accepted -le 0 -or $opened -le 0 -or $exchanges -le 0 -or $tx -le 0 -or $rx -le 0 -or $ms -lt 0){$code='NATIVE_ONLY_EXCHANGE_NOT_OBSERVED'}
  $rows+=([pscustomobject]@{profile_id=$id;native_accepted=$accepted;native_opened=$opened;native_exchanges=$exchanges;tx=$tx;rx=$rx;enable_to_first_exchange_ms=$ms})
 }
 if($Executables.Count -eq 0){$code='RUNNING_BROWSER_REQUIRED'}
 [pscustomobject]@{ready=($code -eq 'READY');code=$code;scope='NATIVE_TRANSPORT_ONLY_NOT_PAGE_PASS';rows=$rows}
}
