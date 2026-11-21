# Pure safe-field projection. No IPC, browser, network or registry operations.
Set-StrictMode -Version Latest
function Get-BrowserDNSField($o,[string]$name,$default=$null){
 if($null -ne $o){$p=$o.PSObject.Properties[$name];if($null -ne $p){return $p.Value}};return $default
}
function Get-BrowserDNSTransportObservation($record){
 $domain=[string](Get-BrowserDNSField $record 'domain' '')
 $policy=Get-BrowserDNSField $record 'policy';$owner=Get-BrowserDNSField $record 'owner'
 $tls=Get-BrowserDNSField (Get-BrowserDNSField $record 'tls_wire') 'origin'
 $action=[string](Get-BrowserDNSField $policy 'action' '')
 $group='OTHER'
 if($domain -match '(^|\.)googlevideo\.com$'){$group='GOOGLEVIDEO'}
 elseif($domain -match '(^|\.)vk\.(ru|com)$'){$group='VK'}
 elseif($domain -match '(^|\.)(youtube\.com|ytimg\.com|ggpht\.com|web\.telegram\.org|telegram\.org|t\.me|claude\.ai|anthropic\.com|claudeusercontent\.com|claude\.com|chatgpt\.com|openai\.com|oaistatic\.com|oaiusercontent\.com)$'){$group='PROTECTED'}
 elseif($domain -match '(^|\.)(youtube-nocookie\.com|youtubei\.googleapis\.com|youtube\.googleapis\.com|youtubeembeddedplayer\.googleapis\.com|youtubekids\.com|youtu\.be|yt3\.googleusercontent\.com|wide-youtube\.l\.google\.com|youtube-ui\.l\.google\.com|ytimg\.l\.google\.com|jnn-pa\.googleapis\.com)$'){$group='PROTECTED'}
 elseif($domain -match '(^|\.)google\.com$'){$group='GOOGLE'}
 elseif($domain -eq '<opaque>' -or !$domain){$group='OPAQUE'}
 $tx=[long](Get-BrowserDNSField $record 'sent_bytes' 0);$rx=[long](Get-BrowserDNSField $record 'received_bytes' 0)
 $hello=[bool](Get-BrowserDNSField $tls 'server_hello_complete' $false)
 $native=(Get-BrowserDNSField $record 'ingress' '') -eq 'NATIVE_TCP'
 $failure=[string](Get-BrowserDNSField $record 'failure_reason' '')
 [pscustomobject]@{
  id=[long](Get-BrowserDNSField $record 'id' 0);profile_id=[string](Get-BrowserDNSField $owner 'profile_id' '')
  domain=$domain;destination=[string](Get-BrowserDNSField $record 'destination' '');group=$group;action=$action
  source=[string](Get-BrowserDNSField $policy 'source' '');relay=[string](Get-BrowserDNSField $policy 'relay_id' '')
  tx=$tx;rx=$rx;server_hello_complete=$hello;native=$native;failure=$failure
  exchange=($native -and $hello -and !$failure -and $tx -gt 0 -and $rx -gt 256)
  # A plan is not Internet/page/video proof. Catch even an opened protected DIRECT.
  protected_direct=($group -in @('GOOGLEVIDEO','PROTECTED') -and $action -in @('DIRECT','DIRECT_PLUS') -and $tx -gt 0)
 }
}
function Get-BrowserDNSTransportVerdict($observations,[switch]$RequireGoogleDirect){
 $rows=@($observations)
 if(@($rows|Where-Object {$_.protected_direct}).Count){return 'PROTECTED_DIRECT_OBSERVED'}
 $video=@($rows|Where-Object {$_.group -eq 'GOOGLEVIDEO' -and $_.exchange -and $_.action -eq 'RELAY_REQUIRED' -and $_.relay}).Count -gt 0
 $vk=@($rows|Where-Object {$_.group -eq 'VK' -and $_.exchange -and $_.action -eq 'DIRECT'}).Count -gt 0
 $google=@($rows|Where-Object {$_.group -eq 'GOOGLE' -and $_.exchange -and $_.action -eq 'DIRECT'}).Count -gt 0
 if($RequireGoogleDirect -and $video -and $vk -and $google){
  foreach($profile in @($rows|Where-Object {$_.profile_id}|ForEach-Object {$_.profile_id}|Select-Object -Unique)){
   $same=@($rows|Where-Object {$_.profile_id -eq $profile -and $_.exchange})
   $v=@($same|Where-Object {$_.group -eq 'GOOGLEVIDEO' -and $_.action -eq 'RELAY_REQUIRED' -and $_.relay}).Count -gt 0
   $k=@($same|Where-Object {$_.group -eq 'VK' -and $_.action -eq 'DIRECT'}).Count -gt 0
   $g=@($same|Where-Object {$_.group -eq 'GOOGLE' -and $_.action -eq 'DIRECT'}).Count -gt 0
   if($v -and $k -and $g){return 'TRANSPORT_ROUTES_OBSERVED_PAGE_NOT_VERIFIED'}
  }
  return 'SAME_BROWSER_PROFILE_ROUTES_NOT_OBSERVED'
 }
 if($video -and $vk -and !$RequireGoogleDirect){return 'TRANSPORT_ROUTES_OBSERVED_PAGE_NOT_VERIFIED'}
 if($video -and $vk -and $RequireGoogleDirect -and !$google){return 'GOOGLE_DIRECT_EXCHANGE_NOT_OBSERVED'}
 if(!$video){return 'GOOGLEVIDEO_HOSTNAME_EXCHANGE_NOT_OBSERVED'}
 return 'VK_DIRECT_EXCHANGE_NOT_OBSERVED'
}

function Get-BrowserDNSDeltaObservation($record,[object[]]$InitialBytes){
 $o=Get-BrowserDNSTransportObservation $record
 if($null -ne $InitialBytes){
  if($InitialBytes.Count -ne 2){throw 'NATIVE_FLOW_BASELINE_INVALID'}
  $tx=$o.tx-[long]$InitialBytes[0];$rx=$o.rx-[long]$InitialBytes[1]
  if($tx -lt 0 -or $rx -lt 0){throw 'NATIVE_FLOW_COUNTERS_RESET'}
  $o.tx=$tx;$o.rx=$rx;$o.protected_direct=$o.protected_direct -and $tx -gt 0
  $o.exchange=$o.exchange -and $tx -gt 0 -and $rx -gt 256
 }
 return $o
}
function Get-BrowserDNSVideoAdmissionVerdict($before,$after,[switch]$RequireDedicated){
 $a=Get-BrowserDNSField $before 'googlevideo_admission_failures'
 $b=Get-BrowserDNSField $after 'googlevideo_admission_failures'
 if($null -eq $a -or $null -eq $b){return 'VIDEO_ADMISSION_COUNTERS_UNINSTRUMENTED'}
 if([long]$b -lt [long]$a){return 'VIDEO_ADMISSION_COUNTERS_RESET'}
 if($RequireDedicated -and (Get-BrowserDNSField $after 'admission_scope' '') -notlike 'DEDICATED_*'){return 'VIDEO_ADMISSION_OLD_SHARED_POOL'}
 if([long]$b -gt [long]$a){return 'VIDEO_ADMISSION_FAILURES_INCREASED'}
 return 'VIDEO_ADMISSION_STABLE'
}
