[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$AppPath,
 [Parameter(Mandatory=$true)][ValidateSet('discord','youtube')][string]$Preset,
 [Parameter(Mandatory=$true)][string]$URL,
 [ValidateRange(5,30)][int]$TimeoutSeconds=15,
 [ValidateRange(10,90)][int]$StartupTimeoutSeconds=45,
 [string]$ReportDirectory=(Join-Path $PSScriptRoot '..\..\.e2e\strategy-v2'),
 [string]$TargetIPv4='',
 [switch]$NoQuicFallback,
 [switch]$Automatic,
 [string[]]$CandidateIds=@()
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'acceptance-checks.ps1')
. (Join-Path $PSScriptRoot 'strategy-v2-checks.ps1')
if(!$Automatic){Assert-Administrator}
$Preset=$Preset.ToLowerInvariant()
$AppPath=(Resolve-Path $AppPath).Path;$uri=[Uri]$URL
if($uri.Scheme -ne 'https' -or !$uri.IsAbsoluteUri -or $uri.UserInfo -or $uri.HostNameType -ne [UriHostNameType]::Dns){throw 'Public HTTPS hostname URL required; no credentials in URL'}
foreach($v in @($AppPath,$URL,$ReportDirectory)){if($v.Contains('"')){throw 'Quote in argument'}}
# Process discovery remains in the service. Never attach a debugger to the
# regular browser, or mix profiles/flows from pre-existing app instances.
$running=@(Invoke-ServiceIPC 'processes' @{executables=@($AppPath)})
if($running.Count -and !$Automatic){throw 'Close every process of this executable first; existing TCP routes cannot migrate'}
New-Item -ItemType Directory -Force $ReportDirectory|Out-Null;$ReportDirectory=(Resolve-Path $ReportDirectory).Path
$run=[Guid]::NewGuid().ToString('N');$profileID='!v2-'+$run
$original=Invoke-ServiceIPC 'status'
Write-Host 'Waiting for two equal network fingerprints from distinct service refresh cycles; Happ must be OFF.'
$script:trialRoot=$null
$network=Wait-V2StableNetwork
$network|ConvertTo-Json -Depth 8|Set-Content (Join-Path $ReportDirectory "$run-network-preflight.json") -Encoding UTF8
# Resolve once, then pin ONLY this hostname in the isolated test browser.
# All route trials must attempt the same IP:port with normal TLS/SNI validation.
if(!$TargetIPv4){$TargetIPv4=@([Net.Dns]::GetHostAddresses($uri.DnsSafeHost)|Where-Object{$_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork})[0].ToString()}
$TargetIPv4=Assert-VpsIPv4 $TargetIPv4
$targetDestination=$TargetIPv4+':'+$uri.Port
Assert-V2FrozenNetwork $network (Invoke-ServiceIPC 'local.network')
$catalog=@(Invoke-ServiceIPC 'local.presets');$definition=@($catalog|Where-Object{$_.id -eq $Preset})[0]
# URL must belong to the preset, not an unrestricted browser-wide success claim.
if(!@($definition.domains|Where-Object{$uri.DnsSafeHost -ieq $_ -or $uri.DnsSafeHost.EndsWith('.'+$_,[StringComparison]::OrdinalIgnoreCase)}).Count){throw 'URL is outside the selected preset'}
$install=Invoke-ServiceIPC 'local.preset.apply' @{application=$AppPath;preset=$Preset;quic_fallback=(!$NoQuicFallback)}
$candidates=@($install.config.user|Where-Object{$_.application -ieq $AppPath -and $_.preset -eq $Preset})
if(!$candidates.Count -or $candidates.Count -gt 7){throw 'Invalid finite candidate catalog'}
if($Automatic){$candidates=@($candidates|Where-Object{$_.id -in $CandidateIds})}
$script:socket=$null;$script:cdpID=0;$script:navID=-2;$script:navError='';$script:responses=@{};$script:finished=@{};$script:failed=@{}
function CDP([string]$Method,$Parameters,[switch]$NoWait){
 $script:cdpID++;$id=$script:cdpID;$buffer=[Text.Encoding]::UTF8.GetBytes((@{id=$id;method=$Method;params=$Parameters}|ConvertTo-Json -Depth 8 -Compress))
 $cts=[Threading.CancellationTokenSource]::new(5000)
 try {
  # VoidTaskResult must not escape into the PowerShell success pipeline: it
  # can turn a CDP reply (and Trial result) into an array under PS7.
  [void]$script:socket.SendAsync([ArraySegment[byte]]::new($buffer),[Net.WebSockets.WebSocketMessageType]::Text,$true,$cts.Token).GetAwaiter().GetResult()
  if($NoWait){return}
  while($true){
   $stream=[IO.MemoryStream]::new()
   try{do{$bytes=New-Object byte[] 16384;$message=$script:socket.ReceiveAsync([ArraySegment[byte]]::new($bytes),$cts.Token).GetAwaiter().GetResult();if($message.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close){throw 'CDP closed'};$stream.Write($bytes,0,$message.Count);if($stream.Length -gt 262144){throw 'Bounded CDP message exceeded'}}while(!$message.EndOfMessage);$r=[Text.Encoding]::UTF8.GetString($stream.ToArray())|ConvertFrom-Json}finally{$stream.Dispose()}
   $methodValue=Get-V2Value $r 'method' ''
   if($methodValue -eq 'Network.responseReceived' -and (Get-V2Value (Get-V2Value $r 'params') 'type' '') -eq 'Document'){
    $parameters=Get-V2Value $r 'params';$document=Get-V2Value $parameters 'response';$frameID=[string](Get-V2Value $parameters 'frameId' '');$requestID=[string](Get-V2Value $parameters 'requestId' '')
    if(!$document -or !$frameID -or !$requestID -or !(Get-V2Value $document 'url' '')){throw 'CDP Document response lacks frame/request/response identity'}
    $script:responses[$requestID]=@{response=$document;frame_id=$frameID}
   }
   if($methodValue -eq 'Network.loadingFinished'){$script:finished[[string](Get-V2Value (Get-V2Value $r 'params') 'requestId' '')]=$true}
   if($methodValue -eq 'Network.loadingFailed'){$script:failed[[string](Get-V2Value (Get-V2Value $r 'params') 'requestId' '')]=[string](Get-V2Value (Get-V2Value $r 'params') 'errorText' '')}
   if($script:responses.Count -gt 128 -or $script:finished.Count -gt 1024 -or $script:failed.Count -gt 128){throw 'Bounded CDP event table exceeded'}
   if((Get-V2Value $r 'id' -1) -eq $script:navID){
    if($null -ne $r.PSObject.Properties['error']){throw 'CDP navigation protocol rejected'}
    $script:navError=Get-V2Value (Get-V2Value $r 'result') 'errorText' ''
   }
   if((Get-V2Value $r 'id' -1) -eq $id){if($null -ne $r.PSObject.Properties['error']){throw "CDP $Method failed"};return (Get-V2Value $r 'result')}
  }
 }catch{
  $failure=[InvalidOperationException]::new(('CDP '+$Method+' failed: '+$_.Exception.Message),$_.Exception)
  $failure.Data['v2_failure_kind']='CDP/INSTRUMENTATION_FAILURE';throw $failure
 }finally{$cts.Dispose()}
}
function Trial([string]$Mode,[string]$Strategy,[int]$Index){
 $data=Join-Path ([IO.Path]::GetTempPath()) "neexitlag-v2-$run-$Index-profile";$browser=$null;$identities=@();$capture=$null;$flow=$null
 $script:trialRoot=$null
 $marker=$null;$identityFloor=0L;$socketLog=Join-Path $data '.private-sockets.json';$proofCapture=$null
 $result=@{report_schema_version=4;started_at=[DateTimeOffset]::UtcNow.ToString('o');mode=$Mode;strategy=$Strategy;success=$false;reason='';observation=$null;measurement=$null;failure_kind='';phase='profile_setup';exception_chain=@();diagnostic_errors=@()};$attempted=$false;$measurementValid=$false
 $candidate=@($candidates|Where-Object{$_.id -eq $Strategy}|Select-Object -First 1);$definitionForTrial=if($candidate.Count){$candidate[0]}else{$null}
 try {
  Assert-V2FrozenNetwork $network (Invoke-ServiceIPC 'local.network')
  $marker=Invoke-ServiceIPC 'capture.marker';$result.capture_marker=$marker
  if(!(Get-V2Value $marker 'ledger_id' '')){throw 'Capture marker unavailable; update service'}
  if(!$Automatic -and @(Invoke-ServiceIPC 'processes' @{executables=@($AppPath)}).Count){throw 'Previous trial or another browser process remains; close it before a fresh trial'}
  $p=@{id=$profileID;name='Finite real application strategy test';executables=@($AppPath);mode=$Mode;custom=$true;local_strategy_id=$Strategy}
  if($Mode -eq 'MANUAL'){$p.relay_id='VPS-01'}
  if(!$Automatic){[void](Invoke-ServiceIPC 'profile.set' $p)}
  $effective=Get-AcceptanceProfile (Invoke-ServiceIPC 'status') $AppPath
  if(!$Automatic -and ((Get-V2Value $effective 'id' '') -ne $profileID -or (Get-V2Value $effective 'mode' '') -ne $Mode)){throw 'Another application profile shadows tester decision'}
  $script:responses=@{};$script:finished=@{};$script:failed=@{};$script:cdpID=0
  # DIRECT/RELAY TCP controls use a diagnostic-only QUIC-off flag; DIRECT+
  # trials keep normal QUIC and use the app preset. No certificate bypass.
  $quicFlag=if($Mode -eq 'DIRECT_PLUS'){''}else{'--disable-quic'}
  $args="--log-net-log=`"$socketLog`" --net-log-capture-mode=Default --net-log-max-size-mb=4 $quicFlag --headless=new --no-first-run --no-default-browser-check --disable-background-networking --user-data-dir=`"$data`" --host-resolver-rules=`"MAP $($uri.DnsSafeHost) $TargetIPv4, EXCLUDE localhost`" --remote-debugging-address=127.0.0.1 --remote-debugging-port=0 about:blank"
  $result.phase='browser_startup'
  [void](New-Item -ItemType Directory -Path $data -ErrorAction Stop)
  $identityFloor=[DateTime]::UtcNow.ToFileTimeUtc()
  $browser=Start-Process -FilePath $AppPath -ArgumentList $args -PassThru;[void]$browser.Handle
  $portFile=Join-Path $data 'DevToolsActivePort'
  # Reuse the final-snapshot readiness wait: a partial port file or a listening
  # debugger with no page yet is startup progress, not a failed network trial.
  $ready=Wait-AcceptanceReadiness -TimeoutMS ($StartupTimeoutSeconds*1000) -PollMS 100 -GetSnapshot {
   if($browser.HasExited){throw 'App exited before isolated CDP became ready (unsupported launcher/Electron mode)'}
   $port=0;$pages=@()
   if(Test-Path $portFile){$lines=@(Get-Content $portFile);if($lines.Count -gt 0){[void][int]::TryParse([string]$lines[0],[ref]$port)}}
   if($port -ge 1 -and $port -le 65535){$pageList=Invoke-RestMethod "http://127.0.0.1:$port/json/list" -TimeoutSec 2;$pages=@($pageList|Where-Object{$_.type -eq 'page'})}
   [pscustomobject]@{ready=($pages.Count -gt 0);port=$port;pages=$pages;missing=@('isolated Chromium/Electron DevTools port and page')}
  } -Evaluate {param($s)$s}
  $port=$ready.port;$pages=@($ready.pages)
  if($Automatic){
   $roots=@(Get-V2TrialIdentities $AppPath $identityFloor|Where-Object{$_.PID -eq $browser.Id})
   if($roots.Count -ne 1){throw 'Exact isolated browser root identity unavailable'}
   $script:trialRoot=$roots[0]
   $p.trial_scope=@{pid=$script:trialRoot.PID;creation_time=$script:trialRoot.CreationTime;expires=[DateTimeOffset]::UtcNow.AddMinutes(10).ToString('o')}
   [void](Invoke-ServiceIPC 'profile.set' $p)
  }
  $ws=[Uri]$pages[0].webSocketDebuggerUrl
  if($ws.Host -notin @('127.0.0.1','localhost') -or $ws.Port -ne $port){throw 'CDP must remain on the isolated loopback port'}
  $result.phase='cdp_connect'
  $script:socket=[Net.WebSockets.ClientWebSocket]::new();$cts=[Threading.CancellationTokenSource]::new(5000)
  try{[void]$script:socket.ConnectAsync($ws,$cts.Token).GetAwaiter().GetResult()}finally{$cts.Dispose()}
  $result.phase='cdp_initialize'
  $version=CDP 'Browser.getVersion' @{};$product=[string](Get-V2Value $version 'product' '')
  if($product -notmatch '(?:Chrome|Chromium|Edg|HeadlessChrome)/(\d+)' -or [int]$Matches[1] -lt 117){throw 'Bounded socket metadata requires Chromium 117+; unsupported browser instrumentation'}
  [void](CDP 'Network.enable' @{});[void](CDP 'Network.setCacheDisabled' @{cacheDisabled=$true});[void](CDP 'Network.setBypassServiceWorker' @{bypass=$true})
  $tree=CDP 'Page.getFrameTree' @{};$mainFrame=Get-V2MainFrame $tree
  # Retain exact identities observed in this fresh trial even if the browser
  # or network child exits before the failure snapshot. No PID-only matching.
  try{$identities=@(Get-V2TrialIdentities $AppPath $identityFloor)}catch{$result.diagnostic_errors+=@{stage='pre-navigation identities';message=$_.Exception.Message}}
  $script:navError='';$script:navID=$script:cdpID+1
  $clock=[Diagnostics.Stopwatch]::StartNew()
  # A blocked connection may delay Page.navigate's response for a minute.
  # Send it asynchronously, keep pumping CDP, and apply our navigation deadline.
  $result.phase='navigation_send'
  CDP 'Page.navigate' @{url=$URL} -NoWait
  $result.phase='navigation_measurement'
  $response=$null
  while($true){
   # A harmless protocol round trip pumps Network events, not page code.
   [void](CDP 'Browser.getVersion' @{});Assert-V2SocketLogBound $socketLog
   if($script:navError){$measurementValid=$true;$result.failure_kind=if($script:navError -eq 'net::ERR_TIMED_OUT'){'NETWORK_TIMEOUT'}else{'BROWSER_NETWORK_FAILURE'};throw ('Navigation failed: '+$script:navError)}
   foreach($key in @($script:responses.Keys)){
    $entry=$script:responses[$key];$candidate=$entry.response;$u=[Uri]$candidate.url
    if($entry.frame_id -eq $mainFrame -and $u.DnsSafeHost -ieq $uri.DnsSafeHost -and $script:finished.ContainsKey($key) -and !$script:failed.ContainsKey($key)){$response=$candidate;$result.request_id=$key;$result.frame_id=$mainFrame;break}
   }
   if($null -ne $response){break}
   if($clock.Elapsed.TotalSeconds -ge $TimeoutSeconds){break}
   Start-Sleep -Milliseconds 100
  }
  if($null -eq $response){$measurementValid=$true;$result.failure_kind='NETWORK_TIMEOUT';throw 'No completed target HTTPS response before navigation deadline (CDP responsive)'}
  $measurementValid=$true
  $clock.Stop();$result.phase='response_evidence'
  $observation=Get-V2HTTPSObservation $response $clock.Elapsed.TotalMilliseconds
  $observation.hostname=$uri.DnsSafeHost.ToLowerInvariant().TrimEnd('.');$observation.completed=$true
  if($observation.from_cache -or $observation.from_service_worker){Throw-V2Ambiguous 'Completed response did not establish a fresh network socket'}
  $destination=[string]$observation.destination
  $result.observation=$observation
  $result.phase='socket_evidence'
  $currentIDs=@(Get-V2TrialIdentities $AppPath $identityFloor)
  $identities=@(Merge-V2TrialIdentities $identities $currentIDs)
  # Graceful close flushes Chromium's bounded metadata log. HTTP completion is
  # already established; closing the isolated browser never converts a failure
  # into a successful request. Forced/failed close yields UNKNOWN correlation.
  try{
   CDP 'Browser.close' @{} -NoWait
   if($browser.WaitForExit(5000)){[void]$browser.WaitForExit()}
  }catch{$result.diagnostic_errors+=@{stage='socket metadata flush';message='Isolated browser did not close cleanly; correlation may be unavailable'}}
  Assert-V2SocketLogBound $socketLog
  $observation.socket_binding=Read-V2SocketBinding $socketLog ([long]$observation.connection_id) $destination
  $result.phase='route_evidence'
  $proofCapture=Get-V2ProofCapture $marker $identities $destination $observation.hostname $observation.socket_binding
  $result.proof_capture=$proofCapture
  $route=if($Mode -eq 'MANUAL'){'RELAY'}else{$Mode}
  if($destination -ne $targetDestination){Throw-V2Ambiguous 'Browser ignored the isolated target-IP mapping'}
  $capture=$proofCapture
  $flow=Assert-V2BrowserEvidence $observation $capture $identities $AppPath $route $Strategy
  $result.success=$true;$result.observation=$observation
 }catch{$result.reason=$_.Exception.Message;$result.exception_chain=@(Get-V2ExceptionDetails $_.Exception);$kind=Get-V2ExceptionKind $_.Exception;if($kind){$result.failure_kind=$kind;$measurementValid=$false};if($result.phase -in @('response_evidence','socket_evidence','route_evidence') -and !$kind){if($result.observation -and $result.observation.success -and $result.observation.tls){$measurementValid=$false;$result.failure_kind='TARGET_FLOW_AMBIGUOUS'}else{$result.failure_kind='APPLICATION_RESPONSE_FAILURE'}};if(!$measurementValid -and !$result.failure_kind){$result.failure_kind='CDP/INSTRUMENTATION_FAILURE'}}
 finally {
  try{$finalIdentities=@(Get-V2TrialIdentities $AppPath $identityFloor);$identities=@(Merge-V2TrialIdentities $identities $finalIdentities)}catch{$result.diagnostic_errors+=@{stage='identities';message=$_.Exception.Message}}
  try{$capture=Get-V2ScopedCapture $marker $identities $targetDestination}catch{$result.diagnostic_errors+=@{stage='capture';message=$_.Exception.Message};if($result.success){$result.success=$false;$result.failure_kind='TARGET_FLOW_AMBIGUOUS';$result.reason='Final trial snapshot unavailable; exact lifetime proof cannot be completed';$measurementValid=$false}}
  $attempted=@(Get-V2Value $capture 'flows' @()|Where-Object{
   $f=$_;(Get-V2Value $f 'destination' '') -eq $targetDestination -and (Get-V2Value $f 'exe' '') -ieq $AppPath -and (Get-V2Value (Get-V2Value $f 'counters') 'captured_packets' 0) -gt 0 -and @($identities|Where-Object{$_.PID -eq $f.pid -and $_.CreationTime -eq $f.creation_time}).Count -gt 0
  }).Count -gt 0
  $result.capture=$capture;$result.identities=$identities
  $result.cleanup_errors=@(Stop-V2TrialBrowser $browser $data)
  try{Assert-V2FrozenNetwork $network (Invoke-ServiceIPC 'local.network')}catch{$result.network_changed=$true;$result.reason=$_.Exception.Message;$result.failure_kind='NETWORK_CHANGED';$result.success=$false;$measurementValid=$false}
  $result.diagnostic=Get-V2TrialDiagnostic $capture $identities $AppPath $targetDestination $Mode ([bool]$result.success) $measurementValid $result.failure_kind $definitionForTrial $uri.DnsSafeHost
  $result.classification=$result.diagnostic.classification;$result.classifications=$result.diagnostic.classifications


 }
 $elapsed=if($result.observation){[long]($result.observation.response_ms*1e6)}else{0L}
 $measurement=@{route_id=$(if($Mode -eq 'MANUAL'){'VPS-01'}else{'target'});available=[bool]$result.success;samples=$(if($result.success){1}else{0});rtt=$elapsed;jitter=0;loss=$(if($result.success){0.0}else{1.0});failure_rate=$(if($result.success){0.0}else{1.0});stability=$(if($result.success){1.0}else{0.0});observed_at=[DateTimeOffset]::UtcNow.ToString('o')}
 $result.instrumentation_failure=($result.failure_kind -eq 'CDP/INSTRUMENTATION_FAILURE')
 # A candidate that never transformed TCP was not measured as a strategy.
 $mayRecord=$attempted -and $measurementValid -and ($Mode -ne 'DIRECT_PLUS' -or $result.diagnostic.transform_status -eq 'APPLIED')
 $result.measurement_valid=[bool]$mayRecord
 $result.measurement=$(if($mayRecord){$measurement}else{$null})
 $result.measurement_recorded=$false
 Write-Host "$Mode $Strategy : $($result.success) $($result.reason)"
 Write-V2TrialDiagnostic $result.diagnostic
 if($mayRecord){
  $record=@{application=$AppPath;destination=$targetDestination;protocol='tcp';network=$network.fingerprint;strategy=$(if($Mode -eq 'MANUAL'){'RELAY'}elseif($Mode -eq 'DIRECT'){'DIRECT'}else{$Strategy});success=$result.success;measurement=$measurement}
  if(!$flow -and !$result.success -and $Mode -eq 'DIRECT_PLUS' -and !(Get-V2Value $capture 'truncated' $true) -and !(Get-V2Value $capture 'evidence_lost' $false)){
   $failedTarget=@(Get-V2Value $capture 'flows' @()|Where-Object{(Get-V2ObservedDomain $_) -eq $uri.DnsSafeHost.ToLowerInvariant().TrimEnd('.') -and (Get-V2Value $_ 'strategy' '') -eq $Strategy -and (Get-V2Value (Get-V2Value $_ 'counters') 'direct_plus_packets' 0) -gt 0})
   if($failedTarget.Count){$flow=$failedTarget[0]}
  }
  if($result.success -and $result.observation){$record.observed_hostname=$result.observation.hostname}
  if($flow){$record.pid=$flow.pid;$record.creation_time=$flow.creation_time;$record.capture_marker=$marker;$record.flow_id=$flow.flow_id;$record.source=$flow.source;$record.domain=Get-V2ObservedDomain $flow}
  try{[void](Invoke-ServiceIPC 'local.record' $record);$result.measurement_recorded=$true}catch{
   $result.record_error=$_.Exception.Message
   $result|ConvertTo-Json -Depth 18|Set-Content (Join-Path $ReportDirectory "$run-$Index-proof.json") -Encoding UTF8
   throw
  }
 }
 $result|ConvertTo-Json -Depth 18|Set-Content (Join-Path $ReportDirectory "$run-$Index-proof.json") -Encoding UTF8
 if(Get-V2Value $result 'network_changed' $false){throw $result.reason}
 return $result
}
$results=@()
try {
 if(!$Automatic){[void](Invoke-ServiceIPC 'optimize' @{enabled=$true})}elseif(!(Get-V2Value $original 'optimizing' $false)){throw 'Enable optimization before automatic measurement'}
 [void](Wait-AcceptanceReadiness -TimeoutMS 30000 -GetSnapshot {Invoke-ServiceIPC 'status'} -Evaluate {param($s)$missing=@();if(!$s.optimizing){$missing+='optimization'};if(!$s.backend.ready -or !$s.backend.capabilities.tcp){$missing+='TCP backend'};[pscustomobject]@{ready=(!$missing.Count);missing=$missing}})
 $results+=Trial 'DIRECT' '' 0
 if((Get-V2Value $results[0] 'instrumentation_failure' $false) -and (Get-V2Value $results[0] 'phase' '') -in @('profile_setup','browser_startup','cdp_connect','cdp_initialize')){throw ('Automatic app instrumentation unavailable; networking is NOT marked failed: '+$results[0].reason)}
 foreach($candidate in $candidates){$results+=Trial 'DIRECT_PLUS' $candidate.id $results.Count}
 $results+=Trial 'MANUAL' '' $results.Count
 # The list is finite; refresh control and a successful candidate near the
 # end if long failures made their original measurements stale.
 $results+=Trial 'DIRECT' '' $results.Count
 $working=@($results|Where-Object{(Get-V2Value $_ 'success' $false) -and (Get-V2Value $_ 'mode' '') -eq 'DIRECT_PLUS'})
 if($working.Count){$results+=Trial 'DIRECT_PLUS' (Get-V2Value $working[0] 'strategy' '') $results.Count}
 Assert-V2FrozenNetwork $network (Invoke-ServiceIPC 'local.network')
 $recommendation=Invoke-ServiceIPC 'local.recommend' @{application=$AppPath;destination=$targetDestination;protocol='tcp';network=$network.fingerprint}
 $verifiedStrategies=@($results|Where-Object{Get-V2Value $_ 'success' $false}|ForEach-Object{if((Get-V2Value $_ 'mode' '') -eq 'MANUAL'){'RELAY'}elseif((Get-V2Value $_ 'mode' '') -eq 'DIRECT'){'DIRECT'}else{Get-V2Value $_ 'strategy' ''}})
 $winner=Get-V2Value $recommendation 'recommended' ''
 $winnerVerified=($winner -in $verifiedStrategies)
 $summary=@{results=$results;recommendation=$(if($winnerVerified){$recommendation}else{$null});cached_recommendation=$recommendation;recommendation_verified_in_this_run=$winnerVerified;verified_strategies=$verifiedStrategies;baseline_note='Prior DIRECT=True run with Happ ON is excluded from ISP baseline and current-run evidence';target=$targetDestination;dns_mode="isolated browser hostname mapping; system DNS unchanged";network=$network.fingerprint;note='HTTP/TLS navigation evidence only. Discord login/messages and YouTube video playback require real user tests; no cross-exe learning.'}
 $summary|ConvertTo-Json -Depth 20|Set-Content (Join-Path $ReportDirectory "$run-summary.json") -Encoding UTF8
 if(!@($results|Where-Object{Get-V2Value $_ 'success' $false}).Count){throw 'No verified working route. Inspect proof files; no PASS or learned success was invented.'}
 if(!$winnerVerified){Write-Warning 'Cached recommendation has no successful proof in this run; do not treat it as a verified route or ISP baseline'}
 Write-Host "Cached recommendation: $winner; verified in this run: $winnerVerified. Finite trials complete: $ReportDirectory. Successful evidence expires; AUTO requires fresh per-destination measurements."
}catch{
 $failure=$_.Exception.Message
 try{@{error=$failure;results=$results;status=(Invoke-ServiceIPC 'status')}|ConvertTo-Json -Depth 18|Set-Content (Join-Path $ReportDirectory "$run-FAIL.json") -Encoding UTF8}catch{}
 throw
}finally{
 try{[void](Invoke-ServiceIPC 'profile.delete' @{id=$profileID})}catch{Write-Warning $_}
 if(!$Automatic){try{[void](Invoke-ServiceIPC 'optimize' @{enabled=[bool](Get-V2Value $original 'optimizing' $false)})}catch{Write-Warning $_}}
}
