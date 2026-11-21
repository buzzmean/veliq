[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$ChromePath,
 [Parameter(Mandatory=$true)][string]$URL,
 [Parameter(Mandatory=$true)][string]$TokenFile,
 [string]$HttpURL='',
 [string]$RelayEgress='2.56.177.4',
 [ValidateSet('TCP','QUIC')][string]$Mode='TCP',
 [string]$ReportDirectory=(Join-Path $PSScriptRoot '..\..\.e2e\browser')
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'acceptance-checks.ps1')
Assert-Administrator
$ChromePath=(Resolve-Path $ChromePath).Path
foreach($argument in @($ChromePath,$URL,$ReportDirectory)){if($argument.Contains('"')){throw 'Quote in argument'}}
$uri=[Uri]$URL;if($uri.Scheme -ne 'https' -or $uri.AbsolutePath -ne '/'){throw 'Trusted HTTPS destination URL required'}
if($Mode -eq 'TCP'){if([string]::IsNullOrWhiteSpace($HttpURL)){throw 'TCP browser acceptance requires -HttpURL as well as trusted HTTPS -URL'};$httpUri=[Uri]$HttpURL;if($httpUri.Scheme -ne 'http' -or $httpUri.AbsolutePath -ne '/' -or $httpUri.Host -ne $uri.Host){throw 'Controlled HTTP URL must use the same host and root path'}}
# Separate, temporary browser data. Never attach to a user's regular browser.
if(@(Get-Process -ErrorAction SilentlyContinue|Where-Object{try{$_.Path -ieq $ChromePath}catch{$false}}).Count -gt 0){throw 'Close this browser before acceptance: the executable profile applies to all its processes'}
New-Item -ItemType Directory -Force $ReportDirectory|Out-Null;$ReportDirectory=(Resolve-Path $ReportDirectory).Path
$run=[Guid]::NewGuid().ToString('N');$data=Join-Path $ReportDirectory "$run-profile";$netlog=Join-Path $ReportDirectory "$run-netlog.json";$profileId='!browser-'+$run
$script:responseRequests=@{}
$client=$null;$socket=$null;$original=Invoke-ServiceIPC 'status';$proof=@{mode=$Mode;url=$URL;status='FAIL';note='TCP/QUIC modes are separate; DNS netlog is evidence, not system DNS routing'}
function Sign-WebMessage([string]$Key,[string]$Message){$h=[Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($Key));try{return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Message)))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()}}
function Assert-BrowserObservation($Observation,[string]$Key,[string]$Nonce,[bool]$TLSRequired,[string]$ExpectedSource){
 if($null -eq $Observation){throw 'Browser produced no destination observation'}
 foreach($name in @('nonce','source','protocol','tls','proof')){if($null -eq $Observation.PSObject.Properties[$name]){throw "Destination observation missing $name"}}
 if($Observation.nonce -cne $Nonce -or $Observation.source -ne $ExpectedSource -or $Observation.tls -isnot [bool] -or $Observation.tls -ne $TLSRequired){throw 'Browser source/TLS/nonce proof failed'}
 $tlsText=if($TLSRequired){'true'}else{'false'}
 $expected=Sign-WebMessage $Key ("response`n"+$Observation.nonce+"`n"+$Observation.source+"`n"+$Observation.protocol+"`n"+$tlsText)
 if($Observation.proof -cne $expected){throw 'Invalid destination HMAC proof'}
}
function Navigate-Observation([string]$BaseURL,[bool]$TLSRequired){
 $nonce=[Guid]::NewGuid().ToString('N');$target=([Uri]($BaseURL.TrimEnd('/')+'/observe?nonce='+$nonce)).AbsoluteUri
 $signature=Sign-WebMessage $token ("request`nGET`n/observe`n"+$nonce)
 [void](CDP 'Network.setExtraHTTPHeaders' @{headers=@{'X-Neexitlag-Proof'=$signature}})
 [void](CDP 'Page.navigate' @{url=$target})
 $observation=$null;$deadline=[DateTime]::UtcNow.AddSeconds(15)
 while([DateTime]::UtcNow -lt $deadline){
  Start-Sleep -Milliseconds 300
  # Pump CDP events and read the actual navigation response body. Chromium's
  # JSON viewer DOM is not a stable interface and may add renderer UI text.
  [void](CDP 'Runtime.evaluate' @{expression='0';returnByValue=$true})
  if($script:responseRequests.ContainsKey($target)){
   try{$body=CDP 'Network.getResponseBody' @{requestId=$script:responseRequests[$target]};$text=[string]$body.body;if($body.base64Encoded){$text=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($text))};$candidate=$text|ConvertFrom-Json;if($candidate.nonce -eq $nonce){$observation=$candidate;break}}catch{}
  }
 }
 Assert-BrowserObservation $observation $token $nonce $TLSRequired $RelayEgress
 return $observation
}
function CDP([string]$Method,$Params){
 $script:requestID++;$id=$script:requestID
 $bytes=[Text.Encoding]::UTF8.GetBytes((@{id=$id;method=$Method;params=$Params}|ConvertTo-Json -Depth 12 -Compress))
 $cts=[Threading.CancellationTokenSource]::new(10000)
 try{
  $socket.SendAsync([ArraySegment[byte]]::new($bytes),[Net.WebSockets.WebSocketMessageType]::Text,$true,$cts.Token).GetAwaiter().GetResult()
  while($true){$stream=[IO.MemoryStream]::new();try{do{$buffer=New-Object byte[] 16384;$message=$socket.ReceiveAsync([ArraySegment[byte]]::new($buffer),$cts.Token).GetAwaiter().GetResult();if($message.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close){throw 'CDP closed'};$stream.Write($buffer,0,$message.Count);if($stream.Length -gt 1048576){throw 'CDP response too large'}}while(!$message.EndOfMessage);$response=[Text.Encoding]::UTF8.GetString($stream.ToArray())|ConvertFrom-Json}finally{$stream.Dispose()}
   if($null -ne $response.PSObject.Properties['method'] -and $response.method -eq 'Network.responseReceived'){
    if($script:responseRequests.Count -ge 128){$script:responseRequests.Remove(@($script:responseRequests.Keys)[0])}
    $script:responseRequests[[string]$response.params.response.url]=[string]$response.params.requestId
   }
   if($null -ne $response.PSObject.Properties['id'] -and $response.id -eq $id){if($null -ne $response.PSObject.Properties['error']){throw "CDP $Method failed"};return $response.result}
  }
 }finally{$cts.Dispose()}
}
try {
 [void](Invoke-ServiceIPC 'profile.set' @{id=$profileId;name='Browser acceptance';executables=@($ChromePath);mode='MANUAL';relay_id='VPS-01';custom=$true})
 [void](Invoke-ServiceIPC 'optimize' @{enabled=$true})
 [void](Wait-AcceptanceReadiness -TimeoutMS 30000 -GetSnapshot {Invoke-ServiceIPC 'acceptance.readiness' @{relay_id='VPS-01'}} -Evaluate {param($s)
  $missing=@();if(!$s.connected -or !$s.optimizing -or !$s.backend.ready -or !$s.backend.capabilities.tcp){$missing+='TCP backend'}
  $transport=$s.PSObject.Properties['relay_transport'];if($null -eq $transport -or !$transport.Value.connected -or !$transport.Value.flow_open){$missing+='authenticated relay session/open ACK'}
  if(@($s.profiles|Where-Object{$_.id -eq $profileId -and $_.mode -eq 'MANUAL' -and $_.relay_id -eq 'VPS-01' -and $_.executables -contains $ChromePath}).Count -ne 1){$missing+='browser profile configuration'}
  return [pscustomobject]@{ready=($missing.Count -eq 0);missing=$missing}
 })
 $quicFlag=if($Mode -eq 'TCP'){'--disable-quic'}else{'--enable-quic'}
 $arguments="--headless=new --no-first-run --no-default-browser-check --disable-background-networking --user-data-dir=`"$data`" --remote-debugging-address=127.0.0.1 --remote-debugging-port=0 --log-net-log=`"$netlog`" $quicFlag about:blank"
 $client=Start-Process -FilePath $ChromePath -ArgumentList $arguments -PassThru
 $portFile=Join-Path $data 'DevToolsActivePort';$deadline=[DateTime]::UtcNow.AddSeconds(20)
 while(!(Test-Path $portFile)){if([DateTime]::UtcNow -ge $deadline){throw 'Browser startup timeout'};Start-Sleep -Milliseconds 200}
 $port=[int](Get-Content $portFile)[0]
 $pages=Invoke-RestMethod "http://127.0.0.1:$port/json/list";$page=@($pages|Where-Object{$_.type -eq 'page'})[0]
 $socket=[Net.WebSockets.ClientWebSocket]::new();$cts=[Threading.CancellationTokenSource]::new(5000);try{$socket.ConnectAsync([Uri]$page.webSocketDebuggerUrl,$cts.Token).GetAwaiter().GetResult()}finally{$cts.Dispose()}
 $script:requestID=0
 [void](CDP 'Network.enable' @{})
 $token=[IO.File]::ReadAllText((Resolve-Path $TokenFile).Path).Trim()
 $observations=@()
 # First navigation discovers Alt-Svc; repeated navigations let Chromium choose
 # QUIC naturally. QUIC mode never forces a winner or assumes UDP443 means H3.
 if($Mode -eq 'TCP'){$proof.http=Navigate-Observation $HttpURL $false}
 for($i=0;$i -lt 6;$i++){$observations+=Navigate-Observation $URL $true}
 if($Mode -eq 'TCP'){
  if(@($observations|Where-Object{$_.protocol -eq 'HTTP/2.0'}).Count -eq 0){throw 'Browser HTTP/2 not negotiated'}
  $nonce=[Guid]::NewGuid().ToString('N');$ws=[UriBuilder]$URL;$ws.Scheme='wss';$ws.Path='/ws';$ws.Query='nonce='+$nonce
  $signature=Sign-WebMessage $token ("request`nGET`n/ws`n"+$nonce)
  [void](CDP 'Network.setExtraHTTPHeaders' @{headers=@{'X-Neexitlag-Proof'=$signature}})
  $wsJSON=$ws.Uri.AbsoluteUri|ConvertTo-Json -Compress
  $expression='new Promise(resolve=>{const ws=new WebSocket('+ $wsJSON +');const timer=setTimeout(()=>{ws.close();resolve({error:"WebSocket timeout"})},7000);ws.onmessage=e=>{clearTimeout(timer);ws.close();try{resolve(JSON.parse(e.data))}catch{resolve({error:"Invalid WebSocket JSON"})}};ws.onerror=()=>{clearTimeout(timer);resolve({error:"WebSocket error"})}})'
  $r=CDP 'Runtime.evaluate' @{expression=$expression;returnByValue=$true;awaitPromise=$true}
  if($null -eq $r.result.PSObject.Properties['value']){throw 'No browser WebSocket result'}
  $proof.websocket=$r.result.value
  Assert-BrowserObservation $proof.websocket $token $nonce $true $RelayEgress
 }
 $capture=Invoke-ServiceIPC 'capture.diagnostics'
 $processes=@(Get-Process|Where-Object{try{$_.Path -ieq $ChromePath}catch{$false}}|ForEach-Object{[pscustomobject]@{pid=$_.Id;exe=$_.Path;creation_time=[uint64]$_.StartTime.ToUniversalTime().ToFileTimeUtc()}})
 $pids=@($processes|ForEach-Object{$_.pid})
 $protocol=if($Mode -eq 'TCP'){'tcp'}else{'udp'}
 $expectedDestinations=@();foreach($ip in [Net.Dns]::GetHostAddresses($uri.Host)|Where-Object{$_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork}){$expectedDestinations+=($ip.ToString()+':'+$uri.Port)}
 if($Mode -eq 'TCP'){foreach($ip in [Net.Dns]::GetHostAddresses($httpUri.Host)|Where-Object{$_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork}){$expectedDestinations+=($ip.ToString()+':'+$httpUri.Port)}}
 $leaks=@($capture.flows|Where-Object{$pids -contains $_.pid -and $_.exe -ieq $ChromePath -and $expectedDestinations -contains $_.destination -and $_.counters.direct_packets -gt 0})
 if($leaks.Count -gt 0){throw 'Controlled browser destination has DIRECT traffic'}
 $flows=@($capture.flows|Where-Object{$pids -contains $_.pid -and $_.exe -ieq $ChromePath -and $_.protocol -eq $protocol -and $expectedDestinations -contains $_.destination -and $_.selected_route -eq 'RELAY' -and $_.relay_id -eq 'VPS-01' -and $_.counters.captured_packets -gt 0 -and $_.counters.relayed_packets -gt 0 -and $_.counters.relayed_bytes -gt 0 -and $_.counters.relay_reply_packets -gt 0 -and $_.counters.relay_reply_bytes -gt 0 -and $_.counters.direct_packets -eq 0})
 if($flows.Count -eq 0){throw 'Browser transport capture proof missing'}
 if($Mode -eq 'TCP'){foreach($requiredPort in @($uri.Port,$httpUri.Port)){if(@($flows|Where-Object{$_.destination.EndsWith(':'+$requiredPort)}).Count -eq 0){throw 'Missing browser HTTP/HTTPS TCP destination evidence'}}}
 foreach($flow in $flows){if(@($processes|Where-Object{$_.pid -eq $flow.pid -and $_.creation_time -eq $flow.creation_time}).Count -ne 1){throw 'Browser process creation-time mismatch'}}
 if($Mode -eq 'QUIC' -and @($observations|Where-Object{$_.protocol -eq 'HTTP/3.0'}).Count -eq 0){throw 'QUIC enabled but no real HTTP/3 response; not a QUIC PASS'}
 $proof.observations=$observations;$proof.flows=$flows;$proof.pids=$pids;$proof.processes=$processes;$proof.status='PASS'
 [void](CDP 'Network.setExtraHTTPHeaders' @{headers=@{}})
 try{[void](CDP 'Browser.close' @{})}catch{}
} catch {
 $proof.error=$_.Exception.Message
 try{$proof.service_status=Invoke-ServiceIPC 'status';$proof.capture=Invoke-ServiceIPC 'capture.diagnostics'}catch{}
 throw
} finally {
 if($null -ne $socket){$socket.Dispose()}
 if($null -ne $client){if(!$client.WaitForExit(5000)){& taskkill /PID $client.Id /T /F 2>$null|Out-Null}}
 try{[void](Invoke-ServiceIPC 'profile.delete' @{id=$profileId});[void](Invoke-ServiceIPC 'optimize' @{enabled=$original.optimizing})}catch{Write-Warning $_}
 # Netlog uses Chromium's default redaction; never request IncludeSensitive.
 if(Test-Path $netlog){try{$log=Get-Content $netlog -Raw|ConvertFrom-Json;$dnsTypes=@($log.constants.logEventTypes.PSObject.Properties|Where-Object{$_.Name -match 'DNS|HOST_RESOLVER'});$dnsIDs=@($dnsTypes|ForEach-Object{$_.Value});$proof.dns=@{event_types=@($dnsTypes.Name);event_count=@($log.events|Where-Object{$dnsIDs -contains $_.type}).Count;scope='browser netlog; system resolver/DNS egress not attributed'}}catch{$proof.dns_error=$_.Exception.Message}}
 $proof|ConvertTo-Json -Depth 20|Set-Content (Join-Path $ReportDirectory "$run-proof.json") -Encoding UTF8
}
Write-Host "PASS browser $Mode RELAY; proof retained in $ReportDirectory"
