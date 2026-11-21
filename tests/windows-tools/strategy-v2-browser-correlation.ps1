# A real local Chromium instrumentation regression, NOT external relay/ISP E2E.
# Verify CDP connectionId -> TCP_CONNECT -> exact local source port using an
# independently observed server peer endpoint. No service, driver or TLS bypass.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\..\tools\windows\strategy-v2-checks.ps1')
. (Join-Path $PSScriptRoot '..\..\tools\windows\acceptance-checks.ps1')
function Check($Value,[string]$Message){if(!$Value){throw $Message}}
$choices=@((Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),(Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),(Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe'))
$exe=@($choices|Where-Object{Test-Path -LiteralPath $_}|Select-Object -First 1)
if(!$exe.Count){throw 'Chromium/Edge required for exact socket metadata regression'}
$root=Join-Path ([IO.Path]::GetTempPath()) ('v2-socket-binding-'+[Guid]::NewGuid().ToString('N'));[void](New-Item -ItemType Directory $root)
$data=Join-Path $root 'browser';[void](New-Item -ItemType Directory $data);$netlog=Join-Path $data '.private-sockets.json';$ready=Join-Path $root 'listen';$peer=Join-Path $root 'peer'
$browser=$null;$job=$null;$idle=$null;$script:socket=$null;$phase='local_server_startup';$debugPort=0
try{
 $job=Start-Job -ArgumentList $ready,$peer -ScriptBlock {
  param($Ready,$Peer)
  $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$listener.Start()
  $clients=@();$complete=$false;$accepted=0
  try{
   [IO.File]::WriteAllText($Ready,[string]$listener.LocalEndpoint.Port)
   $deadline=[DateTime]::UtcNow.AddSeconds(90)
   # Chromium may open an idle speculative socket before its request socket.
   # Poll a bounded set instead of blocking on the first accepted connection.
   while(!$complete -and [DateTime]::UtcNow -lt $deadline){
    while($listener.Pending()){
     if(++$accepted -gt 16){throw 'Local metadata server connection bound exceeded'}
     $client=$listener.AcceptTcpClient();$clients+=@{client=$client;header=''}
    }
    foreach($entry in $clients){
     $client=$entry.client;$stream=$client.GetStream()
     if(!$stream.DataAvailable){continue}
     $buf=New-Object byte[] 1024;$n=$stream.Read($buf,0,$buf.Length)
     $entry.header+=[Text.Encoding]::ASCII.GetString($buf,0,$n)
     if($entry.header.Length -gt 16384){throw 'Local metadata request header bound exceeded'}
     if(!$entry.header.Contains("`r`n`r`n")){continue}
     [IO.File]::WriteAllText($Peer,$client.Client.RemoteEndPoint.ToString())
     $reply=[Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Length: 2`r`nContent-Type: text/plain`r`nConnection: close`r`n`r`nok")
     $stream.Write($reply,0,$reply.Length);$stream.Flush();$client.Close();$complete=$true;break
    }
    if(!$complete){Start-Sleep -Milliseconds 10}
   }
   if(!$complete){throw ('No complete local HTTP request; accepted='+$accepted)}
  }finally{foreach($entry in $clients){$entry.client.Close()};$listener.Stop()}
 }
 $deadline=[DateTime]::UtcNow.AddSeconds(20)
 while(!(Test-Path $ready)){if([DateTime]::UtcNow -gt $deadline){throw 'Local metadata server readiness timeout'};Start-Sleep -Milliseconds 100}
 $port=[int](Get-Content $ready -Raw);$url="http://127.0.0.1:$port/"
 # Deterministically keep the first connection idle, as speculative preconnect can.
 $idle=[Net.Sockets.TcpClient]::new();$idle.Connect([Net.IPAddress]::Loopback,$port)
 $arguments="--headless=new --no-first-run --no-default-browser-check --disable-background-networking --disable-quic --user-data-dir=`"$data`" --remote-debugging-address=127.0.0.1 --remote-debugging-port=0 --log-net-log=`"$netlog`" --net-log-capture-mode=Default --net-log-max-size-mb=4 about:blank"
 $browser=Start-Process -FilePath $exe[0] -ArgumentList $arguments -PassThru -RedirectStandardOutput (Join-Path $root 'stdout') -RedirectStandardError (Join-Path $root 'stderr');[void]$browser.Handle
 $phase='isolated_browser_readiness'
 $startup=Wait-AcceptanceReadiness -TimeoutMS 45000 -PollMS 100 -GetSnapshot {
  if($browser.HasExited){throw 'Owned browser exited before DevTools readiness'}
  $portFile=Join-Path $data 'DevToolsActivePort';$portValue=0;$found=@()
  if(Test-Path $portFile){$lines=@(Get-Content $portFile);if($lines.Count){[void][int]::TryParse($lines[0],[ref]$portValue)}}
  if($portValue -gt 0 -and $portValue -le 65535){try{$list=Invoke-RestMethod "http://127.0.0.1:$portValue/json/list" -TimeoutSec 2;$found=@($list|Where-Object{$_.type -eq 'page'})}catch{}}
  [pscustomobject]@{ready=($found.Count -gt 0);port=$portValue;pages=$found;missing=@('owned Chromium DevTools port and page; this is local instrumentation startup')}
 } -Evaluate {param($s)$s}
 $debugPort=$startup.port;$pages=@($startup.pages)
 $phase='cdp_socket_correlation'
 $source=Join-Path $PSScriptRoot '..\..\tools\windows\strategy-tester-v2.ps1';$tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $source),[ref]$tokens,[ref]$errors)
 $cdp=$ast.Find({param($a)$a -is [Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'CDP'},$true);Invoke-Expression $cdp.Extent.Text
 $script:cdpID=0;$script:navID=-2;$script:navError='';$script:responses=@{};$script:finished=@{};$script:failed=@{}
 $script:socket=[Net.WebSockets.ClientWebSocket]::new();$cancel=[Threading.CancellationTokenSource]::new(5000)
 try{[void]$script:socket.ConnectAsync([Uri]$pages[0].webSocketDebuggerUrl,$cancel.Token).GetAwaiter().GetResult()}finally{$cancel.Dispose()}
 [void](CDP 'Network.enable' @{});[void](CDP 'Network.setCacheDisabled' @{cacheDisabled=$true});[void](CDP 'Network.setBypassServiceWorker' @{bypass=$true})
 $main=Get-V2MainFrame (CDP 'Page.getFrameTree' @{});$script:navID=$script:cdpID+1;CDP 'Page.navigate' @{url=$url} -NoWait
 $response=$null;$deadline=[DateTime]::UtcNow.AddSeconds(15)
 while($null -eq $response){
  [void](CDP 'Browser.getVersion' @{});Assert-V2SocketLogBound $netlog
  foreach($id in @($script:responses.Keys)){$entry=$script:responses[$id];if($entry.frame_id -eq $main -and $entry.response.url -eq $url -and $script:finished.ContainsKey($id)){$response=$entry.response;break}}
  if([DateTime]::UtcNow -gt $deadline){throw ('Local completed Document response timeout: nav='+$script:navError+'; responses='+$script:responses.Count+'; finished='+$script:finished.Count+'; failures='+($script:failed.Values -join ',')+'; server='+$job.State+'; server_errors='+(@($job.ChildJobs|ForEach-Object{$_.Error}) -join '; '))}
  Start-Sleep -Milliseconds 50
 }
 Check ($response.status -eq 200 -and $response.connectionId -gt 0) 'No real successful CDP connection identity'
 CDP 'Browser.close' @{} -NoWait
 Check ($browser.WaitForExit(10000)) 'Browser did not flush metadata on graceful close';[void]$browser.WaitForExit()
 $binding=Read-V2SocketBinding $netlog ([long]$response.connectionId) ("127.0.0.1:"+$port)
 Check ($binding.status -eq 'BOUND') ('Exact socket binding unavailable: '+$binding.reason)
 Check ($binding.source -eq (Get-Content $peer -Raw).Trim()) 'CDP socket source differs from actual server-observed peer'
 Write-Host ('PASS real Chromium connectionId={0} -> source={1} -> target={2}; independently verified server peer' -f $binding.connection_id,$binding.source,$binding.destination)
}catch{
 # Keep only bounded stdout/stderr and state from this owned, empty local test
 # browser. Raw Default NetLog/profile and response payload never leave Temp.
 $failure=$_.Exception.Message
 $diagnostics=Join-Path $PSScriptRoot ('../../bin/browser-correlation/'+$PSVersionTable.PSVersion.Major+'-'+[Guid]::NewGuid().ToString('N'))
 [void](New-Item -ItemType Directory -Path $diagnostics -Force)
 foreach($name in @('stdout','stderr')){
  $file=Join-Path $root $name
  if(Test-Path $file){try{$stream=[IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);try{$length=[int][Math]::Min(65536,$stream.Length);[void]$stream.Seek(-$length,[IO.SeekOrigin]::End);$bytes=New-Object byte[] $length;$offset=0;while($offset -lt $length){$n=$stream.Read($bytes,$offset,$length-$offset);if(!$n){break};$offset+=$n};[IO.File]::WriteAllBytes((Join-Path $diagnostics ($name+'.tail')), $bytes)}finally{$stream.Dispose()}}catch{}}
 }
 @{phase=$phase;message=$failure;debug_port=$debugPort;port_file_present=(Test-Path (Join-Path $data 'DevToolsActivePort'));server_state=$(if($job){[string]$job.State}else{'not started'});browser_present=($null -ne $browser)}|ConvertTo-Json -Depth 4|Set-Content (Join-Path $diagnostics 'state.json') -Encoding UTF8
 throw ('Local browser instrumentation failure: '+$failure+'; diagnostics='+$diagnostics)
}finally{
 [void](Stop-V2TrialBrowser $browser $data)
 if($idle){$idle.Dispose()}
 if($job){Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force -ErrorAction SilentlyContinue}
 if(Test-Path $root){Remove-Item $root -Force -Recurse -ErrorAction SilentlyContinue}
}
