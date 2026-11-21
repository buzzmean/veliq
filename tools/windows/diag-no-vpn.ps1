#requires -Version 5.1
<#
Non-interactive, read-only diagnostics to run with the VPN OFF, as a normal user:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\windows\diag-no-vpn.ps1
Writes %LOCALAPPDATA%\VELIQ\Diagnostics\diag-result.txt (falls back to %TEMP%). Changes nothing on the machine. Reads no token/identity/certificate into the
report; the whole report is scrubbed of secret-shaped values before the run ends.
Self-contained: does not need common.ps1. -Only limits the run to some sections:
  env, service, ipc, tcp, udp, mtu, dns, sites, sni, browser, apps, youtube, game, riot, layers
  (youtube = SNI table for www.youtube.com + status flag + stall counters + YouTube records; run: & .\tools\windows\diag-no-vpn.ps1 -Only youtube)
#>
param(
 [string]$VpsHost='146.0.77.98',
 [int]$ControlPlanePort=8443,
 [int]$QuicPort=4433,
 [string]$InstallDirectory="$env:ProgramData\VELIQ",
 [string]$BuildDirectory='',
 [string[]]$Only=@(),
 [string]$ProxyAddress='',   # host:port of the local browser proxy; default: taken from browser.status
 [string]$OutputFile='',
 [string[]]$LayerHosts=@('www.youtube.com','discord.com')
)
$ErrorActionPreference='Continue'
Set-StrictMode -Version 2
$Only=@($Only|ForEach-Object{$_ -split ','}|Where-Object{$_})   # -File passes 'a,b' as one string
$scriptDir=if($PSScriptRoot){$PSScriptRoot}else{(Get-Location).Path}
if(-not $BuildDirectory){$BuildDirectory=Join-Path (Split-Path $scriptDir -Parent | Split-Path -Parent) 'bin\windows-e2e'}
$result=if($OutputFile){$OutputFile}else{
 $reportRoot=if($env:LOCALAPPDATA){Join-Path $env:LOCALAPPDATA 'VELIQ\Diagnostics'}else{[IO.Path]::GetTempPath()}
 try{[void][IO.Directory]::CreateDirectory($reportRoot)}catch{$reportRoot=[IO.Path]::GetTempPath()}
 Join-Path $reportRoot 'diag-result.txt'
}
$utf8=New-Object Text.UTF8Encoding($false)      # appends: the BOM is written once, below
$utf8Bom=New-Object Text.UTF8Encoding($true)
$bom=[byte[]](0xEF,0xBB,0xBF)                    # UTF-8 BOM so Windows tools show Cyrillic correctly
try{[IO.File]::WriteAllBytes($result,$bom)}catch{$result=Join-Path ([IO.Path]::GetTempPath()) 'diag-result.txt';[IO.File]::WriteAllBytes($result,$bom)}
$isWin=($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows

function Say([string]$Text){Write-Host $Text;[IO.File]::AppendAllText($result,$Text+"`r`n",$utf8)}
function Want([string]$Section){return ($Only.Count -eq 0) -or ($Only -contains $Section) -or ($Section -eq 'sni' -and $Only -contains 'youtube')}
function Section([string]$Title){Say '';Say ('=== '+$Title+' ===')}
function Scrub([string]$Text){
 $Text=[regex]::Replace($Text,'-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----','[PEM REMOVED]')
 [regex]::Replace($Text,'(?i)("?(token|secret|private[_ ]?key|seed|password|authorization)"?\s*[:=]\s*)"?[^",\s}]+"?','$1"[REDACTED]"')
}
function Json($Value){Scrub ($Value|ConvertTo-Json -Depth 12)}
# NB: parameter is not called $Name: script blocks run in the caller scope and
# loops below use their own variable names, never shadowing this one.
function Step([string]$StepName,[scriptblock]$Body){try{& $Body}catch{Say ("[$StepName] ERROR: "+(Scrub $_.Exception.Message))}}
function Prop($Object,[string]$PropName,$Default=$null){
 if($null -ne $Object){$property=$Object.PSObject.Properties[$PropName];if($null -ne $property){return $property.Value}};return $Default
}

# Configured default and observed traffic are deliberately separate. AUTO is
# not proof of DIRECT, especially on services predating the game safety fix.
function Get-RelayProfileSummary($AppProfile,$Routing,$Snapshots){
 $profileId=[string](Prop $AppProfile 'id' '')
 $mode=[string](Prop $AppProfile 'mode' '')
 $defaultRoute=if($mode -eq 'MANUAL'){'RELAY'}elseif($mode -eq 'AUTO'){'UNKNOWN_LEGACY_AUTO'}else{$mode}
 $origin='unknown (legacy files do not record GUI/IPC author)'
 $allowed='unknown'
 $configuredRelay=[string](Prop $AppProfile 'relay_id' '-')
 if($null -ne $Routing){$defaultRoute=[string](Prop $Routing 'default_route' $defaultRoute);$origin=[string](Prop $Routing 'origin' $origin);$allowed=[string](Prop $Routing 'automatic_relay_allowed' 'unknown')}
 if($null -ne $Routing){$configuredRelay=[string](Prop $Routing 'relay_id' $configuredRelay)}
 "PROFILE id=$profileId mode=$mode origin=$origin default=$defaultRoute automatic_relay_allowed=$allowed relay=$configuredRelay"
 $observed=0;$complete=(@($Snapshots).Count -gt 0)
 foreach($snap in @($Snapshots)){
  $processId=[uint32](Prop $snap 'pid' 0);$birth=[uint64](Prop $snap 'birth' 0)
  if(!$processId -or !$birth){continue}
  $data=Prop $snap 'data'
  $truncated=[bool](Prop $data 'truncated' $false);$lost=[bool](Prop $data 'evidence_lost' $false)
  if($truncated -or $lost){$complete=$false}
  "CAPTURE profile=$profileId pid=$processId birth=$birth truncated=$truncated evidence_lost=$lost"
  foreach($flow in @(Prop $data 'flows' @())){
   if([uint32](Prop $flow 'pid' 0) -ne $processId -or [uint64](Prop $flow 'creation_time' 0) -ne $birth){continue}
   $group=[string](Prop $flow 'process_group' '')
   if($group -and $group -ne $profileId){continue}
   $counters=Prop $flow 'counters';$relayed=[uint64](Prop $counters 'relayed_packets' 0)
   $route=[string](Prop $flow 'selected_route' '')
   if($route -ne 'RELAY' -and !$relayed){continue}
   $observed++
   $policy=Prop $flow 'policy'
   "FLOW profile=$profileId pid=$processId route=$route relay=$(Prop $flow 'relay_id' '-') protocol=$(Prop $flow 'protocol') destination=$(Prop $flow 'destination') captured=$(Prop $counters 'captured_packets' 0) relayed=$relayed relay_bytes=$(Prop $counters 'relayed_bytes' 0) direct=$(Prop $counters 'direct_packets' 0) source=$(Prop $policy 'source' 'unknown') fallback=$(Prop $policy 'fallback' 'unknown') last_seen=$(Prop $flow 'last_seen' 'unknown')"
  }
 }
 "OBSERVED profile=$profileId relay_flows=$observed snapshots_complete=$complete (bounded cumulative evidence, not a complete live-connection census)"
}

function Write-RelayProfileAudit {
 $profiles=@(Invoke-IPC 'profiles')
 $routing=@()
 try{$audit=Invoke-IPC 'profiles.routing';$routing=@(Prop $audit 'profiles' @());Say ("routing_metadata_truncated="+(Prop $audit 'truncated' $false))}
 catch{Say 'profiles.routing unavailable: legacy AUTO may inherit a global relay; configured mode alone is insufficient'}
 # Put games/ordinary apps before browser subprocesses in the bounded sample.
 $ordered=@($profiles|Sort-Object @{Expression={if((Prop $_ 'id') -eq 'cs2'){0}elseif((Prop $_ 'mode') -eq 'MANUAL'){1}elseif((Prop $_ 'mode') -eq 'DIRECT'){2}else{3}}},@{Expression={Prop $_ 'id'}})
 $budget=32;$cache=@{}
 foreach($appProfile in @($ordered|Select-Object -First 64)){
  $profileId=[string](Prop $appProfile 'id');$exe=@(Prop $appProfile 'executables' @())
  $entry=@($routing|Where-Object{(Prop $_ 'id') -eq $profileId}|Select-Object -First 1)
  $metadata=if($entry.Count){$entry[0]}else{$null}
  $snapshots=@()
  if($exe.Count -and $budget -gt 0){
   $processes=@(Invoke-IPC 'processes' @{executables=$exe})
   foreach($process in $processes){
    $processId=[uint32](Prop $process 'PID' 0);$birth=[uint64](Prop $process 'CreationTime' 0)
    if(!$processId -or !$birth){continue}
    $key="$processId/$birth"
    if(!$cache.ContainsKey($key)){
     if($budget -le 0){break}
     $data=Invoke-IPC 'capture.diagnostics' @{pid=$processId;creation_time=$birth}
     $cache[$key]=[pscustomobject]@{pid=$processId;birth=$birth;data=$data};$budget--
    }
    $snapshots+=@($cache[$key])
   }
  }
  foreach($line in @(Get-RelayProfileSummary $appProfile $metadata $snapshots)){Say $line}
 }
 Say ("sample_limits: profiles=$([Math]::Min(64,$profiles.Count))/$($profiles.Count) process_budget_remaining=$budget; zero observed flows is not proof of no relay outside this sample")
}

# Existing user browsers are observed only; never send them quit/kill or change PAC.
function Get-LiveBrowserIdentity {
 if(-not $isWin){return @()}
 $session=(Get-Process -Id $PID).SessionId
 @(Get-CimInstance Win32_Process -Filter "Name='chrome.exe' OR Name='msedge.exe'" -ErrorAction Stop|
  Where-Object{$_.SessionId -eq $session -and $_.ExecutablePath}|
  ForEach-Object{[pscustomobject]@{name=$_.Name;pid=$_.ProcessId;created=$_.CreationDate.ToUniversalTime().ToString('o');path=$_.ExecutablePath}})
}
$script:liveBrowserBefore=@()
if(Want 'browser'){
 Step 'existing_browser_before' {$script:liveBrowserBefore=@(Get-LiveBrowserIdentity)}
}

# Reads a file another process may still hold open (a Chrome child that inherited the
# redirected handle): shared read access, short retries.
function Read-SharedText([string]$Path){
 if(-not (Test-Path -LiteralPath $Path)){return ''}
 for($try=0;$try -lt 20;$try++){
  try{
   $fs=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
   try{$sr=New-Object IO.StreamReader($fs,[Text.Encoding]::UTF8);return $sr.ReadToEnd()}finally{$fs.Dispose()}
  }catch [IO.IOException]{Start-Sleep -Milliseconds 250}
 }
 return ''
}
# Ends the browser we started: the tree first, then any leftover process whose command
# line carries our one-off profile directory (children detach when the parent exits).
function Stop-OwnBrowser($Process,[string]$Marker){
 try{if($Process -and -not $Process.HasExited){& taskkill.exe /T /F /PID $Process.Id 2>&1|Out-Null}}catch{}
 try{
  Get-CimInstance Win32_Process -Filter "Name='chrome.exe' OR Name='msedge.exe'" -ErrorAction SilentlyContinue|
   Where-Object{$_.CommandLine -and $_.CommandLine.Contains($Marker)}|
   ForEach-Object{Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue}
 }catch{}
}

# TCP connect + TLS handshake to one IP with a chosen SNI. Certificate validation stays
# ON: the callback returns the real verdict. It only records whether the server answered
# the ClientHello at all, which is what separates "SNI/data blocked" (timeout, reset) from
# "reachable" (server certificate received, even if it is for another name).
function Test-TlsSni([string]$Address,[string]$Sni,[int]$Port=443,[int]$TimeoutMs=5000){
 $result=[ordered]@{Ip=$Address;Sni=$Sni;Tcp='';TcpMs=-1;Tls='';Detail=''}
 $client=New-Object Net.Sockets.TcpClient
 try{
  $watch=[Diagnostics.Stopwatch]::StartNew()
  $task=$client.ConnectAsync($Address,$Port)
  $connected=$false;try{$connected=$task.Wait($TimeoutMs) -and $client.Connected}catch{}
  $result.TcpMs=[int]$watch.ElapsedMilliseconds
  if(-not $connected){$result.Tcp='FAILED';$result.Tls='not attempted';return [pscustomobject]$result}
  $result.Tcp='OK'
  $client.ReceiveTimeout=$TimeoutMs;$client.SendTimeout=$TimeoutMs
  $global:SniProbe=@{Got=$false;Errors=''}
  $cb=[Net.Security.RemoteCertificateValidationCallback]{param($sender,$certificate,$chain,$errors) $global:SniProbe.Got=$true;$global:SniProbe.Errors=[string]$errors;return ($errors -eq [Net.Security.SslPolicyErrors]::None)}
  $ssl=New-Object Net.Security.SslStream($client.GetStream(),$false,$cb)
  $hs=[Diagnostics.Stopwatch]::StartNew()
  try{
   $ssl.AuthenticateAsClient($Sni,$null,[Security.Authentication.SslProtocols]::Tls12,$false)
   $result.Tls="OK in $($hs.ElapsedMilliseconds) ms (certificate verified)"
  }catch{
   $inner=$_.Exception.GetBaseException()
   if($global:SniProbe.Got){$result.Tls="SERVER ANSWERED in $($hs.ElapsedMilliseconds) ms (certificate not accepted for this name: $($global:SniProbe.Errors))"}
   elseif($inner -is [Net.Sockets.SocketException] -and $inner.SocketErrorCode -eq 'ConnectionReset'){$result.Tls="RESET after ClientHello ($($hs.ElapsedMilliseconds) ms)"}
   elseif($inner -is [IO.IOException] -and $inner.Message -match 'timed out|timeout|expired'){$result.Tls="NO ANSWER (timeout $($hs.ElapsedMilliseconds) ms)"}
   elseif($inner -is [Net.Sockets.SocketException] -and $inner.SocketErrorCode -eq 'TimedOut'){$result.Tls="NO ANSWER (timeout $($hs.ElapsedMilliseconds) ms)"}
   else{$result.Tls="FAILED ($($inner.GetType().Name): $($inner.Message -replace '\s+',' '))"}
  }
  $ssl.Dispose()
 }catch{$result.Tls="ERROR $($_.Exception.Message)"}
 finally{$client.Close()}
 return [pscustomobject]$result
}

# ---------- IPC (same wire format as the GUI: 4-byte big-endian length + JSON) ----------
function Read-Exact($Stream,[int]$Count,[DateTime]$Deadline){
 $bytes=New-Object byte[] $Count;$offset=0
 while($offset -lt $Count){
  $left=[int][Math]::Max(1,($Deadline-[DateTime]::UtcNow).TotalMilliseconds)
  $pending=$Stream.BeginRead($bytes,$offset,$Count-$offset,$null,$null)
  if(-not $pending.AsyncWaitHandle.WaitOne($left)){throw 'IPC timeout'}
  $n=$Stream.EndRead($pending);if($n -eq 0){throw 'IPC stream closed'};$offset+=$n
 }
 return ,$bytes
}
function Invoke-IPCOnce([string]$Method,$Payload=$null){
 $token=[IO.File]::ReadAllText((Join-Path $InstallDirectory 'ipc.token')).Trim()   # authenticates only; never printed
 $id=[Guid]::NewGuid().ToString('N')
 $request=@{version=1;id=$id;sent_at=[DateTimeOffset]::UtcNow.ToString('o');token=$token;method=$Method;payload=$Payload}|ConvertTo-Json -Depth 8 -Compress
 $bytes=[Text.Encoding]::UTF8.GetBytes($request)
 $pipe=New-Object IO.Pipes.NamedPipeClientStream('.','neexitlag-v1',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous)
 try{
  $pipe.Connect(3000)
  $deadline=[DateTime]::UtcNow.AddSeconds(8)
  $header=[BitConverter]::GetBytes([uint32]$bytes.Length);[Array]::Reverse($header)
  foreach($part in @($header,$bytes)){$w=$pipe.BeginWrite($part,0,$part.Length,$null,$null);if(-not $w.AsyncWaitHandle.WaitOne(8000)){throw 'IPC write timeout'};$pipe.EndWrite($w)}
  $lenBytes=Read-Exact $pipe 4 $deadline;[Array]::Reverse($lenBytes);$length=[BitConverter]::ToUInt32($lenBytes,0)
  if($length -lt 1 -or $length -gt 1048576){throw 'invalid IPC response size'}
  $response=[Text.Encoding]::UTF8.GetString((Read-Exact $pipe ([int]$length) $deadline))|ConvertFrom-Json
  if(-not $response.ok){throw ([string]$response.error)}
  return $response.data
 }finally{$pipe.Dispose()}
}
function Invoke-IPC([string]$Method,$Payload=$null){
 $until=[DateTime]::UtcNow.AddSeconds(30)
 while($true){
  try{return Invoke-IPCOnce $Method $Payload}
  catch{if("$_" -notlike '*service is starting*' -or [DateTime]::UtcNow -ge $until){throw};Start-Sleep -Milliseconds 500}
 }
}

# ---------- network helpers ----------
# QUIC long header with a reserved version: a QUIC server answers with Version
# Negotiation, but only when the datagram is at least 1200 bytes (RFC 9000 14.1).
function New-QuicProbe([int]$Size){
 $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
 $dcid=New-Object byte[] 8;$scid=New-Object byte[] 8;$rng.GetBytes($dcid);$rng.GetBytes($scid)
 $packet=New-Object byte[] $Size
 $packet[0]=0xC0;$packet[1]=0x1A;$packet[2]=0x2A;$packet[3]=0x3A;$packet[4]=0x4A
 $packet[5]=8;[Array]::Copy($dcid,0,$packet,6,8);$packet[14]=8;[Array]::Copy($scid,0,$packet,15,8)
 return ,$packet
}
function Test-UdpLoss([string]$Address,[int]$Port,[int]$Size,[int]$Count=50,[int]$GapMs=20){
 $packet=New-QuicProbe $Size
 $udp=New-Object Net.Sockets.UdpClient
 $replies=0;$rtts=New-Object Collections.Generic.List[double]
 try{
  $udp.Connect($Address,$Port)
  $watch=[Diagnostics.Stopwatch]::StartNew()
  $drain={
   while($udp.Available -gt 0){
    $remote=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0)
    [void]$udp.Receive([ref]$remote);$script:replies++
   }
  }
  for($i=0;$i -lt $Count;$i++){
   [void]$udp.Send($packet,$packet.Length)
   Start-Sleep -Milliseconds $GapMs
   $replies+=0
   while($udp.Available -gt 0){$remote=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0);[void]$udp.Receive([ref]$remote);$replies++}
  }
  $end=[DateTime]::UtcNow.AddMilliseconds(1500)
  while([DateTime]::UtcNow -lt $end){
   if($udp.Available -gt 0){$remote=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0);[void]$udp.Receive([ref]$remote);$replies++}else{Start-Sleep -Milliseconds 20}
  }
 }finally{$udp.Close()}
 return [pscustomobject]@{Size=$Size;Sent=$Count;Replies=$replies;LossPercent=[Math]::Round(100.0*(1-[Math]::Min($replies,$Count)/$Count),1)}
}
function Test-IcmpLoss([string]$Address,[int]$Size,[int]$Count=50){
 $buffer=New-Object byte[] $Size
 $pings=@();$tasks=@()
 for($i=0;$i -lt $Count;$i++){
  $p=New-Object Net.NetworkInformation.Ping;$pings+=$p
  $tasks+=$p.SendPingAsync($Address,1500,$buffer)
  Start-Sleep -Milliseconds 20
 }
 try{[void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]$tasks,10000)}catch{}
 $ok=@($tasks|Where-Object{$_.Status -eq 'RanToCompletion' -and $_.Result.Status -eq 'Success'})
 $rtt=@($ok|ForEach-Object{$_.Result.RoundtripTime})
 foreach($p in $pings){$p.Dispose()}
 return [pscustomobject]@{Size=$Size;Sent=$Count;Replies=$ok.Count;LossPercent=[Math]::Round(100.0*(1-$ok.Count/$Count),1);AvgMs=$(if($rtt.Count){[Math]::Round(($rtt|Measure-Object -Average).Average,1)}else{$null})}
}
function Find-PathMtu([string]$Address){
 # Largest ICMP payload that passes with DF set; MTU = payload + 28.
 $ping=New-Object Net.NetworkInformation.Ping
 $options=New-Object Net.NetworkInformation.PingOptions(64,$true)
 $try={param($n) $r=$ping.Send($Address,1500,(New-Object byte[] $n),$options);return $r.Status}
 try{
  if((& $try 32) -ne 'Success'){return [pscustomobject]@{Reachable=$false;Detail='no ICMP reply even for a 32-byte DF probe (ICMP filtered or host down)'}}
  $lo=32;$hi=1472
  if((& $try $hi) -eq 'Success'){$lo=$hi}
  else{while($hi-$lo -gt 1){$mid=[int](($lo+$hi)/2);if((& $try $mid) -eq 'Success'){$lo=$mid}else{$hi=$mid}}}
  return [pscustomobject]@{Reachable=$true;MaxPayload=$lo;PathMtu=$lo+28;Detail=''}
 }finally{$ping.Dispose()}
}

$ScriptVersion='2026-10-25.16 (measurement revision 2: relay sessions, layered DNS/TLS, timestamp/early failure audit)'
Say "VELIQ diag-no-vpn, started $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))"
Say "Script version: $ScriptVersion"
Say "Script file: $(if($PSCommandPath){$PSCommandPath}else{'(unknown)'})"
Step 'repo' {
 $repo=Split-Path (Split-Path $scriptDir -Parent) -Parent
 if((Test-Path (Join-Path $repo '.git')) -and (Get-Command git -ErrorAction SilentlyContinue)){
  $head=(& git -C $repo rev-parse --short=12 HEAD 2>&1|Out-String).Trim()
  $branch=(& git -C $repo branch --show-current 2>&1|Out-String).Trim()
  $dirty=(& git -C $repo status --porcelain --untracked-files=no 2>&1|Out-String).Trim().Length -gt 0
  Say "Repository: $repo branch $branch commit $head$(if($dirty){' (+local changes)'})  <- compare with the commit you expect"
 }else{Say "Repository: not a git checkout here ($repo): this script file may be a stray copy"}
}
Say "Result file: $result"

if(Want 'env'){
Section '0. Environment (is the VPN really off?)'
Step 'env' {
 $os=Get-CimInstance Win32_OperatingSystem
 Say "OS: $($os.Caption) build $($os.BuildNumber); user: $env:USERNAME; PowerShell $($PSVersionTable.PSVersion)"
 $vpn=@(Get-NetAdapter|Where-Object{$_.Status -eq 'Up' -and ($_.InterfaceDescription+' '+$_.Name) -match 'VPN|Happ|TUN|TAP|WireGuard|Wintun'}|ForEach-Object{$_.Name})
 Say ("Active VPN-like adapters: "+$(if($vpn.Count){($vpn -join ', ')+'  <-- VPN looks ON, results below are NOT a no-VPN test'}else{'none (good)'}))
 Say ("Default route(s): "+((Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue|Sort-Object RouteMetric|ForEach-Object{"if$($_.InterfaceIndex) via $($_.NextHop) metric $($_.RouteMetric)"}) -join '; '))
 Say ("System DNS: "+((Get-DnsClientServerAddress -AddressFamily IPv4|Where-Object{$_.ServerAddresses}|ForEach-Object{$_.ServerAddresses -join ','}|Select-Object -Unique) -join '; '))
}}

if(Want 'service'){
Section '1a. Service and binary'
Step 'service' {
 $svc=Get-Service VELIQ -ErrorAction Stop
 Say "Service VELIQ: $($svc.Status), start type $($svc.StartType)"
 $hashes=@{}
 foreach($pair in @(@('installed',(Join-Path $InstallDirectory 'veliq-service.exe')),@('built',(Join-Path $BuildDirectory 'veliq-service.exe')))){
  if(Test-Path $pair[1]){$h=(Get-FileHash $pair[1] -Algorithm SHA256).Hash;$hashes[$pair[0]]=$h;Say "SHA256 $($pair[0]): $h (modified $((Get-Item $pair[1]).LastWriteTime.ToString('yyyy-MM-dd HH:mm')))"}
  else{Say "SHA256 $($pair[0]): file not found ($($pair[1]))"}
 }
 if($hashes.ContainsKey('installed') -and $hashes.ContainsKey('built')){Say ("installed == built: "+($hashes['installed'] -eq $hashes['built']))}
}}

$script:status=$null
$script:browserJson=''
if(Want 'ipc'){
Section '1b. IPC status'
Step 'status' {
 $script:status=Invoke-IPC 'status'
 Say ("optimizing: "+(Prop $script:status 'optimizing')+"; service build: "+(Prop $script:status 'build' '(none: the running service is OLDER than the build stamp)'))
 Say (Json $script:status)
}
Section '1c. IPC profiles (what Optimize covers)'
Step 'profiles' {
 $rows=@(Invoke-IPC 'profiles');Say "Profile count: $($rows.Count)"
 foreach($p in $rows){Say ("- id=$(Prop $p 'id') name=$(Prop $p 'name') mode=$(Prop $p 'mode') custom=$(Prop $p 'custom') fallback=$(Prop $p 'fallback') preset=$(Prop $p 'app_preset') exe=$((@(Prop $p 'executables' @())) -join ' | ') rules=$(@(Prop $p 'rules' @()).Count)")}
 $exes=($rows|ForEach-Object{@(Prop $_ 'executables' @())})-join ' '
 Say ("Has Chrome profile: "+($exes -match 'chrome\.exe')+"; Edge: "+($exes -match 'msedge\.exe')+"; Telegram: "+($exes -match '(?i)telegram\.exe')+"; Discord: "+($exes -match '(?i)discord'))
}
Section '1c-activation. Activation / certificate validity (no credential)'
Step 'ipc' {
 try{$v=Invoke-IPC 'activation.status';$state=[string](Prop $v 'state' 'UNKNOWN');if($state -notin @('CODE_REQUIRED','CODE_STAGED','ACTIVATING','ACTIVATED','ACTIVATION_ERROR','UNAVAILABLE')){$state='UNKNOWN'};Say ('activation state='+$state+' identity='+(Prop $v 'has_identity' $false)+' ca_not_after='+(Prop $v 'ca_not_after' 'UNKNOWN')+' server_not_after='+(Prop $v 'server_not_after' 'UNKNOWN'))}catch{Say 'activation: STATUS_UNAVAILABLE (older service or IPC unavailable)'}
}

Section '1d. IPC browser.status'
Step 'browser' {$script:browserJson=Json (Invoke-IPC 'browser.status');Say $script:browserJson}
Section '1e. IPC capture.diagnostics'
Step 'capture' {Say (Json (Invoke-IPC 'capture.diagnostics'))}
Section '1f. IPC quality.diagnostics'
Step 'quality' {Say (Json (Invoke-IPC 'quality.diagnostics'))}
Section '1g. IPC relay.pool.diagnostics (handshake/x509/dial errors show up here)'
Step 'pool' {
 $ids=@();if($script:status){$ids=@(Prop $script:status 'relays' @()|ForEach-Object{Prop $_ 'id'}|Where-Object{$_})}
 if($ids.Count -eq 0){$ids=@('VPS-01')}
 foreach($relayId in $ids){Say ("relay $relayId : "+(Json (Invoke-IPC 'relay.pool.diagnostics' @{relay_id=$relayId})))}
}}

if((Want 'apps') -or (Want 'ipc')){
 Section '1h. Процессы с профилем RELAY'
 Step 'relay-profiles' {Write-RelayProfileAudit}
}

if(Want 'tcp'){
Section "2a. $VpsHost TCP $ControlPlanePort (control plane) - INFORMATIONAL"
Say 'Informational only. The control plane requires TLS 1.3. Windows PowerShell 5.1 (.NET Framework) cannot speak TLS 1.3, so this script does not handshake itself; curl.exe is used with the project CA and normal verification. A failure here is a limit of this probe, NOT a service fault: the service status (IPC, sections 1b/1g) is authoritative for the control plane and relay.'
Step 'tcp' {
 $watch=[Diagnostics.Stopwatch]::StartNew()
 $client=New-Object Net.Sockets.TcpClient
 try{
  $task=$client.ConnectAsync($VpsHost,$ControlPlanePort)
  $ok=$false;try{$ok=$task.Wait(6000) -and $client.Connected}catch{Say ("TCP connect error: "+$_.Exception.GetBaseException().Message)}
  if($ok){Say "TCP ${ControlPlanePort}: connected in $($watch.ElapsedMilliseconds) ms"}
  else{Say "TCP ${ControlPlanePort}: NO CONNECTION within 6 s (blocked, dropped or nothing listening)";return}
 }finally{$client.Close()}
 $caPath=Join-Path $InstallDirectory 'cp-ca.pem'
 if(-not (Test-Path $caPath)){
  $manifest=Join-Path $InstallDirectory 'service.json'
  if(Test-Path $manifest){try{$m=Get-Content $manifest -Raw|ConvertFrom-Json;$caPath=[string](Prop $m 'control_plane_ca_file' '')}catch{}}
 }
 $curlExe=(Get-Command curl.exe -ErrorAction SilentlyContinue)
 if(-not $curlExe){Say 'curl.exe not found: certificate check skipped (informational).';return}
 if(-not $caPath -or -not (Test-Path $caPath)){Say "Project CA file not readable ($caPath): certificate check skipped (informational). Verification is never disabled."; return}
 # Normal verification against the project CA. --ssl-no-revoke only skips the
 # revocation-list download that a private CA cannot answer; it does not weaken the chain,
 # validity or host checks.
 $raw=(& $curlExe.Source -sS -m 10 --ssl-no-revoke --cacert $caPath -o NUL -w 'HTTP %{http_code} tls_verify=%{ssl_verify_result} connect=%{time_connect}s tls=%{time_appconnect}s' "https://${VpsHost}:${ControlPlanePort}/healthz" 2>&1|Out-String)
 $curlExit=$LASTEXITCODE   # must be read right after the native call
 $text=($raw.Trim() -replace '\s+',' ')
 $tlsSeconds=0.0
 $tlsMatch=[regex]::Match($text,'tls=([0-9]+(?:[.,][0-9]+)?)s')
 if($tlsMatch.Success){[void][double]::TryParse(($tlsMatch.Groups[1].Value -replace ',','.'),[Globalization.NumberStyles]::Float,[Globalization.CultureInfo]::InvariantCulture,[ref]$tlsSeconds)}
 # OK only when curl itself succeeded, a TLS handshake really happened (time > 0) and the
 # certificate verified against the project CA. Anything else, including a curl/Schannel
 # error such as SEC_E_ILLEGAL_MESSAGE with tls=0, is "undetermined", never a pass.
 $verdict=if($curlExit -eq 0 -and $tlsSeconds -gt 0 -and $text -match 'tls_verify=0'){'handshake and certificate OK against the project CA'}else{"UNDETERMINED (curl exit code $curlExit, tls time ${tlsSeconds}s): the handshake did not complete here; this probe cannot tell a service fault from a client TLS limit"}
 Say "curl with project CA: $text -> $verdict"
}}

if(Want 'udp'){
Section "2b. $VpsHost UDP ${QuicPort}: loss by datagram size (QUIC Version Negotiation probes, 50 each)"
Step 'udp' {
 Say 'Only datagrams of >=1200 bytes make a QUIC server answer; smaller sizes cannot be measured on this port (server ignores them by design). Echo port 40000 needs a secret token and a fixed 128-byte format, so it is NOT probed here.'
 foreach($size in 100,600,1200,1400){
  if($size -lt 1200){Say "UDP ${QuicPort} size ${size}: not measurable (QUIC servers ignore datagrams <1200 bytes)";continue}
  $r=Test-UdpLoss $VpsHost $QuicPort $size 50 20
  Say "UDP ${QuicPort} size ${size}: sent $($r.Sent), replies $($r.Replies), loss $($r.LossPercent)%"
 }
}}

if(Want 'mtu'){
Section "2c. $VpsHost ICMP loss by size, path MTU, route"
Step 'icmp' {
 foreach($size in 100,600,1200,1400){
  $r=Test-IcmpLoss $VpsHost $size 50
  Say "ICMP payload ${size}: sent $($r.Sent), replies $($r.Replies), loss $($r.LossPercent)%, avg rtt $($r.AvgMs) ms"
 }
}
Step 'mtu' {
 $m=Find-PathMtu $VpsHost
 if($m.Reachable){Say "Path MTU (DF set): max payload $($m.MaxPayload) bytes -> MTU $($m.PathMtu)"}else{Say "Path MTU: $($m.Detail)"}
}
Step 'tracert' {
 if($isWin){
  Say 'tracert -d -h 15 -w 1000:'
  foreach($line in (& tracert.exe -d -h 15 -w 1000 $VpsHost 2>&1)){$t="$line".TrimEnd();if($t){Say "  $t"}}
 }else{Say 'tracert skipped (not Windows)'}
}}

if(Want 'dns'){
Section 'DNS: system resolver vs 8.8.8.8'
$dnsHosts=@('claude.ai','api.anthropic.com','chatgpt.com','www.youtube.com','web.telegram.org','discord.com','t.me')
foreach($dnsHost in $dnsHosts){
 Step "dns $dnsHost" {
  $sys='';$pub=''
  try{$sys=(@(Resolve-DnsName $dnsHost -Type A -DnsOnly -ErrorAction Stop|Where-Object{$_.Type -eq 'A'}|ForEach-Object{$_.IPAddress})|Sort-Object) -join ','}catch{$sys='ERROR '+($_.Exception.Message -replace '\s+',' ')}
  try{$pub=(@(Resolve-DnsName $dnsHost -Type A -DnsOnly -Server 8.8.8.8 -ErrorAction Stop|Where-Object{$_.Type -eq 'A'}|ForEach-Object{$_.IPAddress})|Sort-Object) -join ','}catch{$pub='ERROR '+($_.Exception.Message -replace '\s+',' ')}
  $sa=@($sys -split ',');$pa=@($pub -split ',')
  $verdict=if($sys -like 'ERROR*' -or $pub -like 'ERROR*'){'a lookup failed'}elseif(@($sa|Where-Object{$pa -contains $_}).Count -gt 0){'overlap (consistent)'}else{'NO OVERLAP (can be CDN rotation or DNS tampering)'}
  Say "$dnsHost | system: $sys | 8.8.8.8: $pub | $verdict"
 }
}}

if(Want 'sites'){
Section 'HTTPS to the target sites (plain curl.exe, not through Chrome/PAC)'
$curl=(Get-Command curl.exe -ErrorAction SilentlyContinue)
foreach($site in @('chatgpt.com','claude.ai','www.youtube.com','web.telegram.org','discord.com')){
 Step "site $site" {
  if($curl){
   $text=(& $curl.Source -sS -m 15 -o NUL -w 'HTTP %{http_code} ip=%{remote_ip} connect=%{time_connect}s tls=%{time_appconnect}s total=%{time_total}s' "https://$site/" 2>&1|Out-String).Trim() -replace '\s+',' '
   $verdict=if($text -match 'HTTP (2|3)\d\d'){'OPENS'}elseif($text -match 'HTTP (4|5)\d\d'){'ANSWERS (HTTP error, host reachable)'}else{'FAILS'}
   Say "$site [$verdict] $text"
  }else{
   try{$r=Invoke-WebRequest "https://$site/" -UseBasicParsing -TimeoutSec 15 -MaximumRedirection 0 -ErrorAction Stop;Say "$site [OPENS] HTTP $([int]$r.StatusCode)"}
   catch{$resp=$_.Exception.Response;if($resp){Say "$site [ANSWERS] HTTP $([int]$resp.StatusCode)"}else{Say "$site [FAILS] $($_.Exception.Message)"}}
  }
 }
}}

function Write-RiotEvidence($snapshot) {
 Say ('Riot: '+(Prop $snapshot 'scope' 'UNINSTRUMENTED'))
 foreach($row in @(Prop $snapshot 'records' @())) {
  $policy=Prop $row 'policy';$owner=Prop $row 'owner'
  Say (' Riot flow: exe='+(Prop $owner 'exe')+' domain='+(Prop $row 'domain')+' destination='+(Prop $row 'upstream_destination')+' stage='+(Prop $policy 'action')+' reason='+(Prop $policy 'reason')+' tx='+(Prop $row 'sent_bytes' 0)+' rx='+(Prop $row 'received_bytes' 0)+' result='+(Prop $row 'result'))
 }
 foreach($row in @(Prop $snapshot 'stages' @())) {Say (' Riot LOCAL/RELAY: stage='+(Prop $row 'stage')+' strategy='+(Prop $row 'strategy')+' connections='+(Prop $row 'Connections' 0)+' tx='+(Prop $row 'TX' 0)+' rx='+(Prop $row 'RX' 0)+' failures='+(Prop $row 'Failures' 0))}
 Say ('Riot address policy: '+(Prop $snapshot 'address_policy' 'UNINSTRUMENTED'))
}

if(Want 'riot'){
 Section 'Riot launcher: real SNI vs foreign SNI; read-only DIRECT probes'
 Step 'riot-installed-exe' {
  foreach($base in @($env:LOCALAPPDATA,$env:ProgramFiles,${env:ProgramFiles(x86)},($env:SystemDrive+'\'))){
   if(-not $base){continue};$folder=Join-Path $base 'Riot Games\Riot Client'
   if(Test-Path -LiteralPath $folder){Get-ChildItem -LiteralPath $folder -Filter 'RiotClient*.exe' -File -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 12 | ForEach-Object {Say (' Riot installed executable: '+$_.FullName)}}
  }
 }

 Step 'riot-status' { Write-RiotEvidence (Invoke-IPC 'riot.status') }
 Step 'riot-tls' {
  $timer=[Diagnostics.Stopwatch]::StartNew()
  foreach($riotHost in @('sieve.services.riotcdn.net','auth.riotgames.com','clientconfig.rpg.riotgames.com','data.riotgames.com','authenticate.riotgames.com','lol.secure.dyn.riotcdn.net','valorant.secure.dyn.riotcdn.net','eas-prod.pp.sgp.pvp.net','telemetry.sgp.pvp.net')){
   if($timer.Elapsed.TotalSeconds -ge 45){Say (' Riot '+$riotHost+': PROBE_BUDGET_EXHAUSTED');continue}
   $addresses=@();try{$addresses=@(Resolve-DnsName $riotHost -Type A -DnsOnly -ErrorAction Stop | Where-Object {$_.Type -eq 'A'} | Select-Object -ExpandProperty IPAddress -Unique | Select-Object -First 2)}catch{Say (' Riot '+$riotHost+': DNS_FAILED')}
   foreach($ip in $addresses){
    foreach($sni in @($riotHost,'example.com')){
     if($timer.Elapsed.TotalSeconds -ge 45){Say (' Riot '+$riotHost+' '+$ip+': PROBE_BUDGET_EXHAUSTED');break}
     $probe=Test-TlsSni $ip $sni 443 1500
     Say (' Riot '+$riotHost+' ip='+$ip+' sni='+$sni+' tcp='+$probe.Tcp+' tcp_ms='+$probe.TcpMs+' tls='+$probe.Tls)
    }
   }
  }
  Say 'Both names silent is evidence for this endpoint, not proof for an entire Cloudflare subnet. Foreign certificate mismatch is ANSWERED, not TLS/HTTP PASS. No credentials/patch URLs are used.'
 }
}

if(Want 'sni'){
Section 'YouTube: TCP + TLS per IP with different SNI (is it SNI blocking?)'
Step 'sni' {
 $addrs=@()
 foreach($srv in @($null,'8.8.8.8')){
  try{
   $q=@{Name='www.youtube.com';Type='A';DnsOnly=$true;ErrorAction='Stop'};if($srv){$q.Server=$srv}
   $addrs+=@(Resolve-DnsName @q|Where-Object{$_.Type -eq 'A'}|ForEach-Object{$_.IPAddress})
  }catch{Say ("DNS www.youtube.com via $(if($srv){$srv}else{'system'}): "+($_.Exception.Message -replace '\s+',' '))}
 }
 $addrs=@($addrs|Select-Object -Unique|Select-Object -First 8)
 if($addrs.Count -eq 0){Say 'No A records for www.youtube.com, SNI test skipped.';return}
 Say ("Addresses tested: "+($addrs -join ', '))
 $short={param($x)
  if($x.Tcp -ne 'OK'){return 'TCP-FAIL'}
  if($x.Tls -like 'OK*'){return 'OK'}
  if($x.Tls -like 'SERVER ANSWERED*'){return 'ANSWERED'}
  if($x.Tls -like 'RESET*'){return 'RESET'}
  if($x.Tls -like 'NO ANSWER*'){return 'NO-ANSWER'}
  return 'ERROR'}
 $answered={param($c) $c -eq 'OK' -or $c -eq 'ANSWERED'}
 $rows=@()
 foreach($ip in $addrs){
  $r=@{}
  foreach($sni in 'www.youtube.com','www.google.com','example.com'){
   $r[$sni]=Test-TlsSni $ip $sni 443 5000
   Say ("  $ip SNI=$sni : tcp $($r[$sni].Tcp) ($($r[$sni].TcpMs) ms); tls $($r[$sni].Tls)")
  }
  $yt=& $short $r['www.youtube.com'];$gg=& $short $r['www.google.com'];$ex=& $short $r['example.com']
  $verdict=if($yt -eq 'TCP-FAIL'){'TCP blocked at IP/port level (not an SNI verdict)'}
           elseif(& $answered $yt){'server answers for www.youtube.com: no block at this layer'}
           elseif((& $answered $gg) -or (& $answered $ex)){'SNI BLOCKING LIKELY: another SNI is answered, youtube is not'}
           else{'data after the handshake is dropped for this IP (IP-level), not SNI-specific'}
  $rows+=[pscustomobject]@{IP=$ip;TCP=$r['www.youtube.com'].Tcp;'SNI youtube'=$yt;'SNI google (control)'=$gg;'SNI example (foreign)'=$ex;Verdict=$verdict}
 }
 Say ''
 Say 'Verdict table (OK/ANSWERED = server replied to the ClientHello; NO-ANSWER = silence; RESET = connection reset):'
 foreach($line in ($rows|Format-Table -AutoSize -Wrap|Out-String -Width 220).Split("`n")){if($line.Trim()){Say ("  "+$line.TrimEnd())}}
}}

function Write-TlsWireEvidence($snapshot,[string]$lane) {
 $instrumented=$false
 Say ($lane+' TLS scope: client_written=accepted upstream Write; origin_read=before delivery; no proof of HTTP success or remote receipt. Prefix masks payload with xx; 5 bytes alone are NOT a complete TLS alert.')
 foreach($r in @(Prop $snapshot 'records' @())|Select-Object -First 48){
  $attempts=Prop $r 'origin_attempts'
  if($null -ne $attempts){
   $tried=@(Prop $attempts 'attempts' @())|Select-Object -First 3
   $summary=@($tried|ForEach-Object{([string](Prop $_ 'destination'))+':'+(Prop $_ 'reason')}) -join ','
   Say ($lane+' origin IP recovery: domain='+(Prop $r 'domain')+' addresses_tried='+(Prop $attempts 'addresses_tried' 0)+' selected='+(Prop $attempts 'selected')+' negative_skips='+(Prop $attempts 'negative_cache_skips' 0)+' dns='+(Prop $attempts 'dns')+' replayed_client_hello_bytes='+(Prop $attempts 'client_hello_replayed_bytes' 0)+' state='+(Prop $attempts 'state')+' attempts='+$summary+' (transport evidence, not TLS/HTTP PASS)')
  }
  $dns=Prop (Prop $r 'plan') 'dns_recovery'
  if($null -ne $dns){$origin=Prop $dns 'origin';Say ($lane+' DNS recovery: domain='+(Prop $r 'domain')+' destination='+(Prop $dns 'destination')+' address_verified='+(Prop $dns 'address_verified' (Prop $dns 'verified' $false))+' http_probe_success='+(Prop $dns 'verified' $false)+' http_status='+(Prop $origin 'http_status' 0)+' phase='+(Prop $origin 'phase')+' failure='+(Prop $dns 'failure')+' expires='+(Prop $dns 'expires')+' (address proof != page/video PASS)')}
  $wire=Prop $r 'tls_wire'
  if($null -eq $wire){continue}
  $instrumented=$true
  foreach($side in @('client_written','origin_read')){
   $m=Prop $wire $side
   $records=@(Prop $m 'records' @())|Select-Object -First 8
   $framing=@($records|ForEach-Object{('type='+(Prop $_ 'type' 0)+':len='+(Prop $_ 'payload_length' 0)+':complete='+(Prop $_ 'complete' $false))}) -join ','
   $prefix=[string](Prop $m 'first_16_hex_masked' '')
   if($prefix -notmatch '^(?:[0-9a-f]{2}|xx){0,16}$'){$prefix='INVALID_REDACTED'}
   Say ($lane+' TLS: id='+(Prop $r 'id' 0)+' domain='+(Prop $r 'domain')+' destination='+(Prop (Prop $r 'plan') 'destination' (Prop $r 'upstream_destination'))+' side='+$side+' bytes='+(Prop $m 'bytes' 0)+' state='+(Prop $m 'state' 'UNINSTRUMENTED')+' server_hello_complete='+(Prop $m 'server_hello_complete' $false)+' hello_bytes='+(Prop $m 'client_hello_handshake_bytes' 0)+' records='+$framing+' first16_masked='+$prefix+' alert_level='+(Prop $m 'alert_level' 0)+' alert_description='+(Prop $m 'alert_description' 0)+' bounded='+(Prop $m 'bounded' $false))
  }
 }
 if(!$instrumented){Say ($lane+' TLS: NO_INSTRUMENTED_FLOW (old service or no fresh TLS flow); old bytes are not reconstructed')}
}

function Write-BrowserPathEvidence($snapshot,[string]$lane) {
 $silent=Prop $snapshot 'silent_activation' $null
 if($null -ne $silent){Say ($lane+' silent PAC: state='+(Prop $silent 'state' 'UNKNOWN')+' configured_profiles='+(@(Prop $silent 'configured_profiles' @()).Count)+' applied_at='+(Prop $silent 'applied_at' 'NOT_OBSERVED')+' first_request_at='+(Prop $silent 'first_request_at' 'NOT_OBSERVED')+' apply_to_request_ms='+(Prop $silent 'apply_to_request_ms' -1)+' requests='+(Prop $silent 'observed_requests' 0)+' existing_tcp=PINNED_UNTIL_CLOSED');Say 'Registry policy configured != effective browser proxy proof; pending may apply on next browser launch. No browser closed/restarted; page PASS not inferred.'}
 Write-TlsWireEvidence $snapshot ($lane+'.PAC')
 try{$timing=Invoke-IPC ($lane+'.first-byte');Write-BrowserFirstByteEvidence $timing $lane}catch{Say ($lane+' first-byte: UNAVAILABLE (old service or IPC failure); no latency invented')}
 Say ($lane+' path='+(Prop $snapshot 'path' 'PAC_LEGACY_UNINSTRUMENTED')+' metrics_lost='+(Prop $snapshot 'metrics_lost' 0)+' failure_details_lost='+(Prop $snapshot 'failure_details_lost' 0))
 foreach($m in @(Prop $snapshot 'path_metrics' @())) {
  $opened=[long](Prop $m 'opened' 0)
  $observation=if($opened -gt 0){'PAC_TUNNEL_OBSERVED'}else{'NO_NEW_PAC_TUNNEL_OBSERVED'}
  Say ($lane+' PAC timing: profile='+(Prop $m 'profile_id')+' state='+$observation+' accepted='+(Prop $m 'accepted' 0)+' opened='+$opened+' failed='+(Prop $m 'failed' 0)+' active='+(Prop $m 'active' 0)+' first_open='+(Prop $m 'first_tunnel_opened_at' 'NOT_OBSERVED')+' listen_to_first_open_ms='+(Prop $m 'listen_to_first_open_ms' -1)+' first_exchange='+(Prop $m 'first_bidirectional_exchange_at' 'NOT_OBSERVED')+' tx='+(Prop $m 'sent_bytes' 0)+' rx='+(Prop $m 'received_bytes' 0))
 }
 foreach($f in @(Prop $snapshot 'failure_details' @())|Sort-Object -Property count -Descending|Select-Object -First 48) {
  Say ($lane+' origin failure: profile='+(Prop $f 'profile_id')+' domain='+(Prop $f 'domain')+' stage='+(Prop $f 'phase')+' reason='+(Prop $f 'reason')+' route='+(Prop $f 'route' 'UNKNOWN')+' destination='+(Prop $f 'destination' 'UNKNOWN')+' policy_source='+(Prop $f 'policy_source' 'UNKNOWN')+' count='+(Prop $f 'count')+' last='+(Prop $f 'last_at'))
 }
 Say 'PAC OPEN means CONNECT/upstream-handoff accepted; actual native OPEN is separate. One PAC ingress may feed one PAC_NATIVE_UPSTREAM: do not sum them as independent application requests. No bytes/probe result alone proves page load.'
}

function Write-BrowserFirstByteEvidence($snapshot,[string]$lane) {
 $property=if($null -ne $snapshot){$snapshot.PSObject.Properties['first_byte_metrics']}else{$null}
 if($null -eq $property){Say ($lane+' first-byte: UNINSTRUMENTED (old service); no before/after latency invented');return}
 $rows=@($property.Value)
 if($rows.Count -eq 0){Say ($lane+' first-byte: NO_SAMPLES')}
 Say ($lane+' first-byte scope: proxy TCP accept -> first delivered origin byte (including TLS); not HTTP/page load; PAC_NATIVE_UPSTREAM is not a second sample; lost='+(Prop $snapshot 'first_byte_metrics_lost' 0)+' rows_omitted='+(Prop $snapshot 'first_byte_rows_omitted' 0)+' truncated='+(Prop $snapshot 'truncated' $false))
 Say 'no-reply scope: first observed I/O termination before local cleanup; client EOF can be a half-close. No request payload is only a preconnect candidate, not proof of success or harmless cancellation. Old totals cannot be retrospectively classified.'
 $pairs=@{}
 foreach($metric in @($rows)){
  $samples=[long](Prop $metric 'replies' 0)
  $avg=if($samples -gt 0){[Math]::Round(([double](Prop $metric 'total_ms' 0)/$samples),2)}else{'NOT_OBSERVED'}
  $mode=[string](Prop $metric 'mode' 'UNINSTRUMENTED')
  Say ($lane+' first-byte: network='+(Prop $metric 'network')+' profile='+(Prop $metric 'profile_id')+' group='+(Prop $metric 'group')+' port='+(Prop $metric 'port' 0)+' path='+(Prop $metric 'path')+' mode='+$mode+' n='+$samples+' no_reply='+(Prop $metric 'closed_without_reply' 0)+' avg_ms='+$avg+' min_ms='+(Prop $metric 'min_ms' -1)+' max_ms='+(Prop $metric 'max_ms' -1)+' last_ms='+(Prop $metric 'last_ms' -1))
  $noReply=[long](Prop $metric 'closed_without_reply' 0)
  $causes=Prop $metric 'no_reply_reasons'
  $parts=@();$classified=[long]0
  # Fixed vocabulary only; never dump arbitrary properties/errors or infer preconnect PASS.
  foreach($reason in @('CLIENT_CLOSED_BEFORE_REQUEST','CLIENT_CLOSED_BEFORE_REPLY','CLIENT_INPUT_ERROR','CLIENT_DELIVERY_ERROR','TIMEOUT','UPSTREAM_EOF','UPSTREAM_EOF_WITHOUT_REQUEST','UPSTREAM_ERROR','ORIGIN_DNS_FAILED','GOOGLEVIDEO_ADMISSION','OPAQUE_GOOGLE_ADMISSION','SERVICE_STOP','LOCAL_CANCELLED_OR_CLOSED','POLICY_OR_PLAN_FAILED','UNCLASSIFIED')){
   $reasonProperty=if($null -ne $causes){$causes.PSObject.Properties[$reason]}else{$null}
   $count=if($null -ne $reasonProperty){[long]$reasonProperty.Value}else{[long]0}
   if($count -gt 0){$parts+=@($reason+'='+$count);$classified+=$count}
  }
  if($classified -lt $noReply){$parts+=@('UNCLASSIFIED_LEGACY='+($noReply-$classified))}
  if($classified -gt $noReply){$parts+=@('INVALID_REASON_TOTAL')}
  Say ($lane+' no-reply: group='+(Prop $metric 'group')+' mode='+$mode+' reasons='+($parts -join ',')+' without_request_payload='+(Prop $metric 'no_reply_without_request_payload' 'UNKNOWN')+' with_request_payload='+(Prop $metric 'no_reply_with_request_payload' 'UNKNOWN')+' origin_payload_seen='+(Prop $metric 'no_reply_origin_payload_seen' 'UNKNOWN'))
  $key=([string](Prop $metric 'network'))+'|'+(Prop $metric 'profile_id')+'|'+(Prop $metric 'group')+'|'+(Prop $metric 'path')+'|'+(Prop $metric 'port' 0)
  if(!$pairs.ContainsKey($key)){$pairs[$key]=@{}}
  if($samples -gt 0){$pairs[$key][$mode]=$avg}
 }
 foreach($key in @($pairs.Keys|Sort-Object)){
  $before=if($pairs[$key].ContainsKey('DIRECT_FIRST')){$pairs[$key]['DIRECT_FIRST']}else{'NOT_OBSERVED'}
  $after=if($pairs[$key].ContainsKey('RELAY_FIRST')){$pairs[$key]['RELAY_FIRST']}else{'NOT_OBSERVED'}
  Say ($lane+' first-byte comparison '+$key+': before_direct_first_avg_ms='+$before+' after_relay_first_avg_ms='+$after+' (observed connections; not a controlled ISP A/B test)')
 }
}

function Write-BrowserDNSEvidence($native) {
 $dns=Prop $native 'browser_dns'
 if($null -eq $dns){Say 'browser DNS broker: UNINSTRUMENTED'}else{
  Say ('browser DNS broker: scope='+(Prop $dns 'scope')+' queries='+(Prop $dns 'queries' 0)+' relay_https_doh='+(Prop $dns 'relay_doh' 0)+' original_resolver='+(Prop $dns 'system_dns' 0)+' failed='+(Prop $dns 'failed' 0)+' active='+(Prop $dns 'active' 0)+'/'+(Prop $dns 'max_active' 0))
  Say ('browser Secure DNS: '+(Prop $dns 'secure_dns_policy')+'; encrypted_answers='+(Prop $dns 'encrypted_answers'))
  foreach($r in @(Prop $dns 'records' @())|Select-Object -Last 16){
   Say ('browser DNS query: profile='+(Prop $r 'profile_id')+' domain='+(Prop $r 'domain')+' qtype='+(Prop $r 'query_type')+' path='+(Prop $r 'path')+' result='+(Prop $r 'result')+' hinted_addresses='+(Prop $r 'addresses' 0))
  }
 }
 $cache=Prop $native 'domain_cache'
 Say ('browser DNS hints: active_addresses='+(Prop $cache 'browser_scoped_addresses' 0)+' omitted='+(Prop $cache 'browser_scoped_hints_omitted' 0)+' opaque_failed_endpoints='+(Prop $cache 'opaque_direct_failed_endpoints' 0)+' TLS_budget_ms='+(Prop $cache 'native_first_tls_reply_budget_ms' 'UNINSTRUMENTED')+' Google_failure_hits='+(Prop $cache 'google_failure_group_hits' 0))
 foreach($h in @(Prop $cache 'browser_scoped_hints' @())|Select-Object -First 16){
  Say ('browser DNS hint: network='+(Prop $h 'network')+' profile='+(Prop $h 'profile_id')+' address='+(Prop $h 'address')+' domain='+(Prop $h 'domain')+' expires='+(Prop $h 'expires'))
 }
 foreach($g in @(Prop $cache 'google_failure_groups' @())|Select-Object -First 16){
  Say ('opaque Google recovery: network='+(Prop $g 'network')+' profile='+(Prop $g 'profile_id')+' state='+(Prop $g 'state')+' distinct_failures='+(Prop $g 'distinct_failed_addresses' 0)+' first_address='+(Prop $g 'first_address')+' until='+(Prop $g 'until')+' failure='+(Prop $g 'last_failure'))
 }
 $usage=Prop $native 'relay_usage'
 Say ('browser relay admission: scope='+(Prop $usage 'admission_scope' 'LEGACY_SHARED_GOOGLE_VIDEO')+' known_googlevideo='+(Prop $usage 'googlevideo_active_tunnels' 0)+'/'+(Prop $usage 'googlevideo_tunnel_limit' 0)+' opaque_google='+(Prop $usage 'opaque_google_active_tunnels' 0)+'/'+(Prop $usage 'opaque_google_tunnel_limit' 'UNKNOWN')+' total='+(Prop $usage 'google_admission_total_active' (Prop $usage 'googlevideo_shared_limit_active' 'UNKNOWN'))+' video_waiters='+(Prop $usage 'googlevideo_waiters' 0)+' opaque_waiters='+(Prop $usage 'opaque_google_waiters' 'UNINSTRUMENTED'))
 Say ('browser video admission: failures='+(Prop $usage 'googlevideo_admission_failures' 0)+' canceled='+(Prop $usage 'googlevideo_admission_canceled' 'UNINSTRUMENTED')+' waited='+(Prop $usage 'googlevideo_waited' 'UNINSTRUMENTED')+' wait_total_ms='+(Prop $usage 'googlevideo_wait_total_ms' 'UNINSTRUMENTED')+' wait_max_ms='+(Prop $usage 'googlevideo_wait_max_ms' 'UNINSTRUMENTED')+' idle_closed='+(Prop $usage 'googlevideo_idle_closed' 'UNINSTRUMENTED'))
 Say ('browser other Google admission: failures='+(Prop $usage 'opaque_google_admission_failures' 'UNINSTRUMENTED')+' canceled='+(Prop $usage 'opaque_google_admission_canceled' 'UNINSTRUMENTED')+' idle_closed='+(Prop $usage 'opaque_google_idle_closed' 'UNINSTRUMENTED')+' ordinary_capacity_direct_fallback_attempts='+(Prop $usage 'ordinary_capacity_direct_fallbacks' 'UNINSTRUMENTED')+' (ordinary fallback is a NEW DIRECT plan before payload, never hidden RELAY_REQUIRED bytes)')
 $videoProperty=if($null -ne $usage){$usage.PSObject.Properties['video_connections']}else{$null}
 if($null -eq $videoProperty){Say 'video performance: UNINSTRUMENTED'}else{
  Say ('video performance scope='+(Prop $usage 'video_performance_scope' 'UNKNOWN')+' omitted='+(Prop $usage 'video_connections_omitted' 0))
  foreach($v in @($videoProperty.Value)){
   Say ('video connection: id='+(Prop $v 'id')+' profile='+(Prop $v 'profile_id')+' domain='+(Prop $v 'domain')+' destination='+(Prop $v 'destination')+' ingress='+(Prop $v 'ingress')+' state='+(Prop $v 'state')+' admission_ms='+(Prop $v 'admission_ms' -1)+' relay_open_ms='+(Prop $v 'relay_open_ms' -1)+' first_byte_ms='+(Prop $v 'first_byte_ms' -1)+' write_to_first_byte_ms='+(Prop $v 'write_to_first_byte_ms' -1)+' average_rx_mbps='+(Prop $v 'average_receive_mbps' -1)+' receive_span_mbps='+(Prop $v 'receive_span_mbps' -1)+' max_read_gap_ms='+(Prop $v 'max_read_gap_ms' -1)+' rx='+(Prop $v 'received_bytes' 0)+' tx='+(Prop $v 'sent_bytes' 0))
  }
 }
 Say 'DNS hints are not authenticated inner SNI. Transit DoH answers and svchost caller are not observed. Opaque Google is not a proven googlevideo hostname; no DNS53-to-relay, no page/video PASS inferred.'
}

function Write-RelayOpenPerformance($pool) {
 $creation=Prop $pool 'session_creation'
 Say ('relay sessions60s: attempts='+(Prop $creation 'Attempts60s' 'UNINSTRUMENTED')+' created='+(Prop $creation 'NewSessions60s' 'UNINSTRUMENTED')+' max_attempts='+(Prop $creation 'MaxAttempts60s' 'UNINSTRUMENTED')+' max_created='+(Prop $creation 'MaxNewSessions60s' 'UNINSTRUMENTED')+' creating='+(Prop $creation 'Concurrent' 'UNINSTRUMENTED')+' max_concurrent='+(Prop $creation 'MaxConcurrent' 'UNINSTRUMENTED'))
 foreach($event in @(Prop $creation 'Recent' @())|Select-Object -Last 16){Say (' session creation: at='+(Prop $event 'at')+' reason='+(Prop $event 'reason')+' success='+(Prop $event 'success')+' factory_ms='+(Prop $event 'factory_ms' -1)+' QUIC_handshake_ms='+(Prop $event 'quic_handshake_ms' -1))}
 Say ('session window: '+(Prop $creation 'Window' 'UNINSTRUMENTED')+'; successful handshake only; no SNI/parallelism DPI verdict from counts')
 Say ('relay OPEN: active_sessions='+(Prop $pool 'active_sessions' 'UNINSTRUMENTED')+' waiting='+(Prop $pool 'waiting_opens' 'UNINSTRUMENTED')+' failures='+(Prop $pool 'open_failures' 'UNINSTRUMENTED'))
 foreach($v in @(Prop $pool 'recent_opens' @())|Select-Object -Last 16){
  Say ('relay OPEN sample: session='+(Prop $v 'session_id')+' protocol='+(Prop $v 'protocol')+' destination='+(Prop $v 'destination')+' total_ms='+(Prop $v 'duration_ms' -1)+' acquire_ms='+(Prop $v 'acquire_ms' 'UNINSTRUMENTED')+' stream_origin_open_ms='+(Prop $v 'stream_open_ms' 'UNINSTRUMENTED')+' session_age_ms='+(Prop $v 'session_age_ms' 'UNINSTRUMENTED')+' failure='+(Prop $v 'failure_reason' 'NONE'))
 }
 Say 'acquire includes pool wait/new mTLS+ticket session; stream_origin_open includes OPEN wire round trip and VPS TCP connect, not separate origin TLS. Existing QUIC sessions are reused; application TCP/TLS streams are never pooled across browser sockets.'
}

function Write-TrafficEvidence($traffic) {
 if($null -eq $traffic){Say 'Relay traffic: UNINSTRUMENTED; monthly usage UNKNOWN';return}
 $client=Prop $traffic 'client';$server=Prop $traffic 'server'
 Say ('Relay traffic client: state='+(Prop $client 'state')+' session_sent='+(Prop (Prop $client 'SessionTotal') 'Sent' 0)+' session_received='+(Prop (Prop $client 'SessionTotal') 'Received' 0)+' day_sent='+(Prop (Prop $client 'DayTotal') 'Sent' 0)+' day_received='+(Prop (Prop $client 'DayTotal') 'Received' 0)+' omitted='+(Prop $client 'DaysOmitted' 0)+' error='+(Prop $client 'error' '')+' scope='+(Prop $client 'scope'))
 foreach($row in @(Prop $client 'days' @())){Say (' relay day='+(Prop $row 'day_utc')+' profile='+(Prop $row 'profile')+' service='+(Prop $row 'service')+' subgroup='+(Prop $row 'subgroup')+' reason='+(Prop $row 'reason')+' logical_relay='+(Prop $row 'logical_relay')+' tx='+(Prop $row 'Sent' 0)+' rx='+(Prop $row 'Received' 0))}
 Say ('Relay traffic server: state='+(Prop $server 'state')+' checked='+(Prop $server 'checked')+' error='+(Prop $server 'error' '')+' scope='+(Prop $server 'scope'))
 foreach($row in @(Prop $server 'relays' @())){Say (' relay month: id='+(Prop $row 'relay')+' month='+(Prop $row 'month_utc')+' known_bytes='+(Prop $row 'known_egress_bytes' 0)+' limit_bytes='+(Prop $row 'monthly_limit_bytes' 0)+' forecast_valid='+(Prop $row 'forecast_valid' $false)+' forecast_bytes='+(Prop $row 'forecast_bytes' 0)+' known_from='+(Prop $row 'known_from')+' partial='+(Prop $row 'partial_coverage' $true)+' warning='+(Prop $row 'warning'))}
 Say 'Month is sampled NIC egress, not provider invoice. Partial/missing coverage is never unused quota; client bytes exclude transport overhead.'
}

function Write-LocalCatalogEvidence($catalog) {
 if($null -eq $catalog){Say 'local catalog: UNINSTRUMENTED';return}
 Say ('local catalog: source='+(Prop $catalog 'source')+' version='+(Prop $catalog 'version' 0)+' schema='+(Prop $catalog 'schema')+' rules='+(Prop $catalog 'rules' 0)+' unsupported='+(Prop $catalog 'unsupported' 0)+' available_plans='+@(Prop $catalog 'plans' @()).Count+' checked='+(Prop $catalog 'last_check')+' error='+(Prop $catalog 'error' '')+' activation='+(Prop $catalog 'activation'))
 foreach($plan in @(Prop $catalog 'plans' @()) | Select-Object -First 48){Say (' catalog plan='+(Prop $plan 'ID')+' source='+(Prop $plan 'source')+' rule='+(Prop $plan 'rule')+' adaptation='+(Prop $plan 'adaptation'))}
 Say ('Origin policy data: version='+(Prop $catalog 'origin_version' 0)+' groups='+(Prop $catalog 'origin_rules' 0)+' immutable RELAY floors retained; ordinary origins DIRECT')
 Say 'Catalog availability/signature is NOT local bypass confirmation; unsupported modes are never executed.'
}

function Write-CdnTrialEvidence($ladder) {
 if($null -eq $ladder -or -not $ladder.PSObject.Properties['trials']){Say 'CDN trial evidence: UNINSTRUMENTED (service update required)';return}
 $trialRows=@(Prop $ladder 'trials' @() | Where-Object {$null -ne $_})
 if($trialRows.Count -eq 0){Say 'CDN trial evidence: NO_RECORDED_TRIAL'}
 Say 'CDN LOCAL probes: host | subgroup | strategy | result | tx/rx | close/timing | sibling at admission'
 foreach($trial in $trialRows){
  $p=Prop $trial 'Packets';$t=Prop $trial 'Timing';$peer=Prop $trial 'Sibling'
  Say (' CDN trial: host='+(Prop $trial 'Host')+' subgroup='+(Prop $trial 'Subgroup')+' strategy='+(Prop $trial 'Strategy')+' trial_result='+(Prop $trial 'TrialResult')+' data_trial='+(Prop $trial 'DataTrial' $false)+' active='+(Prop $trial 'Active' $false)+' tx='+(Prop $trial 'TX' 0)+' rx='+(Prop $trial 'RX' 0)+' reason='+(Prop $trial 'Reason')+' io='+(Prop $trial 'IOFailure')+' first='+(Prop $p 'first_close' 'NOT_OBSERVED')+' client_fin='+(Prop $p 'ClientFIN' 0)+' remote_fin='+(Prop $p 'RemoteFIN' 0)+' client_rst='+(Prop $p 'ClientRST' 0)+' remote_rst='+(Prop $p 'RemoteRST' 0)+' client_retransmits='+(Prop $p 'ClientRetransmits' 0)+' remote_retransmits='+(Prop $p 'RemoteRetransmits' 0)+' hello_to_close_ms='+(Prop $t 'hello_to_close_ms' -1)+' last_rx_to_close_ms='+(Prop $t 'last_rx_to_close_ms' -1)+' sibling_reason='+(Prop $peer 'Reason' 'UNKNOWN')+' sibling_age_at_admission_ms='+(Prop $peer 'AgeMS' -1)+' sibling_last_rx='+(Prop $peer 'LastRX' '')+' media_host='+(Prop $peer 'MediaHost' '')+' media_rx='+(Prop $peer 'MediaBytes' 0)+' media_age_ms='+(Prop $peer 'MediaAgeMS' -1)+' media_match='+(Prop $peer 'MediaMatch' '')+' trial_id='+(Prop $trial 'trial_id' 'UNINSTRUMENTED')+' record_id='+(Prop $trial 'ID' 'UNINSTRUMENTED')+' slot_active='+(Prop $trial 'slot_active' 'UNINSTRUMENTED')+' slot_released_at='+(Prop $trial 'slot_released_at' '')+' slot_release_reason='+(Prop $trial 'slot_release_reason' '')+' neutral_short_attempt='+(Prop $trial 'neutral_short_attempt' 'UNINSTRUMENTED')+' cooldown_until='+(Prop $trial 'cooldown_until' ''))
 }
 foreach($bad in @(Prop $ladder 'cdn_endpoint_negatives' @()) | Where-Object {$null -ne $_}){Say (' CDN endpoint negative: host='+(Prop $bad 'Host')+' address='+(Prop $bad 'Address')+' strategy='+(Prop $bad 'Strategy')+' until='+(Prop $bad 'Until')+' reason='+(Prop $bad 'Reason')+' scope=network/profile/host/IP/strategy; not subgroup proof')}
 Say 'Media admission requires >1MiB recent RELAY RX on the same host/subgroup, plus the existing sibling guard; rrN is never a segment classifier.'
 Say 'Trials counts LOCAL probe exposures; data_trials counts >=64KiB completed TLS type23 bytes plus ServerHello/post-hello write/transform. Expected reply size and HTTP redirect/segment are UNKNOWN_ENCRYPTED; rrN is not a classifier.'
 Say 'Sibling history: same network/profile, googlevideo media, recent RX <=30s including closed tunnels; same subgroup preferred. It does NOT guarantee a concurrent playable relay segment. Max1 unproven trial; up to 3 neutral short probes/subgroup without 3min wait, then >=3min cooldown. Real failure retains cooldown.'
}

function Write-OrdinaryAddressEvidence($ladder) {
 if($null -eq $ladder -or -not $ladder.PSObject.Properties['ordinary']){Say 'Ordinary address retries: UNINSTRUMENTED (service update required)';return}
 $rows=@(Prop $ladder 'ordinary' @() | Where-Object {$null -ne $_})
 if($rows.Count -eq 0){if((Prop $ladder 'ordinary_retained' 0) -gt 0){Say ('Ordinary address retries: OMITTED_BY_IPC_BUDGET retained='+(Prop $ladder 'ordinary_retained' 0))}else{Say 'Ordinary address retries: NONE_RECORDED; healthy ordinary origins stay DIRECT, see native records'}}
 Say ('Ordinary DNS DIRECT attempts='+(Prop $ladder 'ordinary_dns_direct_attempts' 'UNINSTRUMENTED')+' scope_denials='+(Prop $ladder 'ordinary_scope_denials' 'UNINSTRUMENTED')+'; capacity fallback counter is a separate path')
 Say ('Ordinary retries: retained='+(Prop $ladder 'ordinary_retained' $rows.Count)+' omitted='+(Prop $ladder 'ordinary_omitted' 0)+'; host | profile | stage/reason | DNS address | TCP/TLS first flight | tx/rx')
 foreach($row in $rows | Select-Object -Last 16){
  Say (' ordinary host='+(Prop $row 'Host')+' profile='+(Prop $row 'Profile')+' stage='+(Prop $row 'Stage')+' reason='+(Prop $row 'Reason')+' dns='+(Prop $row 'DNS'))
  foreach($address in @(Prop $row 'Addresses' @()) | Select-Object -First 4){
   Say ('  ordinary address='+(Prop $address 'Address')+' stage='+(Prop $address 'Stage')+' first_flight='+(Prop $address 'Result')+' tx='+(Prop $address 'TX' 0)+' rx='+(Prop $address 'RX' 0))
  }
 }
 foreach($flow in @(Prop $ladder 'ordinary_ladder' @()) | Where-Object {$null -ne $_}){
  Say (' ordinary ladder: record_id='+(Prop $flow 'id')+' host='+(Prop $flow 'domain')+' destination='+(Prop $flow 'destination')+' stage='+(Prop $flow 'stage')+' reason='+(Prop $flow 'reason')+' io='+(Prop $flow 'io_failure' '')+' tx='+(Prop $flow 'TX' 0)+' rx='+(Prop $flow 'RX' 0)+' profile='+(Prop $flow 'profile' ''))
 }
 Say 'A timeout/reset does not classify IP, GEO or DPI filtering. No network-wide/subnet verdict is inferred; HTTP/GEO response is encrypted.'
 Say 'Ordinary: at most two public DNS IPv4; per-network/profile/host/IP negative TTL10min; no subnet inference. TLS ServerHello is not HTTP/page proof; any origin byte forbids replay.'
}

function Write-LocalProbeEvidence($ladder) {
 $audit=Prop $ladder 'layer_audit'
 Say ('LOCAL layer audit: retained='+(Prop $audit 'RetainedFlows' 'UNINSTRUMENTED')+' pure_ts='+(Prop $audit 'PureTS' 'UNINSTRUMENTED')+' missing_payload_ts='+(Prop $audit 'PureTSMissingPayloadTimestamp' 'UNINSTRUMENTED')+' negotiation_unknown='+(Prop $audit 'PureTSNegotiationUnknown' 'UNINSTRUMENTED')+' not_negotiated='+(Prop $audit 'PureTSNotNegotiated' 'UNINSTRUMENTED')+' timestamp_option_required='+(Prop $audit 'TimestampOptionRequired' 'UNINSTRUMENTED')+' timestamp_required_probes='+(Prop $audit 'TimestampOptionRequiredProbes' 'UNINSTRUMENTED')+' inspection_unknown='+(Prop $audit 'InspectionUnavailable' 'UNINSTRUMENTED')+' pure_ts_inspection_unknown='+(Prop $audit 'PureTSInspectionUnavailable' 'UNINSTRUMENTED')+' plan_unknown='+(Prop $audit 'PlanUnavailable' 'UNINSTRUMENTED')+' early_retrans_candidates='+(Prop $audit 'EarlyRetransmitCandidates' 'UNINSTRUMENTED')+' small_RST_candidates='+(Prop $audit 'SmallRSTCandidates' 'UNINSTRUMENTED')+' late_after_reply='+(Prop $audit 'LateFailuresAfterReply' 'UNINSTRUMENTED')+' freeze_wire_16_20KiB='+(Prop $audit 'Freeze16To20KiB' 'UNINSTRUMENTED'))
 Say ('audit scope: '+(Prop $audit 'Scope' 'UNINSTRUMENTED'))
 Write-CdnTrialEvidence $ladder
 Write-OrdinaryAddressEvidence $ladder
 foreach($closed in @(Prop $ladder 'tcp_closures' @())){
  $t=Prop $closed 'Packets';$timing=Prop $closed 'Timing'
  Say (' LOCAL close: domain='+(Prop $closed 'Domain')+' strategy='+(Prop $closed 'Strategy')+' reason='+(Prop $closed 'Reason')+' io='+(Prop $closed 'IOFailure')+' tx='+(Prop $closed 'TX')+' rx='+(Prop $closed 'RX')+' first='+(Prop $t 'first_close' 'NOT_OBSERVED')+' flags='+(Prop $t 'first_close_flags' 0)+' first_ttl='+(Prop $t 'first_close_ttl' 0)+' client_fin='+(Prop $t 'ClientFIN' 0)+' client_rst='+(Prop $t 'ClientRST' 0)+' remote_fin='+(Prop $t 'RemoteFIN' 0)+' remote_rst='+(Prop $t 'RemoteRST' 0)+' synack_ttl='+(Prop $t 'SYNACKTTL' 0)+' remote_terminal_ttl='+(Prop $t 'RemoteTerminalTTL' 0)+' hello_to_close_ms='+(Prop $timing 'hello_to_close_ms' -1)+' last_rx_to_close_ms='+(Prop $timing 'last_rx_to_close_ms' -1)+' hello_to_server_hello_ms='+(Prop $timing 'hello_to_server_hello_ms' -1)+' rx_after_hello_observed='+(Prop $timing 'rx_after_server_hello_observed' 0)+' client_application_record='+(Prop $timing 'ClientApplicationRecord' $false)+' origin_application_record='+(Prop $timing 'OriginApplicationRecord' $false)+' application_records='+(Prop $timing 'ApplicationRecords' 0)+' application_bytes='+(Prop $timing 'ApplicationBytes' 0)+' application_span_ms='+(Prop $timing 'ApplicationSpanMS' 0)+' app_evidence_bounded='+(Prop $timing 'ApplicationEvidenceBounded' $false)+' half_close_requested='+(Prop $timing 'HalfCloseRequested' $false)+' open_ms='+(Prop $closed 'OpenMS' -1)+' transform_send_ms='+(Prop $closed 'TransformSendMS' -1)+' client_retransmits='+(Prop $t 'ClientRetransmits' 0)+' remote_retransmits='+(Prop $t 'RemoteRetransmits' 0)+' early_retransmits='+(Prop $t 'client_early_retransmits' 'UNKNOWN')+' rst_relative_known='+(Prop $t 'remote_rst_relative_known' $false)+' rst_relative='+(Prop $t 'remote_rst_relative' 'UNKNOWN'))
 }
 foreach($failure in @(Prop $ladder 'failures' @())){
  Say (' LOCAL failure: at='+(Prop $failure 'At')+' domain='+(Prop $failure 'Domain')+' strategy='+(Prop $failure 'Strategy')+' reason='+(Prop $failure 'Reason')+' tx='+(Prop $failure 'TX' 0)+' rx='+(Prop $failure 'RX' 0)+' hello_to_failure_ms='+(Prop $failure 'SinceClientHelloMS' -1)+' server_hello_to_failure_ms='+(Prop $failure 'SinceServerHelloMS' -1)+' last_rx_to_failure_ms='+(Prop $failure 'SinceLastRXMS' -1)+' rx_after_hello='+(Prop $failure 'ReceivedAfterHello' 0)+' application_records='+(Prop $failure 'ApplicationRecords' 0)+' promoted='+(Prop $failure 'Promoted' $false)+' post_hello_write='+(Prop $failure 'PostHelloWrite' $false))
 }
 Say 'MIDSTREAM_STALL closes the current socket after unanswered writes; the browser may retry/rebuffer. No replay/migration after any origin byte. Passive idle alone is not failure.'
 Say 'TLS type23 is an outer application record: TLS1.3 may carry encrypted handshake/alert. H2 GOAWAY, HTTP status and Chrome abort intent are NOT visible without MITM.'
 Say 'REMOTE_PACKET describes wire direction; a remote RST may be injected by a middlebox. TTL difference alone does not prove DPI.'

 Say 'LOCAL probes: service | host | strategy | result | wire_tx | wire_rx | body_rx | committed | inspection | sent packets(length/TTL/protocol)'
 foreach($probe in @(Prop $ladder 'probes' @())){
  $inspection=Prop $probe 'inspection'
  $actions=@(Prop $probe 'planned_actions' @() | ForEach-Object {$native=Prop $_ 'native_tcp';if($null -ne $native){'native:'+(Prop $native 'mode')+'/repeats='+(Prop $native 'repeats')+'/fooling='+(Prop $native 'fooling')+'/badseq_only_if_fooling_badseq='+(Prop $native 'bad_sequence')+'/badack_only_if_fooling_badseq='+(Prop $native 'bad_ack')+'/ts_delta='+(Prop $native 'timestamp_delta')}else{((Prop $_ 'kind')+'/ttl='+(Prop $_ 'ttl' 0)+'/repeats='+(Prop $_ 'repeats' 0)+'/fooling='+(Prop $_ 'fooling' ''))}}) -join ','
  Say (' planned (not wire proof): '+$actions)

  $packets=@(Prop $inspection 'sent_packets' @() | ForEach-Object {('fake='+(Prop $_ 'fake' $false)+'/len='+(Prop $_ 'length')+'/ttl='+(Prop $_ 'ttl')+'/proto='+(Prop $_ 'protocol')+'/seq_delta='+(Prop $_ 'sequence_offset')+'/flags='+(Prop $_ 'tcp_flags')+'/ack_delta='+(Prop $_ 'ack_offset' 0)+'/ts='+(Prop $_ 'timestamp_present' $false)+'/ts_delta='+(Prop $_ 'timestamp_delta' 0)+'/md5='+(Prop $_ 'md5_present' $false))}) -join ','
  Say ((Prop $probe 'service')+' | '+(Prop $probe 'host')+' | '+(Prop $probe 'strategy')+' | '+(Prop $probe 'result')+'/failure='+(Prop $probe 'failure' '')+'/http='+(Prop $probe 'http_status' 0)+' | '+(Prop $probe 'sent_bytes' 0)+' | '+(Prop $probe 'received_bytes' 0)+' | '+(Prop $probe 'body_bytes' 0)+' | '+(Prop $probe 'committed' $false)+' | '+(Prop $inspection 'reason' 'NO_LEDGER_OBSERVATION')+' '+(Prop $inspection 'detail' '')+' syn='+(Prop $inspection 'syn_seen' 'UNKNOWN')+' handshake='+(Prop $inspection 'handshake_confirmed' 'UNKNOWN')+' server_ttl='+(Prop $inspection 'server_ttl' 'UNKNOWN')+' transform_send_ms='+(Prop $inspection 'transform_send_ms' -1)+' reassembly_ms='+(Prop $inspection 'reassembly_ms' -1)+' original_packet_bytes='+(Prop $inspection 'original_packet_bytes' 'UNKNOWN')+' tcp_header='+(Prop $inspection 'tcp_header_bytes' 'UNKNOWN')+' timestamp_option='+(Prop $inspection 'timestamp_option' 'UNKNOWN')+' | '+$packets)
 }

}

function Write-YouTubeLocalEvidence($ladder) {
 if($null -eq $ladder){Say 'YouTube local ladder: UNINSTRUMENTED (service update required)';return}
 Say ('YouTube local ladder: cache_entries='+(Prop $ladder 'cache_entries' 0)+' recent_records_omitted='+(Prop $ladder 'records_omitted' 0)+' cache_entries_omitted='+(Prop $ladder 'cache_entries_omitted' 0)+' contract='+(Prop $ladder 'replay_contract' 'UNKNOWN'))
 $shared=Prop $ladder 'shared_learning'
 if($null -ne $shared){
  Say ('LOCAL shared learning: state='+(Prop $shared 'state')+' checked='+(Prop $shared 'last_check')+' error='+(Prop $shared 'last_error' '')+' scope='+(Prop $shared 'scope'))
  foreach($row in @(Prop $shared 'rows' @())){Say (' shared profile='+(Prop $row 'profile')+' group='+(Prop $row 'group')+' picker='+(Prop $row 'picker' $false)+' candidate='+(Prop $row 'candidate' '')+' state='+(Prop $row 'state')+' until='+(Prop $row 'until'))}
 }
 $selection=Prop $ladder 'selection'
 if($null -ne $selection){Say ('YouTube selection: background='+(Prop $selection 'BackgroundAttempts' 0)+' background_fail='+(Prop $selection 'BackgroundFailures' 0)+' trials='+(Prop $selection 'Trials' 0)+' trial_success='+(Prop $selection 'TrialSuccesses' 0)+' trial_fail='+(Prop $selection 'TrialFailures' 0)+' failed_after_reply='+(Prop $selection 'FailedAfterReply' 0)+' trial_inconclusive='+(Prop $selection 'TrialInconclusive' 0)+' client_initiated_trial_closes='+(Prop $selection 'ClientInitiatedTrialCloses' 0)+' strong_promotions='+(Prop $selection 'StrongPromotions' 0)+' post_promotion_failures='+(Prop $selection 'PostPromotionFailures' 0)+' small_eof_inconclusive='+(Prop $selection 'RemoteSmallEOFInconclusive' 0)+' burst_promotions='+(Prop $selection 'BurstPromotions' 'UNINSTRUMENTED')+' post_trial_failures='+(Prop $selection 'PostTrialFailures' 'UNINSTRUMENTED')+' data_trials='+(Prop $selection 'DataTrials' 'UNINSTRUMENTED')+' active='+(Prop $selection 'active_trial' $false)+' active_domain='+(Prop $selection 'active_domain' '')+' active_age_ms='+(Prop $selection 'active_age_ms' -1)+' active_last_rx_age_ms='+(Prop $selection 'active_last_rx_age_ms' -1)+' active_state='+(Prop $selection 'active_state' '')+' active_trial_id='+(Prop $selection 'active_trial_id' 'UNINSTRUMENTED')+' active_record_id='+(Prop $selection 'active_record_id' 'UNINSTRUMENTED')+' active_host='+(Prop $selection 'active_host' '')+' active_destination='+(Prop $selection 'active_destination' '')+' active_started_at='+(Prop $selection 'active_started_at' '')+' active_record_result='+(Prop $selection 'active_record_result' '')+' active_record_matches='+(Prop $selection 'active_record_matches' 'UNINSTRUMENTED')+' contract='+(Prop $selection 'contract'))}
 foreach($stage in @(Prop $ladder 'stages' @())){
  $helloSamples=[double](Prop $stage 'HelloSamples' 0);$helloAvg=if($helloSamples -gt 0){[math]::Round([double](Prop $stage 'HelloSumMS' 0)/$helloSamples,1)}else{-1}
  Say (' '+(Prop $stage 'service' 'youtube-media')+' stage='+(Prop $stage 'stage')+' strategy='+(Prop $stage 'strategy' '-')+' connections='+(Prop $stage 'Connections' 0)+' tx='+(Prop $stage 'TX' 0)+' rx='+(Prop $stage 'RX' 0)+' failures='+(Prop $stage 'Failures' 0)+' transport_confirmed='+(Prop $stage 'Confirmed' 0)+' inconclusive='+(Prop $stage 'Inconclusive' 0)+' hello_samples='+$helloSamples+' hello_avg_ms='+$helloAvg+' hello_max_ms='+(Prop $stage 'HelloMaxMS' -1))
 }
 foreach($entry in @(Prop $ladder 'cache' @())){
  $peer=Prop $entry 'Sibling'
  $peerReason='NOT_CHECKED';$peerAge=-1
  if((Prop $entry 'TrialChecks' 0) -gt 0){$peerReason=Prop (Prop $entry 'Sibling') 'Reason' 'UNKNOWN';$peerAge=Prop (Prop $entry 'Sibling') 'AgeMS' -1}
  Say (' youtube cache: profile='+(Prop $entry 'Profile')+' domain='+(Prop $entry 'Domain')+' hint_only='+(Prop $entry 'HintOnly' $false)+' stage='+(Prop $entry 'Stage')+' strategy='+(Prop $entry 'Strategy')+' until='+(Prop $entry 'Until')+' recheck='+(Prop $entry 'Retry')+' qualified='+(Prop $entry 'Qualified' '')+' trial_after='+(Prop $entry 'TrialAfter' '')+' admission='+(Prop $entry 'TrialAdmission' 'UNINSTRUMENTED')+' checks='+(Prop $entry 'TrialChecks' 0)+' denials='+(Prop $entry 'TrialDenials' 0)+' last_check='+(Prop $entry 'LastTrialCheck' '')+' streak='+(Prop $entry 'Streak' 0)+' neutral_short_streak='+(Prop $entry 'NeutralShortStreak' 'UNINSTRUMENTED')+' cooldown_wait_ms='+(Prop $entry 'CooldownWaitMS' 'UNINSTRUMENTED')+' slot_released_at='+(Prop $entry 'slot_released_at' '')+' slot_release_reason='+(Prop $entry 'slot_release_reason' '')+' sibling_waits='+(Prop $entry 'SiblingWaits' 0)+' sibling_reason='+$peerReason+' sibling_age_ms='+$peerAge+' media_host='+(Prop $peer 'MediaHost' '')+' media_rx='+(Prop $peer 'MediaBytes' 0)+' media_match='+(Prop $peer 'MediaMatch' '')+' reason='+(Prop $entry 'Reason'))
 }
 foreach($flow in @(Prop $ladder 'records' @())){
  Say (' youtube step #'+(Prop $flow 'id')+' profile='+(Prop $flow 'profile')+' service='+(Prop $flow 'service' 'youtube-media')+' domain='+(Prop $flow 'domain')+' destination='+(Prop $flow 'destination')+' stage='+(Prop $flow 'stage')+' strategy='+(Prop $flow 'strategy' '-')+' tx='+(Prop $flow 'TX' 0)+' rx='+(Prop $flow 'RX' 0)+' server_hello='+(Prop $flow 'ServerHello' $false)+' committed_transform_confirmed='+$(if(Prop $flow 'TransformKnown' $false){if(Prop $flow 'Transform' $false){'YES'}else{'NOT_CONFIRMED'}}else{'UNKNOWN_NOT_QUERIED'})+' trial_result='+(Prop $flow 'trial_result' '')+' reason='+(Prop $flow 'reason')+' io='+(Prop $flow 'io_failure' ''))
 }
 Say 'LOCAL bytes are real upstream bytes; transport_confirmed requires committed native transform and sustained TLS bytes, not playback PASS. DIRECT/LOCAL ClientHello traffic can precede a RELAY fallback. Existing TLS never moves after origin bytes.'
}

function Write-NativeIngressEvidence($native) {
 foreach($r in @(Prop (Prop $native 'youtube_local_ladder') 'records' @())){
  $hostName=[string](Prop $r 'domain' '');$address=[string](Prop $r 'destination' '')
  if($hostName -match '(^|\.)googlevideo\.com$' -and $address -match '^188\.43\.(61|64|65|66|67|68|69|87|126|127)\.[0-9]+:443$'){
   Say ('googlevideo GGC: host='+$hostName+' destination='+$address+' label=COMMUNITY_GGC_RANGE_UNVERIFIED AS20485-reference; prefix label only, not measured ownership/throttling and no routing change')
  }
 }

 Write-YouTubeLocalEvidence (Prop $native 'youtube_local_ladder')
 Write-BrowserDNSEvidence $native
 $dc=Prop $native 'domain_cache';if($dc){Say ('native DNS cache: checked='+(Prop $dc 'checked_at')+' error='+(Prop $dc 'last_error')+' addresses='+(Prop $dc 'addresses')+' source='+(Prop $dc 'source')+' unknown_policy='+(Prop $dc 'unknown_policy'))}
 Write-TlsWireEvidence $native 'native.actual_upstream'
 $ingress=Prop $native 'capture_ingress'
 if($null -eq $ingress){Say 'capture ingress: UNINSTRUMENTED (update service required)'}else{
  Say ('capture ingress: scope='+(Prop $ingress 'scope')+' tcp_packets='+(Prop $ingress 'tcp_packets' 0)+' udp443='+(Prop $ingress 'udp_443_packets' 0)+' ipv6='+(Prop $ingress 'ipv6_packets' 0)+' native_syn='+(Prop $ingress 'native_deferred_syn' 0)+' reflection_accepts='+(Prop $ingress 'reflected_accepts' 0)+' socket_events='+(Prop $ingress 'socket_events' 0)+' unknown_tcp_owner='+(Prop $ingress 'unknown_tcp_owner' 0)+' samples_lost='+(Prop $ingress 'lost' 0))
  foreach($key in @('tcp_filter','udp_filter','socket_filter','ipv6_filter')){Say ($key+'='+(Prop $ingress $key 'UNAVAILABLE'))}
  foreach($sample in @(Prop $ingress 'records' @())){
   Say ('capture attribution: stage='+(Prop $sample 'stage')+' pid='+(Prop $sample 'pid' 0)+' birth='+(Prop $sample 'creation_time' 0)+' exe='+(Prop $sample 'exe')+' protocol='+(Prop $sample 'protocol')+' destination='+(Prop $sample 'destination')+' owner='+(Prop $sample 'owner_lookup')+' profile='+(Prop $sample 'profile_id' 'NONE')+' decision='+(Prop $sample 'decision')+' policy='+(Prop $sample 'policy_source')+' error='+(Prop $sample 'error' 'NONE'))
  }
 }

 Say ('native readiness: state='+(Prop $native 'state' 'UNINSTRUMENTED')+' reason='+(Prop $native 'reason' 'UNINSTRUMENTED')+' configured='+(Prop $native 'configured_profiles' 0)+' guard='+(Prop $native 'guard' 'UNINSTRUMENTED'))
 $state=Prop $native 'native_only_state' 'NATIVE_ONLY_UNINSTRUMENTED'
 $totals=Prop $native 'native_only_totals'
 if($state -eq 'NATIVE_ONLY_OBSERVED' -and ([long](Prop $totals 'bidirectional_exchanges' 0) -le 0 -or [long](Prop $totals 'sent_bytes' 0) -le 0 -or [long](Prop $totals 'received_bytes' 0) -le 0)){$state='NATIVE_ONLY_INVALID_EVIDENCE'}
 Say ('native-only ingress: state='+$state+' auto_mode='+(Prop $native 'native_only_auto_mode' 'UNINSTRUMENTED')+' opened='+(Prop $totals 'opened' 0)+' exchanges='+(Prop $totals 'bidirectional_exchanges' 0)+' tx='+(Prop $totals 'sent_bytes' 0)+' rx='+(Prop $totals 'received_bytes' 0))
 foreach($browserProfile in @(Prop $native 'profiles' @())){
  foreach($path in @('native_only','pac_native_upstream')){
   $m=Prop $browserProfile $path
   if($null -eq $m){Say ('ingress '+$path+': UNINSTRUMENTED');continue}
   Say ('ingress '+$path+': profile='+(Prop $browserProfile 'profile_id')+' accepted='+(Prop $m 'accepted' 0)+' opened='+(Prop $m 'opened' 0)+' failed='+(Prop $m 'failed' 0)+' exchanges='+(Prop $m 'bidirectional_exchanges' 0)+' active='+(Prop $m 'active' 0)+' tx='+(Prop $m 'sent_bytes' 0)+' rx='+(Prop $m 'received_bytes' 0)+' first_open='+(Prop $m 'first_opened_at' 'NOT_OBSERVED')+' first_exchange='+(Prop $m 'first_exchange_at' 'NOT_OBSERVED')+' enable_to_first_open_ms='+(Prop $m 'enable_to_first_open_ms' -1)+' enable_to_first_exchange_ms='+(Prop $m 'enable_to_first_exchange_ms' -1))
  }
 }
 Say 'PAC_NATIVE_UPSTREAM is not native-only. Native new TCP does not require policy refresh. Opaque TLS defaults DIRECT under owner policy; observed protected associations remain relay-only; native UDP443 is rejected to TCP; process capture is not an independent kernel crash guard. No policy changed by diagnostics.'
}
function Write-RelaySelectionEvidence($mapping) {
 Say ('relay new-flow selection: preferred='+(Prop $mapping 'preferred_for_new_opens' 'UNINSTRUMENTED')+' reason='+(Prop $mapping 'selection_reason' 'UNINSTRUMENTED')+' switches='+(Prop $mapping 'selection_switches' 0)+' hold_until='+(Prop $mapping 'standby_hold_until' '-')+' primary_healthy_since='+(Prop $mapping 'primary_healthy_since' '-'))
 foreach($row in @(Prop $mapping 'connections' @())){
  Say (' relay health: id='+(Prop $row 'authenticated_relay_id' 'UNKNOWN')+' address='+(Prop $row 'configured_address' 'UNKNOWN')+' pool_healthy='+(Prop $row 'pool_healthy' 'UNKNOWN')+' state='+(Prop $row 'health' 'UNINSTRUMENTED')+' probe_rtt_ms='+(Prop $row 'probe_rtt_ms' 'UNKNOWN')+' probe_at='+(Prop $row 'probe_observed_at' 'UNKNOWN')+' new_open_failures='+(Prop $row 'new_open_failures' 0)+' last_failure='+(Prop $row 'last_failure_class' '-'))
 }
 Say 'Hysteresis affects new authenticated opens only; no existing flow migration/replay. Pool capacity or one origin failure does not blacklist VPS. Zero/unobserved probe time is not a measured RTT.'
}
function Write-NativeFirewallEvidence($firewall) {
 $state=Prop $firewall 'state' 'UNKNOWN'
 if(!(Prop $firewall 'known' $false)){$state='UNKNOWN: '+$state}
 elseif($state -eq 'APPLIED' -and (!(Prop $firewall 'effective' $false) -or !(Prop $firewall 'program_matches' $false) -or !(Prop $firewall 'rule_present' $false))){$state='INVALID_FIREWALL_EVIDENCE'}
 Say ('native firewall: state='+$state+' rule_present='+(Prop $firewall 'rule_present' $false)+' program_matches='+(Prop $firewall 'program_matches' $false)+' effective='+(Prop $firewall 'effective' $false)+' local_rules_permitted='+(Prop $firewall 'local_rules_permitted' $false)+' checked_at='+(Prop $firewall 'checked_at' 'NOT_OBSERVED'))
 Say 'Firewall admission controls the local SYN/ACK handoff, not remote SNI/TLS or Engine reservation release. DIRECT_STALL after actual forwarded ClientHello is not proof of a missing local allow rule. LOCAL_FLOW_RESERVATION_IN_USE is local lifecycle, not relay transport health.'
}

if((Want 'browser') -or ($Only -contains 'youtube')){
Step 'relay_traffic' {
 try{Write-TrafficEvidence (Invoke-IPC 'traffic.status')}catch{Say 'Relay traffic: UNINSTRUMENTED_OR_UNAVAILABLE; monthly usage UNKNOWN'}
}
Step 'local_catalog' {
 try{Write-LocalCatalogEvidence (Invoke-IPC 'local.catalog')}catch{Say 'local catalog: UNINSTRUMENTED_OR_UNAVAILABLE'}
}
Step 'relay_primary_mapping' {
 try{
  $mapping=Invoke-IPC 'relay.primary.status'
  Write-RelaySelectionEvidence $mapping
  Say ('relay mapping: local_policy=VPS-01 primary='+(Prop $mapping 'configured_primary')+' standby='+(Prop $mapping 'configured_standby')+' last_actual_authenticated_id='+(Prop $mapping 'last_opened_authenticated_relay' 'NONE')+' reason='+(Prop $mapping 'reason'))
  foreach($row in @(Prop $mapping 'connections' @())){Say (' relay payload: authenticated_id='+(Prop $row 'authenticated_relay_id')+' tcp_peer='+(Prop $row 'observed_tcp_session_endpoint' 'UDP_PEER_NOT_EXPOSED')+' opens='+(Prop $row 'Opens' 0)+' active='+(Prop $row 'Active' 0)+' tx='+(Prop $row 'TX' 0)+' rx='+(Prop $row 'RX' 0))}
  if(Prop $mapping 'configured_primary' ''){
   Say 'authenticated pool=VPS-PRIMARY (physical Hostkey; logical VPS-01 policy provider may select standby for a new open)'
   Write-RelayOpenPerformance (Invoke-IPC 'relay.pool.diagnostics' @{relay_id='VPS-PRIMARY'})
  }
 }catch{Say 'primary relay mapping: UNINSTRUMENTED_OR_UNAVAILABLE; legacy VPS-01 pool below does not prove Hostkey data usage'}
}
}

if($Only -contains 'youtube'){
Section 'YouTube: Chrome + Edge, address/domain cache and actual relay payload bytes per minute'
Step 'youtube' {
 try{Write-YouTubeLocalEvidence (Prop (Invoke-IPC 'browser.native.status') 'youtube_local_ladder')}catch{Say 'YouTube local ladder: STATUS_UNAVAILABLE'}
 $st=Invoke-IPC 'status'
 Say ("service build: "+(Prop $st 'build' '-')+"; optimizing: "+(Prop $st 'optimizing')+"; youtube_via_relay="+(Prop (Prop $st 'settings') 'youtube_via_relay' $false)+" (legacy preference; automatic YouTube local ladder does not require it)")
 try{Write-RelayOpenPerformance (Invoke-IPC 'relay.pool.diagnostics' @{relay_id='VPS-01'})}catch{Say 'relay OPEN performance: UNAVAILABLE (older service/no current pool)'}
 $allRecords=@();$shownUsage=$false
 foreach($lane in @('browser','edge')){
  try{$snapshot=Invoke-IPC ($lane+'.status')}catch{Say ($lane+': IPC unavailable: '+(Scrub $_.Exception.Message));continue}
  Say ($lane+": listening="+(Prop $snapshot 'listening')+" policy_ready="+(Prop $snapshot 'policy_ready')+" ready_profiles="+(@(Prop $snapshot 'ready_profiles' @()) -join ',')+" rollback_guard_active="+(Prop $snapshot 'rollback_guard_active' $false)+" readiness_state="+(Prop $snapshot 'readiness_state' '')+" pending_profile="+(Prop $snapshot 'pending_profile' '')+" last_error="+(Prop $snapshot 'last_error' '')+" truncated="+(Prop $snapshot 'truncated')+" lost="+(Prop $snapshot 'lost'))
  Write-BrowserPathEvidence $snapshot $lane
  $cache=Prop $snapshot 'direct_timeout_cache'
  if($cache){
   Say ("cache (shared by both lanes): domains="+(Prop $cache 'active_origins')+" addresses="+(Prop $cache 'active_addresses' '-')+" stalls="+(Prop $cache 'direct_stalls_total')+" rechecks="+(Prop $cache 'background_direct_probes')+" recovered_verified="+(Prop $cache 'recovered_to_direct'))
   foreach($origin in @(Prop $cache 'top_origins' @())){
    Say (" cache: network="+(Prop $origin 'network' '-')+" profile="+(Prop $origin 'profile_id' '-')+" group="+(Prop $origin 'group' '(exact host)')+" probe_host="+(Prop $origin 'probe_host' '-')+" domain="+(Prop $origin 'host')+" port="+(Prop $origin 'port')+" address="+(Prop $origin 'address' '(domain)')+" reason="+(Prop $origin 'reason' '-')+" distinct="+(Prop $origin 'distinct_failed_addresses' '-')+" ttl_ms="+(Prop $origin 'ttl_remaining_ms' '-')+" next_probe="+(Prop $origin 'next_direct_probe'))
   }
  }
  $usage=Prop $snapshot 'relay_usage'
  if($usage -and -not $shownUsage){
   $shownUsage=$true
   Say ("relay usage (TCP payload excluding QUIC overhead/probes): googlevideo="+(Prop $usage 'googlevideo_active_tunnels')+"/"+(Prop $usage 'googlevideo_tunnel_limit')+" opaque_google="+(Prop $usage 'opaque_google_active_tunnels' 0)+" admission_scope="+(Prop $usage 'admission_scope' 'LEGACY_SHARED')+" total_google="+(Prop $usage 'google_admission_total_active' (Prop $usage 'googlevideo_shared_limit_active' 'UNINSTRUMENTED'))+" waiters="+(Prop $usage 'googlevideo_waiters' 0)+" admission_failures="+(Prop $usage 'googlevideo_admission_failures' 0)+" cap_events="+(Prop $usage 'googlevideo_limit_events')+" truncated="+(Prop $usage 'truncated')+" overflow_bytes="+(Prop $usage 'cardinality_overflow_bytes'))
   foreach($minute in @(Prop $usage 'minutes' @())){Say (" minute="+(Prop $minute 'minute_utc')+" profile="+(Prop $minute 'profile_id')+" domain="+(Prop $minute 'domain')+" tx="+(Prop $minute 'sent_bytes')+" rx="+(Prop $minute 'received_bytes'))}
  }
  $failures=Prop $snapshot 'failures'
  if($failures){foreach($property in $failures.PSObject.Properties){if($property.Name -match 'DIRECT_|UPSTREAM_|MIDSTREAM'){Say (" $lane failure "+$property.Name+'='+$property.Value)}}}
  foreach($record in @(Prop $snapshot 'records' @())){
   $allRecords+= $record
   if((Prop $record 'domain' '') -notmatch '(^|\.)(youtube\.com|googlevideo\.com|ytimg\.com|ggpht\.com|youtu\.be|youtube-nocookie\.com)$'){continue}
   $plan=Prop $record 'plan';$policy=Prop $plan 'policy';$owner=Prop $record 'owner'
   Say (" $lane #"+(Prop $record 'id')+" process="+(Prop $owner 'exe')+" pid="+(Prop $owner 'pid')+" profile="+(Prop $owner 'profile_id')+" "+(Prop $record 'domain')+":"+(Prop $record 'port')+" -> "+(Prop $plan 'destination')+" action="+(Prop $policy 'action')+" source="+(Prop $policy 'source')+" probe="+(Prop $plan 'probe')+" attempts="+(Prop $plan 'direct_attempts' '-')+" result="+(Prop $record 'result')+" open_failure="+(Prop $record 'open_failure')+" tx="+(Prop $record 'sent_bytes')+" rx="+(Prop $record 'received_bytes'))
  }
 }
 $videoName=@($allRecords|ForEach-Object{Prop $_ 'domain' ''}|Where-Object{$_ -match '(^|\.)googlevideo\.com$'}|Select-Object -First 1)
 if($videoName.Count){$videoOrigin=[string]$videoName[0]}else{$videoOrigin='redirector.googlevideo.com';Say 'No real video CDN hostname in retained evidence; using redirector only as a DNS/TLS control, not as video PASS.'}
 Say ("googlevideo address checks: "+$videoOrigin)
 $videoAddresses=@()
 foreach($dnsServer in @($null,'8.8.8.8')){
  try{
   $query=@{Name=$videoOrigin;Type='A';DnsOnly=$true;ErrorAction='Stop'};if($dnsServer){$query.Server=$dnsServer}
   $found=@(Resolve-DnsName @query|Where-Object{$_.Type -eq 'A'}|ForEach-Object{$_.IPAddress}|Select-Object -Unique)
   Say (" DNS "+$(if($dnsServer){$dnsServer}else{'system'})+': '+($found -join ','));$videoAddresses+=$found
  }catch{Say (' DNS failed: '+(Scrub $_.Exception.Message))}
 }
 foreach($ipAddress in @($videoAddresses|Select-Object -Unique|Select-Object -First 8)){
  foreach($serverName in @($videoOrigin,'www.youtube.com','www.google.com','example.com')){
   $probe=Test-TlsSni $ipAddress $serverName 443 3000
   Say (" $ipAddress SNI=$serverName TCP="+$probe.Tcp+" tcp_ms="+$probe.TcpMs+" TLS="+$probe.Tls)
  }
 }
 Say 'These DNS/TCP/TLS controls do not establish video playback, HTTP/3, site usability or an Internet PASS.'
}}

if(Want 'browser'){
Section 'Native browser new-connection evidence (owned PAC crash-guard retained)'
Step 'native_browser' {
 $native=Invoke-IPC 'browser.native.status'
 Write-NativeIngressEvidence $native
 try{
  $inventory=Invoke-IPC 'browser.native.attribution'
  Say ('live browser TCP inventory: scope='+(Prop $inventory 'scope')+' truncated='+(Prop $inventory 'truncated' $false)+' error='+(Prop $inventory 'error' 'NONE'))
  foreach($row in @(Prop $inventory 'records' @())){
   $identity=Prop $row 'identity'
   Say ('live browser socket: pid='+(Prop $identity 'PID')+' birth='+(Prop $identity 'CreationTime')+' exe='+(Prop $identity 'Path')+' destination='+(Prop $row 'destination')+' loopback='+(Prop $row 'loopback')+' state='+(Prop $row 'tcp_state')+' profile='+(Prop $row 'profile_id' 'NONE')+' deferred='+(Prop $row 'deferred')+' native_opener='+(Prop $row 'native_opener'))
  }
 }catch{Say 'live browser TCP inventory unavailable (service update required); zero Engine flows does not prove zero network packets'}
 try{Write-NativeFirewallEvidence (Invoke-IPC 'browser.native.firewall')}catch{Say 'native firewall: UNKNOWN_IPC_UNAVAILABLE; no assumption about the rule'}
 Say ("capture_ready="+(Prop $native 'capture_ready')+" optimizing="+(Prop $native 'optimizing')+" existing_tcp="+(Prop $native 'existing_tcp')+" truncated="+(Prop $native 'truncated')+" lost="+(Prop $native 'lost'))
 foreach($p in @(Prop $native 'profiles' @())){
  $state=if([long](Prop $p 'opened' 0) -gt 0){'NATIVE_UPSTREAM_OPEN_OBSERVED'}else{'NO_NEW_NATIVE_UPSTREAM_OBSERVED'}
  Say ("native timing: state="+$state+' profile='+(Prop $p 'profile_id')+' accepted='+(Prop $p 'accepted' 0)+' opened='+(Prop $p 'opened' 0)+' failed='+(Prop $p 'failed' 0)+' first_open='+(Prop $p 'first_tunnel_opened_at' 'NOT_OBSERVED')+' enable_to_first_open_ms='+(Prop $p 'enable_to_first_open_ms' -1)+' first_exchange='+(Prop $p 'first_bidirectional_exchange_at' 'NOT_OBSERVED')+' tx='+(Prop $p 'sent_bytes' 0)+' rx='+(Prop $p 'received_bytes' 0))
 }
 foreach($lane in @('browser','edge')){
  try{$pac=Invoke-IPC ($lane+'.status');Write-BrowserPathEvidence $pac $lane
   if($lane -eq 'edge'){Say ('edge transport_mode='+(Prop $pac 'transport_mode' 'LEGACY')+' readiness='+(Prop $pac 'readiness_state')+' nonce='+(Prop $pac 'pac_nonce_readiness' 'LEGACY')+' owned_guard='+(Prop $pac 'owned_guard_installed' $false)+' rollback_guard='+(Prop $pac 'rollback_guard_active' $false))}
  }catch{Say ($lane+' path metrics unavailable: '+(Scrub $_.Exception.Message))}
 }
 foreach($r in @(Prop $native 'records' @())|Select-Object -First 32){
  $de=Prop $r 'domain_evidence';if($de){Say ('native domain evidence: source='+(Prop $de 'source')+' confidence='+(Prop $de 'confidence')+' outer='+(Prop $de 'outer_sni')+' candidates='+(@(Prop $de 'candidates' @()) -join ',')+' ambiguous='+(Prop $de 'ambiguous')+' restricted='+(Prop $de 'restricted'))}
  $pre=Prop $r 'origin_preflight';if($pre){Say ('native origin preflight: chosen='+(Prop $pre 'destination')+' verified='+(Prop $pre 'verified')+' address_verified='+(Prop $pre 'address_verified')+' source='+(Prop $pre 'source')+' expires='+(Prop $pre 'expires')+' failure='+(Prop $pre 'failure'))}
  $owner=Prop $r 'owner';$policy=Prop $r 'policy'
  Say ("native ingress="+(Prop $r 'ingress' 'UNINSTRUMENTED')+" #"+(Prop $r 'id')+" pid="+(Prop $owner 'pid')+" birth="+(Prop $owner 'creation_time')+" domain="+(Prop $r 'domain')+" destination="+(Prop $r 'destination')+" route="+(Prop $policy 'action')+" relay="+(Prop $policy 'relay_id')+" source="+(Prop $policy 'source')+" result="+(Prop $r 'result')+" failure="+(Prop $r 'failure_reason')+" tx="+(Prop $r 'sent_bytes')+" rx="+(Prop $r 'received_bytes'))
 }
 $usage=Prop $native 'relay_usage'
 Say ("shared relay TCP: active="+(Prop $usage 'active_tcp_tunnels')+" opened="+(Prop $usage 'tcp_tunnels_opened')+" scope="+(Prop $usage 'scope'))
 foreach($m in @(Prop $usage 'minutes' @())){Say ("relay minute: "+(Json $m))}
 foreach($o in @(Prop $usage 'active_origins' @())){Say ("relay active: "+(Json $o))}
 $refresh=Join-Path $env:LOCALAPPDATA 'VELIQ\browser-native-policy-refresh.txt'
 if(Test-Path $refresh){Say ('Historical refresh request (not live evidence): '+(Get-Content $refresh -TotalCount 1))}
 Say 'Native mode does not require PAC. Registry/refresh/tunnel bytes are NOT live-policy/site PASS. Existing HTTP/2 may be reused on reload; no connection egress migration. Opaque ECH without protected evidence defaults DIRECT; encrypted inner domain is NOT guaranteed; native QUIC is rejected to TCP; domain cannot be inferred.'
}
Section 'Existing browser processes and startup profile registration (no browser restart)'
Step 'startup_profiles' {
 foreach($process in $script:liveBrowserBefore){Say ("existing: "+(Json $process))}
 $profiles=@(Invoke-IPC 'profiles')
 foreach($browserName in 'chrome.exe','msedge.exe'){
  $matches=@($profiles|Where-Object{@(Prop $_ 'executables' @()|Where-Object{($_ -replace '\\','/').Split('/')[-1] -ieq $browserName}).Count -gt 0})
  Say ("$browserName profiles: "+$matches.Count)
  foreach($profile in $matches){Say (Json ([ordered]@{id=(Prop $profile 'id');mode=(Prop $profile 'mode');preset=(Prop $profile 'app_preset');transport=(Prop $profile 'browser_transport');exe=(Prop $profile 'executables')}))}
 }
 $report=Join-Path $env:LOCALAPPDATA 'VELIQ\browser-startup.json'
 if((Test-Path -LiteralPath $report) -and (Get-Item -LiteralPath $report).Length -le 65536){
  $data=Get-Content -LiteralPath $report -Raw|ConvertFrom-Json
  Say ("GUI startup report: started=$(Prop $data 'started') completed=$(Prop $data 'completed') elapsed_ms=$(Prop $data 'elapsed_ms')")
  foreach($entry in (@(Prop $data 'browsers' @())|Select-Object -First 2)){Say (Json ([ordered]@{browser=(Prop $entry 'browser');state=(Prop $entry 'state');mode=(Prop $entry 'mode');profile_id=(Prop $entry 'profile_id');code=(Prop $entry 'code')}))}
 }else{Say 'GUI startup report unavailable; GUI may not have been updated/launched under this user.'}
 Say 'Registration is not routing PASS. Headless checks below use separate profiles, not existing windows.'
}
}

if(Want 'browser'){
Section 'End-to-end through the browser path (the way users really browse)'
Step 'connect' {
 # Raw CONNECT from PowerShell. The proxy authorizes only Chrome-profile processes, so
 # a rejection (403) here is EXPECTED and only proves the proxy is alive. The real
 # end-to-end verdict is the headless-browser test below.
 $json=$script:browserJson
 if(-not $ProxyAddress){
  if(-not $json -and $isWin){try{$json=Json (Invoke-IPC 'browser.status')}catch{}}
  $m=[regex]::Match([string]$json,'"address"\s*:\s*"(127\.0\.0\.1:\d+)"')
  if($m.Success){$ProxyAddress=$m.Groups[1].Value}
 }
 if(-not $ProxyAddress){Say 'Local browser proxy address not found in browser.status (proxy not listening?). Raw CONNECT test skipped.';return}
 $parts=$ProxyAddress -split ':'
 Say "Local browser proxy: $ProxyAddress"
 foreach($target in 'claude.ai','chatgpt.com','www.youtube.com','web.telegram.org','discord.com'){
  $client=New-Object Net.Sockets.TcpClient
  try{
   $w=[Diagnostics.Stopwatch]::StartNew()
   $client.Connect($parts[0],[int]$parts[1]);$client.ReceiveTimeout=12000
   $stream=$client.GetStream()
   $req=[Text.Encoding]::ASCII.GetBytes("CONNECT ${target}:443 HTTP/1.1`r`nHost: ${target}:443`r`n`r`n")
   $stream.Write($req,0,$req.Length)
   $buf=New-Object byte[] 512;$n=$stream.Read($buf,0,512)
   $first=([Text.Encoding]::ASCII.GetString($buf,0,$n) -split "`r?`n")[0]
   $note=if($first -match ' 403'){' (owner check rejects non-browser processes: expected, proves only that the proxy is alive)'}else{''}
   Say "CONNECT ${target}:443 -> '$first' in $($w.ElapsedMilliseconds) ms$note"
  }catch{Say "CONNECT ${target}:443 -> ERROR $($_.Exception.GetBaseException().Message)"}
  finally{$client.Close()}
 }
}
Step 'headless' {
 if(-not $isWin){Say 'Headless browser test skipped (not Windows)';return}
 $browsers=[ordered]@{
  'Chrome'=@("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe","$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe")
  'Edge'=@("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")
 }
 foreach($label in $browsers.Keys){
  $exe=@($browsers[$label]|Where-Object{Test-Path $_})|Select-Object -First 1
  if(-not $exe){Say "$label : not installed";continue}
  Say "$label headless (own empty profile, your windows and tabs are untouched): $exe"
  foreach($site in 'claude.ai','chatgpt.com','www.youtube.com','web.telegram.org','discord.com'){
   $marker='veliq-diag-'+[Guid]::NewGuid().ToString('N')
   $dir=Join-Path ([IO.Path]::GetTempPath()) $marker
   $o="$dir.out";$e="$dir.err";$p=$null
   try{
    New-Item -ItemType Directory -Path $dir -Force|Out-Null
    $w=[Diagnostics.Stopwatch]::StartNew()
    $browserArgs=@('--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--timeout=15000','--dump-dom',"--user-data-dir=$dir","https://$site/")
    $p=Start-Process -FilePath $exe -ArgumentList $browserArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput $o -RedirectStandardError $e
    # Wait for the main process, end the whole tree and any detached child that still
    # holds the redirected files, and only then read them (shared access).
    $finished=$p.WaitForExit(30000)
    Stop-OwnBrowser $p $marker
    $dom=Read-SharedText $o
    $errText=Read-SharedText $e
    $title=[regex]::Match($dom,'(?is)<title[^>]*>(.*?)</title>').Groups[1].Value.Trim()
    $err=[regex]::Match($dom+' '+$errText,'ERR_[A-Z_]+').Value
    $verdict=if(-not $finished){'TIMEOUT (30 s)'}elseif($err){"FAILED $err"}elseif($dom.Length -lt 200){'EMPTY PAGE'}else{'DOM RECEIVED (not full-site PASS)'}
    Say "  $site [$verdict] $($w.ElapsedMilliseconds) ms, dom $($dom.Length) bytes, title: '$title'"
   }catch{Say "  $site ERROR $($_.Exception.Message)"}
   finally{
    Stop-OwnBrowser $p $marker
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue;Remove-Item -LiteralPath $o,$e -Force -ErrorAction SilentlyContinue
   }
  }
 }
}}

if(Want 'browser'){
Section 'Existing browser identity after diagnostics'
Step 'existing_browser_after' {
 $after=@(Get-LiveBrowserIdentity)
 foreach($before in $script:liveBrowserBefore){
  $same=@($after|Where-Object{$_.pid -eq $before.pid -and $_.created -eq $before.created})
  Say ("existing $($before.name) PID=$($before.pid) created=$($before.created) unchanged="+($same.Count -eq 1))
 }
 Say 'PID continuity covers this diagnostic interval only; it does not prove PAC adoption or route success in an existing window.'
}
}

if(Want 'game'){
Section 'Игровой UDP-обход: DIRECT / LOCAL_UDP / RELAY'
Step 'game_udp' {
 . (Join-Path $scriptDir 'game-udp-report.ps1')
 $game=Invoke-IPC 'gameudp.status'
 Say ('guard='+ (Json (Prop $game 'guard')))
 foreach($profile in @(Prop $game 'profiles' @())){Say ('profile='+[string](Prop $profile 'profile_id' '')+' state='+[string](Prop $profile 'state' '')+' reason='+[string](Prop $profile 'reason' ''))}
 Say (Json @(Get-GameUdpRows $game))
 Say 'Transport counters are not proof of match loading or anti-cheat compatibility. No game packets are generated by diagnostics.'
}
}

if(Want 'apps'){
Section 'Installed apps and browser coverage'
Step 'apps' {
 $paths=[ordered]@{
  'Chrome'=@("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe","$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe")
  'Edge'=@("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")
  'Firefox'=@("$env:ProgramFiles\Mozilla Firefox\firefox.exe","${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe")
  'Telegram Desktop'=@("$env:APPDATA\Telegram Desktop\Telegram.exe","$env:ProgramFiles\Telegram Desktop\Telegram.exe","$env:LOCALAPPDATA\Telegram Desktop\Telegram.exe")
  'Discord'=@("$env:LOCALAPPDATA\Discord\Update.exe")
 }
 foreach($k in $paths.Keys){$f=@($paths[$k]|Where-Object{Test-Path $_});Say ("$k : "+$(if($f.Count){'installed: '+($f -join '; ')}else{'not found'}))}
 Say ("Running now: "+((Get-Process -ErrorAction SilentlyContinue|Where-Object{$_.ProcessName -match '^(chrome|msedge|firefox|telegram|discord)$'}|Select-Object -ExpandProperty ProcessName -Unique) -join ', '))
}}

Say ''

if($Only -contains 'browser' -or $Only -contains 'youtube'){
 Section 'LOCAL strategy x host probes (all groups)'
 Step 'local-probes' { Write-LocalProbeEvidence (Invoke-IPC 'browser.local.probes') }
}

if(Want 'layers'){
 Section 'Read-only DNS -> TCP -> verified TLS -> bounded public HTTP controls'
 Step 'layers' {
  $probe=Join-Path $BuildDirectory 'network-check.exe'
  if(!(Test-Path -LiteralPath $probe)){Say 'NETWORK_CHECK_NOT_BUILT: run build-e2e.ps1 with installed pinned driver; no resolver or machine setting changed';return}
  $dnsIPs=@('8.8.8.8','1.1.1.1','9.9.9.9','77.88.8.8')
  if($isWin){$dnsIPs+=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue|ForEach-Object{$_.ServerAddresses})}
  $dnsIPs=@($dnsIPs|Select-Object -Unique -First 8)
  foreach($layerHost in @($LayerHosts|Select-Object -First 3)){
   # Helper only accepts existing public controls; no private URLs, tokens, redirects or TLS bypass.
   $probeLines=@(& $probe '-host' $layerHost '-resolvers' ($dnsIPs -join ','))
   if($LASTEXITCODE){Say ('NETWORK_CHECK_FAILED exit='+$LASTEXITCODE);continue}
   foreach($line in $probeLines){Say (Scrub ([string]$line))}
  }
  Say 'NXDOMAIN+aa is evidence, not proof of spoofing; compare verified encrypted DNS. TCP connect failure is not packet proof of SYN DROP. HTTPS redirects are not visible inside browser TLS. No routing or machine settings changed.'
 }
}

Say "Finished $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))."
try{$all=[IO.File]::ReadAllText($result);[IO.File]::WriteAllText($result,(Scrub $all),$utf8Bom)}catch{}
Write-Host "`nSaved: $result"
