# Passive OS connection sampling only. Never opens remote connections or reads
# process memory, packets, TLS content, command lines, keys, config or credentials.
[CmdletBinding()]
param(
 [ValidateRange(1,600)][int]$DurationSeconds=60,
 [ValidateRange(250,5000)][int]$IntervalMilliseconds=1000,
 [ValidateRange(1,50000)][int]$MaxRecords=10000,
 [string[]]$ProcessNames=@('ExitLag','ExitLagService','ExitLagLauncher'),
 [uint32[]]$ProcessIds=@(),
 [string]$OutputDirectory=(Join-Path $PSScriptRoot '..\..\bin\observations')
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'NATIVE_WINDOWS_REQUIRED'}
if($ProcessNames.Count -gt 16 -or $ProcessIds.Count -gt 32){throw 'PROCESS_SELECTION_LIMIT'}
foreach($name in $ProcessNames){if($name -notmatch '^[a-zA-Z0-9._-]{1,64}$'){throw 'EXACT_PROCESS_NAME_REQUIRED'}}
. (Join-Path $PSScriptRoot 'exitlag-observation.ps1')
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$output=Join-Path $OutputDirectory ('exitlag-endpoints-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)+'.csv')
[IO.File]::WriteAllText($output,'At,Event,Pid,Created,Name,Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,RttMs,RttEvidence'+[Environment]::NewLine,[Text.UTF8Encoding]::new($true))
$previous=@{};$written=0;$samples=0;$partial=$false;$stop='DURATION_COMPLETE'
$clock=[Diagnostics.Stopwatch]::StartNew()
do{
 $processes=@();$seen=@{}
 $found=@(Get-Process -Name $ProcessNames -ErrorAction SilentlyContinue)
 foreach($id in $ProcessIds){$found+=@(Get-Process -Id $id -ErrorAction SilentlyContinue)}
 foreach($p in $found|Select-Object -First 32){
  try{if(!$seen.ContainsKey([string]$p.Id)){$seen[[string]$p.Id]=$true;$processes+=,[pscustomobject]@{Pid=$p.Id;Created=$p.StartTime.ToUniversalTime().ToString('O');Name=$p.ProcessName}}}catch{$partial=$true}finally{$p.Dispose()}
 }
 $tcp=@();$udp=@()
 if($processes.Count -gt 0){
  try{$tcp=@(Get-NetTCPConnection -OwningProcess @($processes.Pid) -ErrorAction Stop)}catch{$partial=$true}
  try{$udp=@(Get-NetUDPEndpoint -OwningProcess @($processes.Pid) -ErrorAction Stop)}catch{$partial=$true}
 }
 $current=@{};$rows=@(ConvertTo-ExitLagEndpoints $processes $tcp $udp)
 if($rows.Count -ge 4096){$partial=$true}
 $events=[Collections.Generic.List[object]]::new()
 foreach($r in $rows){
  $current[$r.Key]=$r
  $event=if(!$previous.ContainsKey($r.Key)){'OBSERVED'}elseif($previous[$r.Key].State -ne $r.State){'STATE_CHANGED'}else{''}
  if($event){$events.Add([pscustomobject]@{At=[DateTime]::UtcNow.ToString('O');Event=$event;Pid=$r.Pid;Created=$r.Created;Name=$r.Name;Protocol=$r.Protocol;LocalAddress=$r.LocalAddress;LocalPort=$r.LocalPort;RemoteAddress=$r.RemoteAddress;RemotePort=$r.RemotePort;State=$r.State;RttMs=$null;RttEvidence=$r.RttEvidence})}
 }
 foreach($key in $previous.Keys){if(!$current.ContainsKey($key)){$r=$previous[$key];$events.Add([pscustomobject]@{At=[DateTime]::UtcNow.ToString('O');Event='NOT_SEEN_NEXT_SAMPLE';Pid=$r.Pid;Created=$r.Created;Name=$r.Name;Protocol=$r.Protocol;LocalAddress=$r.LocalAddress;LocalPort=$r.LocalPort;RemoteAddress=$r.RemoteAddress;RemotePort=$r.RemotePort;State=$r.State;RttMs=$null;RttEvidence=$r.RttEvidence})}}
 foreach($event in $events){if($written -ge $MaxRecords){$stop='RECORD_LIMIT';$partial=$true;break};$event|Export-Csv -LiteralPath $output -NoTypeInformation -Encoding UTF8 -Append;$written++}
 $previous=$current;$samples++
 if($written -ge $MaxRecords){break}
 $left=$DurationSeconds*1000-$clock.ElapsedMilliseconds
 if($left -gt 0){Start-Sleep -Milliseconds ([int][Math]::Min($left,$IntervalMilliseconds))}
}while($clock.Elapsed.TotalSeconds -lt $DurationSeconds)
[pscustomobject]@{Result='OBSERVATION_ONLY';File=$output;Samples=$samples;Records=$written;Partial=$partial;Stop=$stop;Rtt='NOT_MEASURED';UdpRemote='NOT_EXPOSED_BY_OS';RouteSwitch='ENDPOINT_CHANGE_IS_NOT_ROUTE_PROOF'}|Format-List
