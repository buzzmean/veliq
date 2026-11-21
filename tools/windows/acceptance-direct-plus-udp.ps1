[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$Target,
 [Parameter(Mandatory=$true)][string]$TokenFile,
 [string]$VpsPublicIP='2.56.177.4',
 [string]$Binaries=(Join-Path $PSScriptRoot '..\..\bin\windows-e2e'),
 [string]$ReportDirectory=(Join-Path $PSScriptRoot '..\..\.e2e\direct-plus-udp'),
 [ValidateRange(30,100)][int]$Count=50
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'acceptance-checks.ps1')
. (Join-Path $PSScriptRoot 'acceptance-process.ps1')
. (Join-Path $PSScriptRoot 'direct-plus-checks.ps1')
Assert-Administrator
if(!(Test-Path (Join-Path $Binaries 'udp-plus.exe')) -and (Test-Path (Join-Path $PSScriptRoot '..\..\udp-plus.exe'))){$Binaries=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path}
$parts=$Target.Split(':');if($parts.Count -ne 2 -or [int]$parts[1] -notin 1..65535){throw 'Public IPv4:port required'}
$ip=Assert-VpsIPv4 $parts[0];$port=[int]$parts[1];$VpsPublicIP=Assert-VpsIPv4 $VpsPublicIP
$TokenFile=(Resolve-Path $TokenFile).Path;foreach($v in @($TokenFile,$ReportDirectory)){if($v.Contains('"')){throw 'Quote in argument'}}
New-Item -ItemType Directory -Force $ReportDirectory|Out-Null;$ReportDirectory=(Resolve-Path $ReportDirectory).Path
$plus=(Resolve-Path (Join-Path $Binaries 'udp-plus.exe')).Path;$direct=(Resolve-Path (Join-Path $Binaries 'control-client.exe')).Path;$relay=(Resolve-Path (Join-Path $Binaries 'test-game.exe')).Path
$old=Invoke-ServiceIPC 'status';$oldLocal=Invoke-ServiceIPC 'local.get';$run=[Guid]::NewGuid().ToString('N');$ids=@();$children=@();$reports=@();$records=@()
try{
 $strategy=@{id='!udp-'+$run;name='Controlled UDP fragmentation';version=1;protocol='udp';ports=@($port);application=$plus;domains=@();ips=@($ip);exclude_domains=@();exclude_ips=@();strategy='udp-fragment-24';cutoff=2;priority=1000;enabled=$true}
 [void](Invoke-ServiceIPC 'local.set' @{version=1;enabled=$true;builtin=@();user=@($oldLocal.user)+@($strategy)})
 foreach($trial in @(@{exe=$plus;mode='DIRECT_PLUS';route='DIRECT_PLUS'},@{exe=$direct;mode='DIRECT';route='DIRECT'},@{exe=$relay;mode='MANUAL';route='RELAY'})){
  $id='!udp-'+$trial.mode+'-'+$run;$ids+=$id;$p=@{id=$id;name='UDP three routes';executables=@($trial.exe);mode=$trial.mode;custom=$true;local_strategy_id=''};if($trial.mode -eq 'MANUAL'){$p.relay_id='VPS-01'};if($trial.mode -eq 'DIRECT_PLUS'){$p.local_strategy_id=$strategy.id};[void](Invoke-ServiceIPC 'profile.set' $p)
  Assert-LocalEffectiveProfile (Invoke-ServiceIPC 'status') $trial.exe $id $trial.mode $p.local_strategy_id
 }
 $network=Invoke-ServiceIPC 'local.network'
 [void](Invoke-ServiceIPC 'optimize' @{enabled=$true})
 [void](Wait-AcceptanceReadiness -TimeoutMS 30000 -GetSnapshot {Invoke-ServiceIPC 'acceptance.readiness' @{relay_id='VPS-01'}} -Evaluate {param($s)$missing=@();if(!$s.backend.ready -or !$s.backend.capabilities.udp){$missing+='UDP backend'};if(!$s.relay_transport.connected -or !$s.relay_transport.flow_open){$missing+='authenticated relay session'};[pscustomobject]@{ready=(!$missing.Count);missing=$missing}})
 foreach($trial in @(@{exe=$plus;route='DIRECT_PLUS'},@{exe=$direct;route='DIRECT'},@{exe=$relay;route='RELAY'})){
  $path=Join-Path $ReportDirectory "$run-$($trial.route).json";$args="-target $Target -token-file `"$TokenFile`" -count $Count -interval 100ms -timeout 3s -report `"$path`" -quiet"
  $children+=@{process=(Start-AcceptanceProcess $trial.exe $args $path);report=$path;exe=$trial.exe;route=$trial.route}
 }
 foreach($child in $children){$code=Wait-AcceptanceProcessExit $child.process (($Count*150)+15000) $child.report;$r=Get-Content $child.report -Raw|ConvertFrom-Json;$e=Invoke-ServiceIPC 'capture.diagnostics' @{pid=$child.process.Id};@{exit=$code;report=$r;capture=$e}|ConvertTo-Json -Depth 22|Set-Content ($child.report+'.proof.json') -Encoding UTF8
  if($code -ne 0){throw "Client exit=$code"};Assert-AcceptanceLoss $r
  if($r.pid -ne $child.process.Id -or $r.exe -ine $child.exe -or $r.creation_time -eq 0 -or $r.destination -ne $Target -or $r.Sent -ne $Count){throw 'Identity/target/sent mismatch'}
  if($child.route -ne 'DIRECT_PLUS'){[void](Assert-AcceptanceRoute $r $e $child.exe $Target $child.route $VpsPublicIP)}else{
   if($e.truncated -or @($r.observed_sources).Count -ne 1 -or $r.observed_sources[0] -eq $VpsPublicIP){throw 'DIRECT+ source/truncation mismatch'}
   $flows=@($e.flows|Where-Object{$_.pid -eq $r.pid -and $_.creation_time -eq $r.creation_time -and $_.exe -ieq $child.exe -and $_.destination -eq $Target -and $_.protocol -eq 'udp'})
   if(!$flows.Count -or @($flows|Where-Object{$_.selected_route -ne 'DIRECT_PLUS' -or $_.counters.relayed_packets -ne 0 -or $_.counters.direct_plus_packets -le 0 -or $_.counters.direct_plus_bytes -le 0}).Count){throw 'UDP local transform not proven; ID-zero/options/oversize packets are unsupported, not a network failure diagnosis'}
  };$reports+=$r
  $variant=$child.route;if($variant -eq 'DIRECT_PLUS'){$variant=$strategy.id}
  $measurement=@{route_id=$(if($child.route -eq 'RELAY'){'VPS-01'}else{'controlled-target'});rtt=[long]($r.RTTMS*1e6);jitter=[long]($r.JitterMS*1e6);loss=[double]$r.Loss;failure_rate=[double]$r.Loss;load=0;stability=(1-[double]$r.Loss);available=$true;samples=[int]$r.Received;observed_at=[DateTimeOffset]::UtcNow.ToString('o')}
  # Cache is scoped to the exact probe exe per route; recommendation below uses
  # the common selected probe identity after the three authenticated proofs.
  $records+=@{application=$plus;destination=$Target;protocol='udp';network=$network.fingerprint;strategy=$variant;success=$true;measurement=$measurement}
  Write-Host "PASS $($child.route): $($r.Received)/$($r.Sent), loss=$($r.Loss), observed source=$($r.observed_sources -join ',')"
 }
 $start=($reports|ForEach-Object{[DateTimeOffset]$_.measurement_started}|Sort-Object -Descending|Select-Object -First 1);$end=($reports|ForEach-Object{[DateTimeOffset]$_.measurement_finished}|Sort-Object|Select-Object -First 1);if($start -ge $end){throw 'Three UDP windows do not overlap'}
 $recommendation=Invoke-ServiceIPC 'local.compare' @{measurements=$records}
 @{recommendation=$recommendation;reports=$reports;network=$network}|ConvertTo-Json -Depth 20|Set-Content (Join-Path $ReportDirectory "$run-summary.json") -Encoding UTF8
 Write-Host "Recommended (measured probes, temporary acceptance config): $($recommendation.recommended)"

} catch{
 try{@{error=$_.Exception.Message;status=(Invoke-ServiceIPC 'status');capture=(Invoke-ServiceIPC 'capture.diagnostics')}|ConvertTo-Json -Depth 20|Set-Content (Join-Path $ReportDirectory "$run-FAIL.json") -Encoding UTF8}catch{};throw
} finally{
 foreach($child in $children){if(!$child.process.HasExited){Stop-Process -Id $child.process.Id -ErrorAction SilentlyContinue}}
 foreach($id in $ids){try{[void](Invoke-ServiceIPC 'profile.delete' @{id=$id})}catch{Write-Warning $_}}
 try{[void](Invoke-ServiceIPC 'local.set' $oldLocal)}catch{Write-Warning $_};try{[void](Invoke-ServiceIPC 'optimize' @{enabled=$old.optimizing})}catch{Write-Warning $_}
}
