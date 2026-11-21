[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$URL,
 [Parameter(Mandatory=$true)][string]$TokenFile,
 [string]$EndpointCA='',
 [string]$VpsPublicIP='2.56.177.4',
 [ValidateSet('tcp-split-1','tcp-split-5')][string]$Strategy='tcp-split-1',
 [string]$Binaries=(Join-Path $PSScriptRoot '..\..\bin\windows-e2e'),
 [string]$ReportDirectory=(Join-Path $PSScriptRoot '..\..\.e2e\direct-plus-simultaneous'),
 [ValidateRange(5,10)][int]$Count=10
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'acceptance-checks.ps1')
. (Join-Path $PSScriptRoot 'acceptance-process.ps1')
. (Join-Path $PSScriptRoot 'direct-plus-checks.ps1')
Assert-Administrator
if(!(Test-Path (Join-Path $Binaries 'tcp-selected.exe')) -and (Test-Path (Join-Path $PSScriptRoot '..\..\tcp-selected.exe'))){$Binaries=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path}
$u=[Uri]$URL;if($u.Scheme -notin @('http','https')){throw 'Controlled HTTP/HTTPS URL required'}
[void](Assert-VpsIPv4 $u.Host);$VpsPublicIP=Assert-VpsIPv4 $VpsPublicIP;$destination="$($u.Host):$($u.Port)"
$TokenFile=(Resolve-Path $TokenFile).Path;if($EndpointCA){$EndpointCA=(Resolve-Path $EndpointCA).Path}
foreach($v in @($URL,$TokenFile,$EndpointCA,$ReportDirectory)){if($v.Contains('"')){throw 'Quote in argument'}}
New-Item -ItemType Directory -Force $ReportDirectory|Out-Null;$ReportDirectory=(Resolve-Path $ReportDirectory).Path
$plus=(Resolve-Path (Join-Path $Binaries 'tcp-plus.exe')).Path;$direct=(Resolve-Path (Join-Path $Binaries 'tcp-control.exe')).Path;$relay=(Resolve-Path (Join-Path $Binaries 'tcp-selected.exe')).Path
$run=[Guid]::NewGuid().ToString('N');$old=Invoke-ServiceIPC 'status';$oldLocal=Invoke-ServiceIPC 'local.get';$children=@();$ids=@();$evidence=@();$reports=@();$before=Get-NetRoute|Sort-Object InterfaceIndex,DestinationPrefix,NextHop|Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric|ConvertTo-Json -Compress
try {
 $new=@{id='!acceptance-'+$run;name='Controlled TCP local transform';version=1;protocol='tcp';ports=@($u.Port);application=$plus;domains=@();ips=@($u.Host);exclude_domains=@();exclude_ips=@();strategy=$Strategy;cutoff=2;priority=1000;enabled=$true}
 [void](Invoke-ServiceIPC 'local.set' @{version=1;enabled=$true;builtin=@();user=@($oldLocal.user)+@($new)})
 foreach($trial in @(@{exe=$plus;mode='DIRECT_PLUS';route='DIRECT_PLUS'},@{exe=$direct;mode='DIRECT';route='DIRECT'},@{exe=$relay;mode='MANUAL';route='RELAY'})){
  $id='!triple-'+$trial.mode+'-'+$run;$ids+=$id;$p=@{id=$id;name='Simultaneous three routes';executables=@($trial.exe);mode=$trial.mode;custom=$true;local_strategy_id=''};if($trial.mode -eq 'MANUAL'){$p.relay_id='VPS-01'};if($trial.mode -eq 'DIRECT_PLUS'){$p.local_strategy_id=$new.id};[void](Invoke-ServiceIPC 'profile.set' $p)
  Assert-LocalEffectiveProfile (Invoke-ServiceIPC 'status') $trial.exe $id $trial.mode $p.local_strategy_id
 }
 [void](Invoke-ServiceIPC 'optimize' @{enabled=$true})
 [void](Wait-AcceptanceReadiness -TimeoutMS 30000 -GetSnapshot {Invoke-ServiceIPC 'acceptance.readiness' @{relay_id='VPS-01'}} -Evaluate {param($s)$missing=@();if(!$s.backend.ready -or !$s.backend.capabilities.tcp){$missing+='TCP backend'};if(!$s.relay_transport.connected -or !$s.relay_transport.flow_open){$missing+='authenticated relay session'};[pscustomobject]@{ready=(!$missing.Count);missing=$missing}})
 # Each stage has independent new processes/connections: warm-up cannot hide
 # measured failures. All three measured windows must overlap.
 foreach($stage in @(@{name='warmup';count=2},@{name='measured';count=$Count})){
  $batch=@();foreach($trial in @(@{exe=$plus;route='DIRECT_PLUS'},@{exe=$direct;route='DIRECT'},@{exe=$relay;route='RELAY'})){
   $path=Join-Path $ReportDirectory "$run-$($stage.name)-$($trial.route).json";$args="-url `"$URL`" -token-file `"$TokenFile`" -count $($stage.count) -interval 500ms -report `"$path`"";if($EndpointCA){$args+=" -ca `"$EndpointCA`""}
   $child=@{process=(Start-AcceptanceProcess $trial.exe $args $path);report=$path;exe=$trial.exe;route=$trial.route};$batch+=$child;$children+=$child
  }
  $reports=@();foreach($child in $batch){$code=Wait-AcceptanceProcessExit $child.process (($stage.count*9000)+15000) $child.report;$report=Get-Content $child.report -Raw|ConvertFrom-Json;$capture=Invoke-ServiceIPC 'capture.diagnostics' @{pid=$child.process.Id};$proof=@{exit=$code;report=$report;capture=$capture};$proof|ConvertTo-Json -Depth 22|Set-Content ($child.report+'.proof.json') -Encoding UTF8
   if($code -ne 0){throw "Client $($child.route) failed exit=$code"};[void](Assert-DirectPlusEvidence $report $capture $child.process.Id $child.exe $child.route $VpsPublicIP $destination $stage.count);$reports+=$report
  }
  $start=($reports|ForEach-Object{[DateTimeOffset]$_.measurement_started}|Sort-Object -Descending|Select-Object -First 1);$end=($reports|ForEach-Object{[DateTimeOffset]$_.measurement_finished}|Sort-Object|Select-Object -First 1);if($start -ge $end){throw 'Three measurement windows do not overlap'}
  Write-Host "PASS $($stage.name): simultaneous DIRECT_PLUS / DIRECT / RELAY; signed observed source + exact PID/exe/destination + real counters"
 }
 $after=Get-NetRoute|Sort-Object InterfaceIndex,DestinationPrefix,NextHop|Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric|ConvertTo-Json -Compress;if($before -ne $after){throw 'Windows route table changed during acceptance'}
} catch {
 try{@{error=$_.Exception.Message;status=(Invoke-ServiceIPC 'status');capture=(Invoke-ServiceIPC 'capture.diagnostics');network=(Invoke-ServiceIPC 'local.network')}|ConvertTo-Json -Depth 20|Set-Content (Join-Path $ReportDirectory "$run-FAIL.json") -Encoding UTF8}catch{}
 throw
} finally {
 foreach($child in $children){if(!$child.process.HasExited){Stop-Process -Id $child.process.Id -ErrorAction SilentlyContinue}}
 foreach($id in $ids){try{[void](Invoke-ServiceIPC 'profile.delete' @{id=$id})}catch{Write-Warning $_}}
 try{[void](Invoke-ServiceIPC 'local.set' $oldLocal)}catch{Write-Warning $_}
 try{[void](Invoke-ServiceIPC 'optimize' @{enabled=$old.optimizing})}catch{Write-Warning $_}
}
