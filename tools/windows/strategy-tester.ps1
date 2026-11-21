[CmdletBinding()]
param(
 [string]$URL='',
 [string]$UDPTarget='',
 [Parameter(Mandatory=$true)][string]$TokenFile,
 [string]$EndpointCA='',
 [string]$VpsPublicIP='2.56.177.4',
 [string]$Binaries=(Join-Path $PSScriptRoot '..\..\bin\windows-e2e'),
 [string]$ReportDirectory=(Join-Path $PSScriptRoot '..\..\.e2e\direct-plus'),
 [ValidateRange(5,12)][int]$Count=10
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'acceptance-checks.ps1')
. (Join-Path $PSScriptRoot 'acceptance-process.ps1')
. (Join-Path $PSScriptRoot 'direct-plus-checks.ps1')
Assert-Administrator
if($UDPTarget){& (Join-Path $PSScriptRoot 'acceptance-direct-plus-udp.ps1') -Target $UDPTarget -TokenFile $TokenFile -VpsPublicIP $VpsPublicIP -Binaries $Binaries -ReportDirectory $ReportDirectory;return}
if(!(Test-Path (Join-Path $Binaries 'tcp-selected.exe')) -and (Test-Path (Join-Path $PSScriptRoot '..\..\tcp-selected.exe'))){$Binaries=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path}
$VpsPublicIP=Assert-VpsIPv4 $VpsPublicIP;$u=[Uri]$URL
if($u.Scheme -notin @('http','https')){throw 'HTTP/HTTPS controlled endpoint required'}
[void](Assert-VpsIPv4 $u.Host);$destination="$($u.Host):$($u.Port)"
$exe=(Resolve-Path (Join-Path $Binaries 'tcp-selected.exe')).Path;$TokenFile=(Resolve-Path $TokenFile).Path
if($EndpointCA){$EndpointCA=(Resolve-Path $EndpointCA).Path}
foreach($v in @($URL,$TokenFile,$EndpointCA,$ReportDirectory)){if($v.Contains('"')){throw 'Quote in argument'}}
New-Item -ItemType Directory -Force $ReportDirectory|Out-Null;$ReportDirectory=(Resolve-Path $ReportDirectory).Path
$config=Invoke-ServiceIPC 'local.get';$network=Invoke-ServiceIPC 'local.network';if(!$network.fingerprint -or @($network.conflicts).Count){throw 'Fresh network context without known conflicts required'}
if(!$config.enabled){throw 'Enable local strategies first (local.set / GUI)'}
$strategies=@($config.user|Where-Object{$_.enabled -and $_.protocol -eq 'tcp' -and ($_.application -ieq $exe -or $_.application -ieq 'tcp-selected.exe')})
if(!$strategies.Count){throw 'Configure explicit tcp-selected.exe TCP strategies for this target first; browser results are not inherited'}
if($strategies.Count -gt 4){throw 'At most four strategies per finite test'}
$run=[Guid]::NewGuid().ToString('N');$id='!local-test-'+$run;$original=Invoke-ServiceIPC 'status';$children=@();$results=@();$records=@()
try {
 [void](Invoke-ServiceIPC 'optimize' @{enabled=$true})
 [void](Wait-AcceptanceReadiness -TimeoutMS 30000 -GetSnapshot {Invoke-ServiceIPC 'acceptance.readiness' @{relay_id='VPS-01'}} -Evaluate {param($s)$missing=@();if(!$s.backend.ready -or !$s.backend.capabilities.tcp){$missing+='TCP backend'};if(!$s.relay_transport.connected -or !$s.relay_transport.flow_open){$missing+='authenticated relay session'};[pscustomobject]@{ready=(!$missing.Count);missing=$missing}})
 $trials=@(@{label='DIRECT';mode='DIRECT';strategy=''});foreach($s in $strategies){$trials+=@{label=$s.id;mode='DIRECT_PLUS';strategy=$s.id}};$trials+=@{label='RELAY';mode='MANUAL';strategy=''}
 foreach($trial in $trials){
  $profile=@{id=$id;name='Controlled local strategy test';executables=@($exe);mode=$trial.mode;custom=$true;local_strategy_id=$trial.strategy};if($trial.mode -eq 'MANUAL'){$profile.relay_id='VPS-01'}
  [void](Invoke-ServiceIPC 'profile.set' $profile)
  Assert-LocalEffectiveProfile (Invoke-ServiceIPC 'status') $exe $id $trial.mode $trial.strategy
  $path=Join-Path $ReportDirectory "$run-$($results.Count).json";$args="-url `"$URL`" -token-file `"$TokenFile`" -count $Count -interval 300ms -report `"$path`"";if($EndpointCA){$args+=" -ca `"$EndpointCA`""}
  $p=Start-AcceptanceProcess $exe $args $path;$children+=@{process=$p;report=$path};$code=Wait-AcceptanceProcessExit $p (($Count*9000)+15000) $path
  $report=Get-Content $path -Raw|ConvertFrom-Json;$evidence=Invoke-ServiceIPC 'capture.diagnostics' @{pid=$p.Id};$pass=$false;$reason='';$source=''
  try{if($code -ne 0){throw "client exit=$code"};$route=$trial.mode;if($route -eq 'MANUAL'){$route='RELAY'};$source=Assert-DirectPlusEvidence $report $evidence $p.Id $exe $route $VpsPublicIP $destination $Count;$pass=$true}catch{$reason=$_.Exception.Message}
  $measurement=Get-StrategyMeasurement $report $pass
 if($trial.label -eq 'RELAY'){$measurement.route_id='VPS-01'}
  $item=@{strategy=$trial.label;status=$(if($pass){'PASS'}else{'FAIL'});reason=$reason;source=$source;measurement=$measurement;report=$report;capture=$evidence}
  $results+=$item;$item|ConvertTo-Json -Depth 22|Set-Content (Join-Path $ReportDirectory "$run-$($results.Count)-proof.json") -Encoding UTF8
  $scope=@{application=$exe;destination=$destination;protocol='tcp';network=$network.fingerprint;strategy=$trial.label;success=$pass;measurement=$measurement}
  $records+=,$scope;Write-Host "$($trial.label): $($item.status) $reason"
 }
 # Submit only after all finite trials, and reject a changed network.
 foreach($record in $records){[void](Invoke-ServiceIPC 'local.record' $record)}
 $scope=@{application=$exe;destination=$destination;protocol='tcp';network=$network.fingerprint}
 $recommendation=Invoke-ServiceIPC 'local.recommend' $scope
 @{results=$results;recommendation=$recommendation;network=$network}|ConvertTo-Json -Depth 24|Set-Content (Join-Path $ReportDirectory "$run-summary.json") -Encoding UTF8
 Write-Host "Recommended: $($recommendation.recommended). RTT is HTTP application response time, not ICMP. Reports: $ReportDirectory"
 if(@($results|Where-Object{$_.status -eq 'PASS'}).Count -eq 0){throw 'No working route'}
} catch {
 try{@{error=$_.Exception.Message;status=(Invoke-ServiceIPC 'status');capture=(Invoke-ServiceIPC 'capture.diagnostics')}|ConvertTo-Json -Depth 20|Set-Content (Join-Path $ReportDirectory "$run-FAIL.json") -Encoding UTF8}catch{}
 throw
} finally {
 foreach($child in $children){if(!$child.process.HasExited){Stop-Process -Id $child.process.Id -ErrorAction SilentlyContinue}}
 try{[void](Invoke-ServiceIPC 'profile.delete' @{id=$id})}catch{Write-Warning $_}
 try{[void](Invoke-ServiceIPC 'optimize' @{enabled=$original.optimizing})}catch{Write-Warning $_}
}
