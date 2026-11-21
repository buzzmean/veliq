[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$VpsPublicIP,
 [Parameter(Mandatory=$true)][string]$SSHUser,
 [Parameter(Mandatory=$true)][ValidateRange(1,65535)][int]$SSHPort,
 [string]$Bundle=(Join-Path $PSScriptRoot '..\..\.e2e\bundle'),
 [string]$Binaries=(Join-Path $PSScriptRoot '..\..\bin\windows-e2e'),
 [string]$ReportDirectory=(Join-Path $PSScriptRoot '..\..\.e2e\reports')
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'acceptance-checks.ps1')
. (Join-Path $PSScriptRoot 'acceptance-process.ps1')
$results=[Collections.Generic.List[object]]::new()
$children=[Collections.Generic.List[object]]::new()
$run=[Guid]::NewGuid().ToString('N')
$selectedId='!e2e-selected-'+$run;$controlId='!e2e-control-'+$run
$lastReadiness=$null;$lastReadinessState=$null;$originalSettings=$null;$originalManifest=$null;$originalOptimizing=$null;$remoteRelayStopped=$false;$remoteCPStopped=$false;$profileMode='MANUAL'
function Stage([string]$Name,[scriptblock]$Body){
 try {$data=& $Body;$results.Add([pscustomobject]@{name=$Name;status='PASS';data=$data});Write-Host "PASS $Name";return $true}
 catch {$message=$_.Exception.Message;$diagnostics=Save-Diagnostics $Name;$results.Add([pscustomobject]@{name=$Name;status='FAIL';error=$message;diagnostics=$diagnostics});Write-Host "FAIL $Name : $message";return $false}
}
function Ensure([bool]$Condition,[string]$Message){if(!$Condition){throw $Message}}
function Save-UTF8([string]$Path,[string]$Text){[IO.File]::WriteAllText($Path,$Text,[Text.UTF8Encoding]::new($false))}
function Profile([string]$Mode){$script:profileMode=$Mode;$payload=@{id=$selectedId;name='Real E2E selected process';executables=@($game);mode=$Mode;custom=$true};if($Mode -eq 'MANUAL'){$payload.relay_id='VPS-01'};[void](Invoke-ServiceIPC 'profile.set' $payload)}
function Launch([string]$Exe,[string]$Label,[int]$Count=100,[int]$Warmup=0){
 $path=Join-Path $ReportDirectory "$run-$Label.json"
 $token=Join-Path $Bundle 'windows\echo.token'
 $args="-target ${VpsPublicIP}:40000 -token-file `"$token`" -count $Count -warmup-count $Warmup -interval 200ms -timeout 3s -quiet -report `"$path`""
 $proc=Start-AcceptanceProcess $Exe $args $path
 $value=[pscustomobject]@{process=$proc;report=$path;exe=$Exe;timeout_ms=(($Count+$Warmup)*200+15000);exit_code=$null};$children.Add($value);return $value
}
function Complete($Client){
 $exitCode=Wait-AcceptanceProcessExit $Client.process $Client.timeout_ms $Client.report
 $Client|Add-Member -NotePropertyName exit_code -NotePropertyValue $exitCode -Force
 Ensure (Test-Path $Client.report) "Client produced no report (exit=$exitCode); inspect $($Client.report).stdout / $($Client.report).stderr"
 $raw=Get-Content $Client.report -Raw|ConvertFrom-Json
 $errorProperty=$raw.PSObject.Properties['error']
 $reportedError=if($null -ne $errorProperty){[string]$errorProperty.Value}else{''}
 if($exitCode -ne 0){
  $reason=if([string]::IsNullOrWhiteSpace($reportedError)){'No error field in report; inspect stderr for process failure'}else{$reportedError}
  throw "Client failed (exit=$exitCode): $reason; report/stdout/stderr retained at $($Client.report)"
 }
 Ensure ([string]::IsNullOrWhiteSpace($reportedError)) "Client reported error despite exit=0: $reportedError; artifacts at $($Client.report)"
 $data=$raw
 Ensure ($data.pid -eq $Client.process.Id -and $data.creation_time -gt 0 -and $data.exe -ieq $Client.exe) 'Client did not report its real Windows identity'
 Assert-AcceptanceLoss $data
 return $data
}
function Evidence($Client){return Invoke-ServiceIPC 'capture.diagnostics' @{pid=$Client.process.Id}}
function Restart-Local {
 Restart-Service VELIQ
 (Get-Service VELIQ).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
}
function Control-Proof([string]$Label){$client=Launch $control $Label;$data=Complete $client;Ensure (@($data.observed_sources).Count -gt 0 -and $data.observed_sources -notcontains $relayEgress) 'Control source is indistinguishable from relay source';return $data}
function Save-Diagnostics([string]$Label) {
 $path=Join-Path $ReportDirectory ("$run-"+($Label -replace '[^a-zA-Z0-9-]','_')+'-diagnostics.json')
 $capture=@();$snapshot=$null;$errors=@()
 try {$snapshot=Invoke-ServiceIPC 'status'}catch{$errors+="status: $($_.Exception.Message)"}
 foreach($child in $children){
  $entry=@{pid=$child.process.Id;exe=$child.exe;report=$child.report;stdout=($child.report+'.stdout');stderr=($child.report+'.stderr');capture=$null;exit_code=$(if($null -ne $child.PSObject.Properties['exit_code']){$child.exit_code}else{$null})}
  try {$entry.capture=Evidence $child}catch{$errors+="PID $($child.process.Id): $($_.Exception.Message)"}
  $capture+=$entry
 }
 try {Save-UTF8 $path (@{status=$snapshot;last_readiness=$lastReadiness;readiness_conditions=$lastReadinessState;readiness_mode=$profileMode;clients=$capture;diagnostic_errors=$errors}|ConvertTo-Json -Depth 18);return $path}catch{return "Diagnostic persistence failed: $($_.Exception.Message)"}
}
function Wait-Relay {
 $budget=if($profileMode -eq 'AUTO'){135000}else{60000}
 return Wait-AcceptanceReadiness -TimeoutMS $budget -GetSnapshot {
  $script:lastReadiness=$null;$script:lastReadinessState=$null
  $script:lastReadiness=Invoke-ServiceIPC 'acceptance.readiness' @{relay_id='VPS-01'}
  return $script:lastReadiness
 } -Evaluate {param($snapshot) $script:lastReadinessState=Get-AcceptanceReadiness $snapshot $game $control $selectedId $controlId $profileMode;return $script:lastReadinessState}
}

try {
 New-Item -ItemType Directory -Force $ReportDirectory|Out-Null
 $prereq=Stage 'Prerequisites' {
  Assert-Administrator
  $script:VpsPublicIP=Assert-VpsIPv4 $VpsPublicIP
  Assert-Ssh $SSHUser $SSHPort
  $script:Bundle=(Resolve-Path $Bundle).Path;$script:Binaries=(Resolve-Path $Binaries).Path;$script:ReportDirectory=(Resolve-Path $ReportDirectory).Path
  $script:game=(Resolve-Path (Join-Path $Binaries 'test-game.exe')).Path;$script:control=(Resolve-Path (Join-Path $Binaries 'control-client.exe')).Path
  $service=Get-Service VELIQ;Ensure ($service.Status -eq 'Running') 'Service is not running'
  $manifestPath="$env:ProgramData\VELIQ\service.json"
  $script:originalManifest=[IO.File]::ReadAllText($manifestPath);$m=$originalManifest|ConvertFrom-Json
  Ensure ($m.probe_target -eq "${VpsPublicIP}:40000" -and $m.control_plane_url -eq "https://${VpsPublicIP}:8443") 'Installed service targets do not match the requested VPS'
  Ensure ((Get-FileHash (Join-Path $m.driver.directory 'WinDivert.dll') -Algorithm SHA256).Hash -eq $m.driver.dll_sha256) 'Driver DLL pin mismatch'
  Ensure ((Get-FileHash (Join-Path $m.driver.directory 'WinDivert64.sys') -Algorithm SHA256).Hash -eq $m.driver.driver_sha256) 'Driver SYS pin mismatch'
  Ensure ((Get-AuthenticodeSignature (Join-Path $m.driver.directory 'WinDivert64.sys')).Status -eq 'Valid') 'SYS signature not trusted'
  $tcp=[Net.Sockets.TcpClient]::new();try{Ensure ($tcp.ConnectAsync($VpsPublicIP,8443).Wait(3000)) 'VPS TCP8443 timeout';Ensure $tcp.Connected 'VPS TCP8443 unreachable'}finally{$tcp.Dispose()}
  $snapshot=Invoke-ServiceIPC 'status';$script:originalSettings=$snapshot.settings;$script:originalOptimizing=$snapshot.optimizing
  [void](Invoke-ServiceIPC 'settings.set' @{automatic=$true;failover='DIRECT';update_channel=$snapshot.settings.update_channel})
  [void](Invoke-ServiceIPC 'optimize' @{enabled=$true})
  [void](Invoke-ServiceIPC 'profile.set' @{id=$controlId;name='Real E2E direct control';executables=@($control);mode='DIRECT';custom=$true})
  Profile 'MANUAL'
  $script:routesBefore=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'|Select-Object InterfaceIndex,NextHop,RouteMetric|Sort-Object InterfaceIndex,NextHop|ConvertTo-Json -Compress
  $state=Wait-Relay
  $referenceJSON=Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort "sudo -n /opt/neexitlag/bin/probe-client -target ${VpsPublicIP}:40000 -token-file /etc/neexitlag/echo/echo.token -quiet -count 5 -interval 100ms -timeout 1s"
  $reference=($referenceJSON -join [Environment]::NewLine)|ConvertFrom-Json
  Ensure ($reference.Received -gt 0 -and @($reference.observed_sources).Count -eq 1) 'VPS could not reach its public echo endpoint (provider NAT/hairpin/firewall)'
  $script:relayEgress=$reference.observed_sources[0]
  @{relay_egress_reference=$reference;platform=[Environment]::OSVersion.VersionString;vps=$VpsPublicIP;backend=$state.backend;target="${VpsPublicIP}:40000"}
 }
 if(!$prereq){throw 'Prerequisites failed; real Windows E2E was not exercised'}
 # Both are ordinary UDP programs running concurrently on this PC.
 $a=Launch $game 'selected' 100 10;$b=Launch $control 'direct' 100 10
 $dataA=$null;$dataB=$null;$proofA=$null;$proofB=$null
 [void](Stage 'A selected.exe RELAY' {
  $script:dataA=Complete $a;$script:proofA=Evidence $a
  $counts=Assert-AcceptanceRoute $dataA $proofA $game "${VpsPublicIP}:40000" 'RELAY' $relayEgress
  @{client=$dataA;capture=$proofA;verified_counters=$counts;binary_sha256=(Get-FileHash $game -Algorithm SHA256).Hash}
 })
 [void](Stage 'B control-client.exe DIRECT' {
  $script:dataB=Complete $b;$script:proofB=Evidence $b
  $counts=Assert-AcceptanceRoute $dataB $proofB $control "${VpsPublicIP}:40000" 'DIRECT' $relayEgress
  @{client=$dataB;capture=$proofB;verified_counters=$counts;binary_sha256=(Get-FileHash $control -Algorithm SHA256).Hash}
 })
 [void](Stage 'C simultaneous selected/control' {
  Ensure ($null -ne $dataA -and $null -ne $dataB) 'Prior traffic reports missing'
  Ensure (@($results|Where-Object{$_.name -like 'A *' -or $_.name -like 'B *'}|Where-Object{$_.status -ne 'PASS'}).Count -eq 0) 'A/B route proof failed'
  Assert-AcceptanceOverlap $dataA $dataB
  @{selected_pid=$dataA.pid;direct_pid=$dataB.pid;overlap=$true;selected_start=$dataA.measurement_started;selected_end=$dataA.measurement_finished;direct_start=$dataB.measurement_started;direct_end=$dataB.measurement_finished}
 })
 [void](Stage 'F service transport loop prevention' {
  $servicePID=(Get-CimInstance Win32_Service -Filter "Name='VELIQ'").ProcessId
  $evidence=Invoke-ServiceIPC 'capture.diagnostics' @{pid=$servicePID}
  $transport=@($evidence.flows|Where-Object{$_.destination -eq "${VpsPublicIP}:4433"})
  Ensure ($transport.Count -gt 0) 'No service relay-transport identity evidence'
  Ensure (($transport|ForEach-Object {$_.counters.loop_prevention_packets}|Measure-Object -Sum).Sum -gt 0) 'No explicit service transport bypass counters'
  Ensure (($transport|ForEach-Object {$_.counters.relayed_packets}|Measure-Object -Sum).Sum -eq 0) 'Service relay transport entered relay routing'
  $evidence
 })
 [void](Stage 'D AUTO relay failure DIRECT fallback' {
  Profile 'AUTO'
  $state=Wait-Relay
  # Wait-Relay AUTO requires eligible quality and a natural VPS-01 primary.
  $d=Launch $game 'auto-failover' 200
  Start-Sleep -Seconds 3
  $before=Evidence $d
  Ensure (($before.flows|ForEach-Object {$_.counters.relayed_packets}|Measure-Object -Sum).Sum -gt 0) 'AUTO flow did not actually relay before failure'
  $script:remoteRelayStopped=$true
  Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort 'sudo -n systemctl stop neexitlag-relay && ! sudo -n systemctl is-active --quiet neexitlag-relay'
  $fallback=Complete $d;$after=Evidence $d
  Ensure ($fallback.observed_sources -contains $relayEgress -and @($fallback.observed_sources|Where-Object{$_ -ne $relayEgress}).Count -gt 0) 'Echo did not observe a real relay-to-DIRECT transition'
  Ensure (($after.flows|ForEach-Object {$_.counters.direct_packets}|Measure-Object -Sum).Sum -gt 0) 'No native DIRECT fallback packets'
  @{client=$fallback;before=$before;after=$after}
 })
 if($remoteRelayStopped){Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort 'sudo -n systemctl start neexitlag-relay';$remoteRelayStopped=$false;Restart-Local}
 Profile 'MANUAL'
 [void](Wait-Relay)
 [void](Stage 'Config outage valid LKG and ordinary networking' {
  $script:remoteCPStopped=$true
  Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort 'sudo -n systemctl stop neexitlag-control-plane && ! sudo -n systemctl is-active --quiet neexitlag-control-plane'
  # Existing authenticated relay session is independent of control-plane forwarding.
  $selected=Launch $game 'cp-outage-selected' 100 10;$ctrl=Launch $control 'cp-outage-control' 100 10
  $selectedData=Complete $selected;$directData=Complete $ctrl
  Ensure ($selectedData.observed_sources -contains $relayEgress) 'Existing authenticated session did not survive CP outage'
  Ensure ($directData.observed_sources -notcontains $relayEgress) 'Ordinary networking broke during CP outage'
  @{selected=$selectedData;control=$directData;scope='short outage with valid LKG and existing session; not expired-cache acceptance'}
 })
 if($remoteCPStopped){Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort 'sudo -n systemctl start neexitlag-control-plane';$remoteCPStopped=$false}
 [void](Stage 'E graceful service stop DIRECT continuity' {
  $ctrl=Launch $control 'service-stop' 160
  Start-Sleep -Seconds 2
  Stop-Service VELIQ;(Get-Service VELIQ).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
  $data=Complete $ctrl;Ensure ($data.observed_sources -notcontains $relayEgress) 'Control did not remain DIRECT'
  $data
 })
 Start-Service VELIQ;(Get-Service VELIQ).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
 [void](Stage 'E abrupt service crash DIRECT continuity and recovery' {
  $ctrl=Launch $control 'service-crash' 160
  Start-Sleep -Seconds 2
  $servicePID=(Get-CimInstance Win32_Service -Filter "Name='VELIQ'").ProcessId
  Ensure ($servicePID -gt 0) 'SCM did not report service PID'
  Stop-Process -Id $servicePID -Force
  $data=Complete $ctrl;Ensure ($data.observed_sources -notcontains $relayEgress) 'Ordinary networking did not remain DIRECT across crash'
  (Get-Service VELIQ).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
  Ensure (Invoke-ServiceIPC 'status').backend.ready 'Service did not recover capture'
  $data
 })
 [void](Stage 'Driver dependency error fail-open' {
  Stop-Service VELIQ;(Get-Service VELIQ).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
  $bad=$originalManifest|ConvertFrom-Json;$bad.driver.dll_sha256='0'*64
  Save-UTF8 "$env:ProgramData\VELIQ\service.json" ($bad|ConvertTo-Json -Depth 8)
  Start-Service VELIQ;(Get-Service VELIQ).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
  $s=Invoke-ServiceIPC 'status'
  Ensure (!$s.backend.ready -and $s.backend.error -like '*SHA256 mismatch*') 'Bad dependency pin did not fail closed before capture'
  $data=Control-Proof 'driver-error-direct'
  @{backend=$s.backend;control=$data;scope='dependency validation failure; not a simulated kernel-driver crash'}
 })
 [void](Stage 'Default route unchanged' {
  $after=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'|Select-Object InterfaceIndex,NextHop,RouteMetric|Sort-Object InterfaceIndex,NextHop|ConvertTo-Json -Compress
  Ensure ($after -eq $routesBefore) 'Default routes changed during acceptance; inspect network configuration'
  $after
 })
} catch {$message=$_.Exception.Message;$diagnostics=Save-Diagnostics 'Execution';$results.Add([pscustomobject]@{name='Execution';status='FAIL';error=$message;diagnostics=$diagnostics})}
finally {
 foreach($child in $children){if(!$child.process.HasExited){Stop-Process -Id $child.process.Id -ErrorAction SilentlyContinue}}
 try {
  if($remoteRelayStopped){Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort 'sudo -n systemctl start neexitlag-relay'}
  if($remoteCPStopped){Invoke-VpsCommand $VpsPublicIP $SSHUser $SSHPort 'sudo -n systemctl start neexitlag-control-plane'}
  if($null -ne $originalManifest){Stop-Service VELIQ -ErrorAction SilentlyContinue;(Get-Service VELIQ).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20));Save-UTF8 "$env:ProgramData\VELIQ\service.json" $originalManifest;Start-Service VELIQ;(Get-Service VELIQ).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))}
  if($null -ne $originalSettings){[void](Invoke-ServiceIPC 'settings.set' $originalSettings);foreach($id in @($selectedId,$controlId)){try{[void](Invoke-ServiceIPC 'profile.delete' @{id=$id})}catch{}};[void](Invoke-ServiceIPC 'optimize' @{enabled=$originalOptimizing})}
 } catch {$results.Add([pscustomobject]@{name='Restoration';status='FAIL';error=$_.Exception.Message})}
 foreach($required in @('Prerequisites','A selected.exe RELAY','B control-client.exe DIRECT','C simultaneous selected/control','D AUTO relay failure DIRECT fallback','E graceful service stop DIRECT continuity','E abrupt service crash DIRECT continuity and recovery','F service transport loop prevention','Config outage valid LKG and ordinary networking','Driver dependency error fail-open','Default route unchanged')){
  if(@($results|Where-Object{$_.name -eq $required}).Count -eq 0){$results.Add([pscustomobject]@{name=$required;status='FAIL';error='NOT RUN due to failed prerequisite or execution error'});Write-Host "FAIL $required : NOT RUN"}
 }
 $passed=@($results|Where-Object{$_.status -ne 'PASS'}).Count -eq 0
 $report=[ordered]@{schema=1;run_id=$run;generated_at=[DateTimeOffset]::UtcNow.ToString('o');real_windows=($env:OS -eq 'Windows_NT');real_public_internet=(@($results|Where-Object{($_.name -like 'A *' -or $_.name -like 'B *') -and $_.status -eq 'PASS'}).Count -eq 2);synthetic_impairment=$false;overall=$(if($passed){'PASS'}else{'FAIL'});vps_public_ip=$VpsPublicIP;artifacts=@($children|ForEach-Object {@{pid=$_.process.Id;exe=$_.exe;report=$_.report;stdout=($_.report+'.stdout');stderr=($_.report+'.stderr');exit_code=$_.exit_code}});tests=$results.ToArray()}
 $path=Join-Path $ReportDirectory "$run-acceptance.json"
 New-Item -ItemType Directory -Force $ReportDirectory|Out-Null
 Save-UTF8 $path ($report|ConvertTo-Json -Depth 14)
 Write-Host "Report: $path"
}
if(!$passed){exit 1}
