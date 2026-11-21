$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../tools/windows/acceptance-checks.ps1')
. (Join-Path $PSScriptRoot '../../tools/windows/common.ps1')
. (Join-Path $PSScriptRoot '../../tools/windows/acceptance-process.ps1')
function Reject([scriptblock]$Body){$failed=$false;try{& $Body|Out-Null}catch{$failed=$true};if(!$failed){throw 'Invalid fixture was accepted'}}
$data=[pscustomobject]@{pid=10;creation_time=20;Sent=30;Received=27;Loss=0.1;observed_sources=@('203.0.113.1')}
$flow=[pscustomobject]@{pid=10;creation_time=20;exe='C:\test-game.exe';destination='203.0.113.1:40000';selected_route='RELAY';relay_id='VPS-01';counters=[pscustomobject]@{captured_packets=30;relayed_packets=30;direct_packets=0;relay_reply_packets=27}}
$evidence=[pscustomobject]@{truncated=$false;flows=@($flow)}
Assert-AcceptanceLoss $data
Assert-AcceptanceRoute $data $evidence $flow.exe $flow.destination 'RELAY' '203.0.113.1'|Out-Null
foreach($counter in @('captured_packets','relayed_packets','relay_reply_packets')) {
 $old=$flow.counters.$counter;$flow.counters.$counter=0
 Reject {Assert-AcceptanceRoute $data $evidence $flow.exe $flow.destination 'RELAY' '203.0.113.1'}
 $flow.counters.$counter=$old
}
$flow.counters.direct_packets=1
Reject {Assert-AcceptanceRoute $data $evidence $flow.exe $flow.destination 'RELAY' '203.0.113.1'}
$flow.counters.direct_packets=0
$flow.relay_id='wrong';Reject {Assert-AcceptanceRoute $data $evidence $flow.exe $flow.destination 'RELAY' '203.0.113.1'};$flow.relay_id='VPS-01'
$flow.selected_route='DIRECT';Reject {Assert-AcceptanceRoute $data $evidence $flow.exe $flow.destination 'RELAY' '203.0.113.1'}
$flow.relay_id='';$flow.counters.relayed_packets=0;$flow.counters.direct_packets=30;$flow.counters.relay_reply_packets=0;$data.observed_sources=@('198.51.100.1')
Assert-AcceptanceRoute $data $evidence $flow.exe $flow.destination 'DIRECT' '203.0.113.1'|Out-Null
$flow.counters.relay_reply_packets=1;Reject {Assert-AcceptanceRoute $data $evidence $flow.exe $flow.destination 'DIRECT' '203.0.113.1'};$flow.counters.relay_reply_packets=0
$evidence.truncated=$true;Reject {Assert-AcceptanceRoute $data $evidence $flow.exe $flow.destination 'DIRECT' '203.0.113.1'};$evidence.truncated=$false
$flow.creation_time=21;Reject {Assert-AcceptanceRoute $data $evidence $flow.exe $flow.destination 'DIRECT' '203.0.113.1'};$flow.creation_time=20
$data.Received=26;$data.Loss=1-26/30;Reject {Assert-AcceptanceLoss $data}
$data.Loss=0;Reject {Assert-AcceptanceLoss $data}
$selected=[pscustomobject]@{id='!selected';mode='MANUAL';relay_id='VPS-01';custom=$true;executables=@('C:\test-game.exe')}
$control=[pscustomobject]@{id='!control';mode='DIRECT';custom=$true;executables=@('C:\control-client.exe')}
$snapshot=[pscustomobject]@{connected=$true;relay_transport=@{relay_id='VPS-01';connected=$true;flow_open=$true};optimizing=$true;backend=@{ready=$true};profiles=@($selected,$control);routes=@(@{id='VPS-01';status='healthy'})}
if(!(Test-AcceptanceReady $snapshot 'C:\test-game.exe' 'C:\control-client.exe' '!selected' '!control' 'MANUAL')){throw 'Valid readiness rejected'}
$snapshot.backend.ready=$false
if(Test-AcceptanceReady $snapshot 'C:\test-game.exe' 'C:\control-client.exe' '!selected' '!control' 'MANUAL'){throw 'Capture startup was ignored'}
$snapshot.backend.ready=$true;$snapshot.profiles+=@([pscustomobject]@{id='!!competing';mode='DIRECT';custom=$true;executables=@('test-game.exe')})
# Windows basename semantics; portable fixture uses absolute executable below.
$snapshot.profiles[-1].executables=@('C:\test-game.exe')
if(Test-AcceptanceReady $snapshot 'C:\test-game.exe' 'C:\control-client.exe' '!selected' '!control' 'MANUAL'){throw 'Competing profile was ignored'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('neexitlag-lf-'+[Guid]::NewGuid().ToString('N'))
try {
 New-Item $temp -ItemType Directory|Out-Null
 foreach($name in @('install.sh','database-sql.py','test.service')){[IO.File]::WriteAllText((Join-Path $temp $name),"line1`r`nline2`r`n")}
 [IO.File]::WriteAllBytes((Join-Path $temp 'binary'),[byte[]]@(1,13,10,255))
 Convert-DeploymentToLF $temp
 foreach($name in @('install.sh','database-sql.py','test.service')){if([IO.File]::ReadAllText((Join-Path $temp $name)).Contains("`r")){throw 'Staged CRLF not normalized'}}
 if([BitConverter]::ToString([IO.File]::ReadAllBytes((Join-Path $temp 'binary'))) -ne '01-0D-0A-FF'){throw 'Binary modified by normalization'}
}finally{Remove-Item $temp -Recurse -Force}
Write-Output 'PASS acceptance route/loss/readiness rejection fixtures and staged CRLF regression (not Windows E2E)'

# Exercise the actual orchestration functions without executing Windows/VPS actions.
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../../tools/windows/acceptance.ps1'),[ref]$tokens,[ref]$parseErrors)
foreach($name in @('Stage','Ensure','Save-UTF8','Complete','Evidence','Save-Diagnostics','Wait-Relay')) {
 $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 Invoke-Expression $definition.Extent.Text
}
$lastReadiness=$null;$lastReadinessState=$null;$run='fixture';$game='C:\test-game.exe';$control='C:\control-client.exe';$selectedId='!selected';$controlId='!control';$profileMode='MANUAL'
$snapshot.profiles=@($selected,$snapshot.profiles[1]);$snapshot.backend.ready=$true
$script:polls=0
function Invoke-ServiceIPC([string]$Method,$Payload) {
 if($Method -eq 'status' -or $Method -eq 'acceptance.readiness') {
  $script:polls++
  if($script:polls -eq 1){throw 'fixture transient IPC startup'}
  $script:snapshot.backend.ready=($script:polls -ge 3)
  return $script:snapshot
 }
 if($Method -eq 'capture.diagnostics'){return $evidence}
 throw 'Unexpected fixture method'
}
$ready=Wait-Relay
if($polls -ne 3 -or !$ready.backend.ready){throw 'Readiness did not retry startup or return actual ready evidence'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('neexitlag-artifacts-'+[Guid]::NewGuid().ToString('N'))
try {
 New-Item $temp -ItemType Directory|Out-Null
 $ReportDirectory=$temp;$results=[Collections.Generic.List[object]]::new();$children=[Collections.Generic.List[object]]::new()
 $path=Join-Path $temp 'failed.json'
 Save-UTF8 $path '{"error":"no authenticated UDP responses","Sent":30,"Received":0}'
 Save-UTF8 ($path+'.stdout') 'fixture client stdout'
 Save-UTF8 ($path+'.stderr') 'fixture client stderr'
 $process=[pscustomobject]@{Id=10;ExitCode=1}
 $process|Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {param($timeout) return $true}
 $process|Add-Member -MemberType ScriptMethod -Name Refresh -Value {}
 $client=[pscustomobject]@{process=$process;report=$path;exe=$game;timeout_ms=1000};$children.Add($client)
 if(Stage 'RELAY zero replies fixture' {Complete $client}){throw 'Zero-reply client accepted'}
 $failure=$results[0]
 if($failure.error -notlike '*no authenticated UDP responses*'){throw 'Wrong client failure reason'}
 $diagnostic=Get-Content $failure.diagnostics -Raw|ConvertFrom-Json
 if($null -eq $diagnostic.status -or $null -eq $diagnostic.clients[0].capture -or !(Test-Path $diagnostic.clients[0].stdout) -or !(Test-Path $diagnostic.clients[0].stderr)){throw 'Failure artifacts were not retained'}
 # An unavailable service must still retain client paths and diagnostic errors.
 function Invoke-ServiceIPC {throw 'fixture service unavailable'}
 $diagnostic=Get-Content (Save-Diagnostics 'unavailable') -Raw|ConvertFrom-Json
 if($diagnostic.clients.Count -ne 1 -or $diagnostic.diagnostic_errors.Count -ne 2 -or !(Test-Path $diagnostic.clients[0].report)){throw 'IPC failure discarded client artifacts'}
}finally{Remove-Item $temp -Recurse -Force}
Write-Output 'PASS actual acceptance startup polling and zero-reply/unavailable-service artifact retention fixtures'

$first=@{measurement_started='2026-10-13T01:00:00Z';measurement_finished='2026-10-13T01:00:20Z'}
$second=@{measurement_started='2026-10-13T01:00:01Z';measurement_finished='2026-10-13T01:00:21Z'}
Assert-AcceptanceOverlap $first $second
$second.measurement_started='2026-10-13T01:00:20Z';Reject {Assert-AcceptanceOverlap $first $second}
$second.measurement_finished='2026-10-13T01:00:19Z';Reject {Assert-AcceptanceOverlap $first $second}
Write-Output 'PASS measured send-window overlap checks (process lifetime alone is insufficient)'

# StrictMode regression: a nullable pre-wait code is not a real non-zero code.
# Exercise Complete itself, retaining exact exit status and report assertions.
$temp=Join-Path ([IO.Path]::GetTempPath()) ('neexitlag-completion-'+[Guid]::NewGuid().ToString('N'))
function Completion-Fixture([int]$Code,[string]$JSON) {
 $path=Join-Path $temp ([Guid]::NewGuid().ToString('N')+'.json')
 Save-UTF8 $path $JSON
 $process=[pscustomobject]@{Id=10;ExitCode=$null;FinalExitCode=$Code;TimedWait=$false;FullWait=$false}
 $process|Add-Member ScriptMethod WaitForExit {param($timeout) if($null -eq $timeout){$this.FullWait=$true;$this.ExitCode=$this.FinalExitCode}else{$this.TimedWait=$true;return $true}}
 $process|Add-Member ScriptMethod Refresh {if(!$this.FullWait){throw 'Refresh before complete wait'}}
 return [pscustomobject]@{process=$process;report=$path;exe=$game;timeout_ms=1000}
}
function Expect-CompletionFailure($Client,[string]$Pattern) {
 $caught=$null
 try {Complete $Client|Out-Null}catch{$caught=$_.Exception.Message}
 if($null -eq $caught -or $caught -notlike $Pattern){throw "Unexpected completion outcome: $caught (expected $Pattern)"}
}
try {
 New-Item $temp -ItemType Directory|Out-Null
 $success='{"pid":10,"creation_time":20,"exe":"C:\\test-game.exe","Sent":100,"Received":98,"Loss":0.02,"observed_sources":["203.0.113.1"]}'
 $client=Completion-Fixture 0 $success
 $completed=Complete $client
 if($completed.Received -ne 98 -or $client.exit_code -ne 0 -or !$client.process.FullWait -or !$client.process.TimedWait){throw 'Successful strict-mode report or full process wait rejected'}
 Expect-CompletionFailure (Completion-Fixture 7 '{"error":"fixture fatal send"}') '*exit=7*fixture fatal send*'
 Expect-CompletionFailure (Completion-Fixture 8 $success) '*exit=8*No error field*'
 # A valid JSON/exit=0 still must pass loss and actual route proof.
 Expect-CompletionFailure (Completion-Fixture 0 $success.Replace('"Received":98,"Loss":0.02','"Received":80,"Loss":0.2')) '*loss exceeds*'
 Expect-CompletionFailure (Completion-Fixture 0 $success.Replace('"Loss":0.02','"Loss":0')) '*report is inconsistent*'
 Expect-CompletionFailure (Completion-Fixture 0 $success.Replace('"pid":10','"pid":11')) '*real Windows identity*'
 Expect-CompletionFailure (Completion-Fixture 0 $success.Replace('"pid":10','"error":"contradictory failure","pid":10')) '*despite exit=0*'
 $flow.selected_route='RELAY';$flow.relay_id='VPS-01';$flow.counters.captured_packets=100;$flow.counters.relayed_packets=100;$flow.counters.direct_packets=0;$flow.counters.relay_reply_packets=98
 Assert-AcceptanceRoute $completed $evidence $game $flow.destination 'RELAY' '203.0.113.1'|Out-Null
 $flow.counters.relayed_packets=0
 Reject {Assert-AcceptanceRoute $completed $evidence $game $flow.destination 'RELAY' '203.0.113.1'}
 $unavailable=Completion-Fixture 0 $success
 $unavailable.process|Add-Member ScriptMethod WaitForExit {param($timeout) if($null -ne $timeout){return $true}} -Force
 $unavailable.process|Add-Member ScriptMethod Refresh {} -Force
 Expect-CompletionFailure $unavailable '*exit code unavailable*'
}finally{Remove-Item $temp -Recurse -Force}
Write-Output 'PASS StrictMode Complete: exit 0 without error, non-zero with/without error, missing code, identity/loss/route rejection'

# Real Start-Process with redirected output on both platforms. Windows CI runs
# this against Windows process handles; fixture JSON is not a networking proof.
$temp=Join-Path ([IO.Path]::GetTempPath()) ('neexitlag redirected '+[Guid]::NewGuid().ToString('N'))
try {
 New-Item $temp -ItemType Directory|Out-Null
 $child=Join-Path $temp 'child.ps1'
 Save-UTF8 $child @'
param([string]$Report,[int]$ExitStatus,[int]$WithError)
Set-StrictMode -Version Latest
$process=Get-Process -Id $PID
$data=@{pid=$PID;creation_time=$process.StartTime.ToFileTimeUtc();exe=$process.Path;Sent=100;Received=98;Loss=0.02;observed_sources=@('203.0.113.1')}
if($WithError){$data.error='redirected fixture failure'}
[IO.File]::WriteAllText($Report,($data|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
[Console]::Out.WriteLine('fixture stdout complete')
[Console]::Error.WriteLine('fixture stderr complete')
exit $ExitStatus
'@
 $shell=(Get-Process -Id $PID).Path
 foreach($case in @(@(0,0),@(9,1),@(10,0))) {
  $path=Join-Path $temp ("report-$($case[0]).json")
  $arguments="-NoProfile -File `"$child`" -Report `"$path`" -ExitStatus $($case[0]) -WithError $($case[1])"
  $process=Start-AcceptanceProcess $shell $arguments $path
  try {
   $client=[pscustomobject]@{process=$process;report=$path;exe=$shell;timeout_ms=30000}
   if($case[0] -eq 0){$report=Complete $client;if($report.Received -ne 98){throw 'Real successful process report rejected'}}
   elseif($case[1]){Expect-CompletionFailure $client '*exit=9*redirected fixture failure*'}
   else{Expect-CompletionFailure $client '*exit=10*No error field*'}
   if($client.exit_code -ne $case[0]){throw 'Real process exit code not retained'}
   if((Get-Content ($path+'.stdout') -Raw).Trim() -ne 'fixture stdout complete' -or (Get-Content ($path+'.stderr') -Raw).Trim() -ne 'fixture stderr complete'){throw 'Redirected output not fully retained after exit'}
  }finally{if(!$process.HasExited){Stop-Process -Id $process.Id -ErrorAction SilentlyContinue};$process.Dispose()}
 }
}finally{Remove-Item $temp -Recurse -Force}
Write-Output 'PASS real redirected Start-Process success/failure with spaces, exact exit status and complete stdout/stderr'

# Readiness has separate MANUAL session and AUTO optimizer contracts.
$snapshot.routes=@([pscustomobject]@{id='VPS-01';status='unhealthy';score=$null;quality=[pscustomobject]@{health='unhealthy';network_sample_count=45;round_count=9}})
$snapshot|Add-Member NoteProperty primary 'DIRECT' -Force
$snapshot|Add-Member NoteProperty settings @{automatic=$true} -Force
foreach($health in @('unhealthy','degraded','warming_up')) {
 $snapshot.routes[0].status=$health;$snapshot.routes[0].quality.health=$health
 if(!(Test-AcceptanceReady $snapshot $game $control $selectedId $controlId 'MANUAL')){throw "MANUAL waited for $health quality instead of real transport evidence"}
}
$snapshot.relay_transport.flow_open=$false
if(Test-AcceptanceReady $snapshot $game $control $selectedId $controlId 'MANUAL'){throw 'Connected session alone proved flow-open readiness'}
$snapshot.relay_transport.flow_open=$true
$snapshot.connected=$false
if(Test-AcceptanceReady $snapshot $game $control $selectedId $controlId 'MANUAL'){throw 'Disconnected service accepted'}
$snapshot.connected=$true
$snapshot.profiles[0].mode='AUTO'
$snapshot.routes[0].status='healthy';$snapshot.routes[0].score=42;$snapshot.routes[0].quality.health='healthy';$snapshot.primary='VPS-01'
if(!(Test-AcceptanceReady $snapshot $game $control $selectedId $controlId 'AUTO')){throw 'Naturally selected eligible AUTO relay rejected'}
foreach($condition in @('samples','rounds','health','score','primary','automatic')) {
 switch($condition){
  'samples' {$snapshot.routes[0].quality.network_sample_count=19}
  'rounds' {$snapshot.routes[0].quality.round_count=2}
  'health' {$snapshot.routes[0].quality.health='unhealthy'}
  'score' {$snapshot.routes[0].score=$null}
  'primary' {$snapshot.primary='DIRECT'}
  'automatic' {$snapshot.settings.automatic=$false}
 }
 if(Test-AcceptanceReady $snapshot $game $control $selectedId $controlId 'AUTO'){throw "AUTO ignored $condition eligibility"}
 $snapshot.routes[0].quality.network_sample_count=45;$snapshot.routes[0].quality.round_count=9;$snapshot.routes[0].quality.health='healthy';$snapshot.routes[0].score=42;$snapshot.primary='VPS-01';$snapshot.settings.automatic=$true
}
$snapshot.profiles[0].mode='MANUAL'
Write-Output 'PASS MANUAL transport readiness independent of quality; AUTO requires history, eligibility and natural selection'

# Deterministic deadline tests use a virtual monotonic clock, never scheduler timing.
foreach($boundary in @('exact','sleep-overshoot','inflight-check')) {
 $clock=@{ms=0;calls=0}
 $get={
  $clock.calls++
  if($boundary -eq 'inflight-check' -and $clock.calls -eq 1){$snapshot.backend.ready=$false;$clock.ms=1001}
  else{$snapshot.backend.ready=($clock.ms -ge 1000)}
  return $snapshot
 }
 $delay={param($ms) $clock.ms+=$ms;if($boundary -eq 'sleep-overshoot'){$clock.ms+=3}}
 $result=Wait-AcceptanceReadiness -TimeoutMS 1000 -PollMS 500 -Now {return $clock.ms} -Delay $delay -GetSnapshot $get -Evaluate {param($s) Get-AcceptanceReadiness $s $game $control $selectedId $controlId 'MANUAL'}
 if(!$result.backend.ready -or $clock.ms -lt 1000 -or $clock.calls -lt 2){throw "Ready at $boundary boundary was falsely rejected"}
}
# The final false check reports concrete blockers; a later diagnostics snapshot
# cannot retroactively replace the exact evidence used for the timeout decision.
$clock=@{ms=0;calls=0};$snapshot.backend.ready=$false;$snapshot.relay_transport.flow_open=$false
$message=$null
try {
 Wait-AcceptanceReadiness -TimeoutMS 1000 -PollMS 500 -Now {return $clock.ms} -Delay {param($ms) $clock.ms+=$ms} -GetSnapshot {$clock.calls++;return $snapshot} -Evaluate {param($s) Get-AcceptanceReadiness $s $game $control $selectedId $controlId 'MANUAL'}|Out-Null
}catch{$message=$_.Exception.Message}
if($null -eq $message -or $message -notlike '*backend*relay transport*' -or $clock.calls -ne 3 -or $clock.ms -ne 1000){throw "Final timeout check/blockers missing: $message"}
$snapshot.backend.ready=$true;$snapshot.relay_transport.flow_open=$true
Write-Output 'PASS readiness exact deadline, sleep overshoot, in-flight completion and concrete final timeout blockers'

$missingSnapshot=[pscustomobject]@{connected=$true;optimizing=$true;backend=@{ready=$true};profiles=@();routes=@();primary='DIRECT';settings=@{automatic=$true};relay_transport=$snapshot.relay_transport}
$state=Get-AcceptanceReadiness $missingSnapshot $game $control $selectedId $controlId 'AUTO'
if($state.ready -or ($state.missing -join ';') -notlike '*selected profile*control profile*quality*AUTO eligibility*'){throw 'Missing profiles/history did not give specific blockers'}
Write-Output 'PASS absent profiles and quality produce specific readiness blockers'
