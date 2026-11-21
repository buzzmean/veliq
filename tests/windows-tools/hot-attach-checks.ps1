$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\..\tools\windows\simultaneous-checks.ps1')
. (Join-Path $PSScriptRoot '..\..\tools\windows\hot-attach-checks.ps1')
function Check($value,[string]$message){if(!$value){throw $message}}
function Reject([scriptblock]$code){$failed=$false;try{&$code|Out-Null}catch{$failed=$true};if(!$failed){throw 'Invalid HOT ATTACH evidence accepted'}}
$root=[pscustomobject]@{PID=5;CreationTime=10;Path='C:\Apps\chrome.exe';ParentPID=1}
$child=[pscustomobject]@{PID=6;CreationTime=11;Path=$root.Path;ParentPID=5}
$roots=@(Get-HotAttachRoots @($root,$child) @('chrome.exe'));Check ($roots.Count -eq 1 -and $roots[0].PID -eq 5) 'Chrome child mistaken for root'
Assert-HotAttachRoots $roots @($root)
Reject {Assert-HotAttachRoots $roots @($child)}
$reused=[pscustomobject]@{PID=5;CreationTime=99;Path=$root.Path};Reject {Assert-HotAttachRoots $roots @($reused)}
Reject {Get-HotAttachRoots @($root) @('Discord.exe')}
$relay=@{flow_id=1;pid=7;creation_time=20;exe='msedge.exe';hot_attach=@{epoch=2;state='HOT_ATTACH_ROUTE_OPENED'};selected_route='RELAY';policy=@{action='RELAY_REQUIRED'};counters=@{relayed_bytes=10;relay_reply_bytes=20;direct_bytes=0;direct_packets=0}}
$yt=@{flow_id=2;pid=5;creation_time=10;exe=$root.Path;protocol='tcp';domain='www.youtube.com';hot_attach=@{epoch=2;state='HOT_ATTACH_TRANSFORM_APPLIED'};selected_route='DIRECT_PLUS';strategy='p2-youtube-disorder';chain='tcp-multisplit + tcp-disorder';policy=@{source='configured_baseline'};counters=@{direct_plus_packets=1;relayed_bytes=0}}
$state=@{Flows=@{'1'=$relay;'2'=$yt};Lost=$false};$hot=@{epoch=2;state='HOT_ATTACH_NETWORK_READY'}
Check ((Get-HotAttachProof $state $hot 2 @('msedge.exe')).transport_evidence_pass) 'Fresh HOT ATTACH proof rejected'
$relay.hot_attach.state='HOT_ATTACH_RETIRED';Check (!(Get-HotAttachProof $state $hot 2 @('msedge.exe')).transport_evidence_pass) 'Old connection counted as fresh relay'
$relay.hot_attach.state='HOT_ATTACH_ROUTE_OPENED';$relay.counters.direct_bytes=1
Check (!(Get-HotAttachProof $state $hot 2 @('msedge.exe')).transport_evidence_pass) 'Transition DIRECT leak hidden'
$relay.counters.direct_bytes=0;$hot.state='HOT_ATTACH_INCOMPLETE';Reject {Get-HotAttachProof $state $hot 2 @('msedge.exe')}
$hot.state='HOT_ATTACH_NETWORK_READY';Reject {Get-HotAttachProof $state $hot 3 @('msedge.exe')}
$state.Lost=$true;Reject {Get-HotAttachProof $state $hot 2 @('msedge.exe')}
Write-Host 'PASS HOT ATTACH original root/PID-birth, fresh route/transform evidence, transition leak, deadline/generation and loss gates'
# Execute the real helper in owned child shells with a temporary IPC fixture.
# Force failure immediately after OFF; both original ON and OFF must be restored.
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('neexitlag-hot-restore-'+[Guid]::NewGuid().ToString('N'))
$oldLog=$env:NEEXITLAG_HOT_RESTORE_LOG;$oldInitial=$env:NEEXITLAG_HOT_RESTORE_INITIAL
try{
 New-Item -ItemType Directory -Force $fixture|Out-Null
 foreach($name in @('acceptance-hot-attach.ps1','simultaneous-checks.ps1','hot-attach-checks.ps1')){Copy-Item (Join-Path $PSScriptRoot ('..\..\tools\windows\'+$name)) (Join-Path $fixture $name)}
 @'
Set-StrictMode -Version Latest
$script:fixtureOff=$false
function Invoke-ServiceIPC($Method,$Payload=$null){
 switch($Method){
  'status' {return @{optimizing=($env:NEEXITLAG_HOT_RESTORE_INITIAL -eq '1')}}
  'processes' {
   if($script:fixtureOff){throw 'expected owned fixture failure after OFF'}
   $rows=@();$n=1;foreach($name in @('chrome.exe','msedge.exe','ChatGPT.exe','codex.exe','Discord.exe')){$rows += [pscustomobject]@{PID=$n;CreationTime=10;Path=('C:\Apps\'+$name);ParentPID=0};$n++};return $rows
  }
  'optimize' {[IO.File]::AppendAllText($env:NEEXITLAG_HOT_RESTORE_LOG,([string][bool]$Payload.enabled)+[Environment]::NewLine);$script:fixtureOff=$true;return @{}}
  default {throw 'unexpected IPC in restore fixture'}
 }
}
'@|Set-Content -LiteralPath (Join-Path $fixture 'common.ps1') -Encoding UTF8
 $runner=(Get-Process -Id $PID).Path
 foreach($initial in @('1','0')){
  $env:NEEXITLAG_HOT_RESTORE_INITIAL=$initial
  $env:NEEXITLAG_HOT_RESTORE_LOG=Join-Path $fixture ('calls-'+$initial+'.txt')
  $reports=Join-Path $fixture ('reports-'+$initial)
  $scriptFile=Join-Path $fixture 'acceptance-hot-attach.ps1'
  $fixtureArguments=@('-NoProfile','-File',('"{0}"' -f $scriptFile),'-StageSeconds','20','-ReportDirectory',('"{0}"' -f $reports))
  $child=Start-Process -FilePath $runner -ArgumentList $fixtureArguments -PassThru -RedirectStandardOutput (Join-Path $fixture ($initial+'-stdout.txt')) -RedirectStandardError (Join-Path $fixture ($initial+'-stderr.txt'))
  if(!$child.WaitForExit(10000)){$child.Kill();throw 'Owned restore fixture timeout'}
  $child.WaitForExit();$child.Refresh()
  $calls=@(Get-Content -LiteralPath $env:NEEXITLAG_HOT_RESTORE_LOG)
  Check ($calls.Count -eq 2 -and $calls[0] -eq 'False' -and $calls[1] -eq ([string]($initial -eq '1'))) 'Original Optimize state not restored after acceptance failure'
  $failures=@(Get-ChildItem -LiteralPath $reports -Filter 'FAIL.json' -Recurse)
  Check ($failures.Count -eq 1) 'Expected failure diagnostics missing'
 }
 Write-Host 'PASS real helper restores original ON/OFF after an owned failure following OFF'
}finally{
 $env:NEEXITLAG_HOT_RESTORE_LOG=$oldLog;$env:NEEXITLAG_HOT_RESTORE_INITIAL=$oldInitial
 if(Test-Path $fixture){Remove-Item -LiteralPath $fixture -Recurse -Force}
}
