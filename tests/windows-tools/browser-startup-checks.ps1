$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repo 'tools\windows\browser-startup-evidence.ps1')
function Assert($value,$why){if(!$value){throw $why}}
$profiles=@([pscustomobject]@{id='chrome';mode='AUTO';browser_transport='native';executables=@('C:\Apps\chrome.exe')},[pscustomobject]@{id='edge';mode='AUTO';browser_transport='native';executables=@('C:\Apps\msedge.exe')})
$good=[pscustomobject]@{accepted=1;opened=1;bidirectional_exchanges=1;sent_bytes=100;received_bytes=200;enable_to_first_exchange_ms=42}
$native=[pscustomobject]@{state='READY_NEW_CONNECTIONS';profiles=@([pscustomobject]@{profile_id='chrome';native_only=$good},[pscustomobject]@{profile_id='edge';native_only=$good})}
$exe=@('C:\Apps\chrome.exe','C:\Apps\msedge.exe')
$r=Test-BrowserNativeStartupEvidence $profiles $native $exe
Assert $r.ready 'valid both-browser native evidence rejected';Assert ($r.scope -eq 'NATIVE_TRANSPORT_ONLY_NOT_PAGE_PASS') 'bytes claimed page success'
$good.accepted=0
$r=Test-BrowserNativeStartupEvidence $profiles $native $exe;Assert (!$r.ready) 'exchange without native accepted manufactured proof'
$good.accepted=1
$native.profiles[1].native_only=[pscustomobject]@{bidirectional_exchanges=0;sent_bytes=100;received_bytes=0}
$r=Test-BrowserNativeStartupEvidence $profiles $native $exe;Assert (!$r.ready) 'one browser or one-way traffic manufactured native proof'
$native.profiles[1].native_only=$null
$r=Test-BrowserNativeStartupEvidence $profiles $native $exe;Assert (!$r.ready) 'missing optional metrics accepted under StrictMode'
$native.profiles[1].native_only=$good;$profiles[0].mode='DIRECT'
$r=Test-BrowserNativeStartupEvidence $profiles $native $exe;Assert (!$r.ready) 'DIRECT default manufactured AUTO'
$profiles[0].mode='AUTO';$native.state='PREPARING'
$r=Test-BrowserNativeStartupEvidence $profiles $native $exe;Assert (!$r.ready) 'not-ready native reported success'
$r=Test-BrowserNativeStartupEvidence @() $null @();Assert (!$r.ready) 'empty snapshot manufactured proof'
foreach($name in @('test-browser-startup.ps1','browser-startup-evidence.ps1','install.ps1','update-service.ps1')){
 $tokens=$null;$errors=$null;[void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repo ('tools\windows\'+$name)),[ref]$tokens,[ref]$errors)
 Assert ($errors.Count -eq 0) ('PS parser failure '+$name)
}
Write-Output 'PASS browser startup evidence, both lanes, no PAC inference, one-way/missing/DIRECT rejection and parser; no installation/VPS/browser access'

$script=Get-Content -Raw (Join-Path $repo 'tools\windows\test-browser-startup.ps1')
Assert ($script.Contains('BROWSER_READY_NOT_CONFIRMED:')) 'missing explanatory ready prerequisite'
Assert ($script.IndexOf('BROWSER_READY_NOT_CONFIRMED:') -lt $script.IndexOf("-Stage `$Phase")) 'ready prerequisite must precede disabled/exit delegation'

# Execute the failed-ready branch in an isolated repository, rather than merely
# matching an error string. It must not call the disabled/exit delegate.
$temp=Join-Path ([IO.Path]::GetTempPath()) ('veliq-startup-check-'+[guid]::NewGuid().ToString('N'))
try{
 $scripts=Join-Path $temp 'tools\windows';New-Item -ItemType Directory -Force $scripts|Out-Null
 foreach($n in @('test-browser-startup.ps1','browser-startup-evidence.ps1')){Copy-Item (Join-Path $repo ('tools\windows\'+$n)) (Join-Path $scripts $n)}
 $reason='';try{& (Join-Path $scripts 'test-browser-startup.ps1')}catch{$reason=$_.Exception.Message}
 Assert ($reason -like 'BROWSER_STARTUP_USAGE:*') ('missing phase must explain exact launch syntax: '+$reason)
 Assert ($reason.Contains('& .\tools\windows\test-browser-startup.ps1')) 'missing full relative path and invocation operator'
 Set-Content (Join-Path $scripts 'check-browser-disable.ps1') "throw 'SHOULD_NOT_DELEGATE'" -Encoding UTF8
 $bin=Join-Path $temp 'bin\diagnostics';New-Item -ItemType Directory -Force $bin|Out-Null
 $born=[datetime]::SpecifyKind([datetime]'2026-10-22 00:00:00',[DateTimeKind]::Utc)
 function Get-CimInstance {param($ClassName,$Filter,$ErrorAction) [pscustomobject]@{CreationDate=$born;ExecutablePath='C:\Apps\chrome.exe'}}
 $baseline=@{browsers=@(@{pid=777;birth=$born.Ticks.ToString([Globalization.CultureInfo]::InvariantCulture);path='C:\Apps\chrome.exe';name='chrome.exe'})}
 $baseline|ConvertTo-Json -Depth 5|Set-Content (Join-Path $bin 'browser-before-veliq.json') -Encoding UTF8
 foreach($phase in @('disabled','exit','stopped')){
  $reason='';try{& (Join-Path $scripts 'test-browser-startup.ps1') -Phase $phase}catch{$reason=$_.Exception.Message}
  Assert ($reason -like 'BROWSER_READY_NOT_CONFIRMED:*') ('failed ready not explained: '+$phase+' '+$reason)
 }
 Remove-Item (Join-Path $bin 'browser-before-veliq.json')
 $reason='';try{& (Join-Path $scripts 'test-browser-startup.ps1') -Phase ready}catch{$reason=$_.Exception.Message}
 Assert ($reason -like 'BROWSER_BASELINE_MISSING:*') ('missing baseline not explained: '+$reason)
}finally{if(Test-Path $temp){Remove-Item -Recurse -Force $temp}}
Write-Output 'PASS actual failed-ready prerequisites for disabled/exit/stopped in isolated fixture; no service/VPS/browser access'
