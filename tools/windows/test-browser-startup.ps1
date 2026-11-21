#requires -Version 5.1
<#
.SYNOPSIS
Проверка native hot attach без закрытия Chrome/Edge.
.EXAMPLE
& .\tools\windows\test-browser-startup.ps1 -Phase baseline
.EXAMPLE
& .\tools\windows\test-browser-startup.ps1 -Phase ready
.NOTES
Из корня репозитория используйте полный относительный путь и &. PowerShell не
ищет ps1 в текущем каталоге/PATH автоматически; bare name не запускает скрипт.
#>
[CmdletBinding()]
param([ValidateSet('baseline','ready','disabled','exit','stopped')][string]$Phase,[ValidateRange(1,60)][int]$WaitSeconds=20)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if([string]::IsNullOrEmpty($Phase)){
 throw 'BROWSER_STARTUP_USAGE: из корня репозитория выполните & .\tools\windows\test-browser-startup.ps1 -Phase baseline, затем -Phase ready после открытия новых вкладок. Chrome и Edge не закрывать. Это диагностика, не установка.'
}
if([string]::IsNullOrEmpty($PSScriptRoot)){
 throw 'BROWSER_STARTUP_SCRIPT_PATH_REQUIRED: запустите файл из корня репозитория через & .\tools\windows\test-browser-startup.ps1 -Phase baseline; не вставляйте содержимое скрипта в консоль.'
}
. (Join-Path $PSScriptRoot 'browser-startup-evidence.ps1')
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$file=Join-Path $repo 'bin\diagnostics\browser-before-veliq.json'
$ownerSession=(Get-Process -Id $PID).SessionId
function Get-BrowserStartupProcesses {
 @(Get-CimInstance Win32_Process -Filter ("(Name='chrome.exe' OR Name='msedge.exe') AND SessionId="+$ownerSession)|Where-Object {$_.CommandLine -and $_.CommandLine -notmatch '--type='}|Select-Object -First 16|ForEach-Object {
  if(!$_.ExecutablePath -or !$_.CreationDate){throw 'BROWSER_IDENTITY_UNAVAILABLE'}
  [pscustomobject]@{pid=[uint32]$_.ProcessId;birth=$_.CreationDate.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture);path=[string]$_.ExecutablePath;name=[string]$_.Name}
 })
}
if($Phase -eq 'baseline'){
 $processes=@(Get-BrowserStartupProcesses)
 foreach($name in @('chrome.exe','msedge.exe')){if(!@($processes|Where-Object {$_.name -ieq $name}).Count){throw ('ALREADY_RUNNING_BROWSER_REQUIRED_'+$name)}}
 New-Item -ItemType Directory -Force (Split-Path $file)|Out-Null
 @{browsers=$processes}|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $file -Encoding UTF8
 Write-Output 'BASELINE_SAVED; Chrome/Edge stay open; launch VELIQ and open new tabs; no browser commands or policy reload.'
 return
}
if(!(Test-Path -LiteralPath $file)){throw 'BROWSER_BASELINE_MISSING: сначала выполните & .\tools\windows\test-browser-startup.ps1 -Phase baseline при открытых Chrome и Edge; браузеры не закрывать.'}
$before=Get-Content -Raw -LiteralPath $file|ConvertFrom-Json
function Assert-BrowserStartupIdentity {
 foreach($browser in @($before.browsers)){
  $now=Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$browser.pid) -ErrorAction SilentlyContinue
  if(!$now -or !$now.CreationDate -or $now.CreationDate.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture) -ne $browser.birth -or [string]$now.ExecutablePath -ine [string]$browser.path){throw 'BROWSER_PID_OR_BIRTH_CHANGED'}
 }
}
Assert-BrowserStartupIdentity
if($Phase -ne 'ready'){
 $disableBaseline=Join-Path $repo 'bin\diagnostics\browser-disable-baseline.json'
 $confirmed=Get-BrowserEvidenceField $before 'native_ready_confirmed' $false
 if(!$confirmed -or !(Test-Path -LiteralPath $disableBaseline)){throw 'BROWSER_READY_NOT_CONFIRMED: фаза ready ещё не прошла; это не новый отказ выключения. Сначала откройте новые вкладки в работающих браузерах и выполните & .\tools\windows\test-browser-startup.ps1 -Phase ready. См. browser.native.status и capture.diagnostics.'}
 & (Join-Path $PSScriptRoot 'check-browser-disable.ps1') -Stage $Phase
 return
}
. (Join-Path $PSScriptRoot 'common.ps1')
$deadline=[DateTime]::UtcNow.AddSeconds($WaitSeconds);$code='STATUS_UNAVAILABLE';$proof=$null
while([DateTime]::UtcNow -lt $deadline){
 try{
  $status=Invoke-ServiceIPC 'status';$native=Invoke-ServiceIPC 'browser.native.status';$profiles=Invoke-ServiceIPC 'profiles'
  $proof=Test-BrowserNativeStartupEvidence $profiles $native @($before.browsers|ForEach-Object {$_.path}|Select-Object -Unique)
  $code=$proof.code
  if((Get-BrowserEvidenceField $status 'optimizing' $false) -ne $true){$code='OPTIMIZATION_NOT_ACTIVE'}
  elseif((Get-BrowserEvidenceField $status 'connected' $false) -ne $true){$code='RELAY_NOT_CONNECTED'}
  elseif($proof.ready){break}
 }catch{$code='STATUS_UNAVAILABLE'}
 Start-Sleep -Milliseconds 500
}
Assert-BrowserStartupIdentity
if($null -eq $proof -or !$proof.ready -or $code -ne 'READY'){throw ('BROWSER_STARTUP_NOT_CONFIRMED code='+$code+'; inspect GUI diagnostics; no page PASS claimed')}
$proof.rows|Format-Table -AutoSize
& (Join-Path $PSScriptRoot 'check-browser-disable.ps1') -Stage baseline
$before|Add-Member -NotePropertyName native_ready_confirmed -NotePropertyValue $true -Force
$before|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $file -Encoding UTF8
Write-Output 'NATIVE_ONLY_OBSERVED for each existing browser; PID/birth unchanged; NATIVE_TRANSPORT_ONLY_NOT_PAGE_PASS.'
Write-Output 'Observe YouTube/Telegram Web/claude.ai in new tabs. HTTP/TLS/page success cannot be inferred from encrypted bytes. Do not reload policy or restart browsers.'
