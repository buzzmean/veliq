[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('baseline','disabled','exit','stopped')][string]$Stage)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$proof=Join-Path $repo 'bin\diagnostics\browser-disable-baseline.json'
$ownerSession=(Get-Process -Id $PID).SessionId
function Field($o,[string]$name){if($null -ne $o){$p=$o.PSObject.Properties[$name];if($p){return $p.Value}};return $null}
function ProcessBirth($p){if($p -and $p.CreationDate){return $p.CreationDate.ToUniversalTime().Ticks.ToString([System.Globalization.CultureInfo]::InvariantCulture)};return ''}
function ServiceView {Get-CimInstance Win32_Service -Filter "Name='VELIQ'" -ErrorAction Stop}
function BrowserView {@(Get-CimInstance Win32_Process -Filter ("(Name='chrome.exe' OR Name='msedge.exe') AND SessionId="+$ownerSession) -ErrorAction Stop|Where-Object {$_.CommandLine -and $_.CommandLine -notmatch '--type='}|Select-Object -First 16|ForEach-Object {[pscustomobject]@{pid=[uint32]$_.ProcessId;birth=(ProcessBirth $_);path=[string]$_.ExecutablePath}})}
function PolicyView {
 foreach($lane in @(@('Chrome','Google\Chrome'),@('Edge','Microsoft\Edge'))){
  $path='HKCU:\Software\Policies\'+$lane[1];$key=Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
  [pscustomobject]@{browser=$lane[0];proxy_settings_present=($null -ne (Field $key 'ProxySettings'))}
 }
}
$svc=ServiceView
if($Stage -eq 'baseline'){
 if($svc.State -ne 'Running' -or $svc.ProcessId -eq 0){throw 'SERVICE_NOT_RUNNING_FOR_BASELINE'}
 . (Join-Path $PSScriptRoot 'common.ps1')
 $status=Invoke-ServiceIPC 'status'
 if((Field $status 'optimizing') -ne $true){throw 'OPTIMIZATION_NOT_ACTIVE_FOR_BASELINE'}
 $browsers=@(BrowserView);if($browsers.Count -eq 0){throw 'ALREADY_RUNNING_BROWSER_REQUIRED'}
 if(@($browsers|Where-Object {!$_.birth -or !$_.path}).Count){throw 'BROWSER_IDENTITY_UNAVAILABLE'}
 $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$svc.ProcessId) -ErrorAction Stop
 if(!(ProcessBirth $process)){throw 'SERVICE_PROCESS_BIRTH_UNAVAILABLE'}
 New-Item -ItemType Directory -Force (Split-Path $proof)|Out-Null
 @{service_pid=[uint32]$svc.ProcessId;service_birth=(ProcessBirth $process);browsers=$browsers}|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $proof -Encoding UTF8
 Write-Output 'BASELINE_SAVED; no browser was closed or restarted'
}else{
 if(!(Test-Path -LiteralPath $proof)){throw 'BASELINE_REQUIRED'}
 $before=Get-Content -Raw -LiteralPath $proof|ConvertFrom-Json
 foreach($browser in @($before.browsers)){
  $current=Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$browser.pid) -ErrorAction SilentlyContinue
  if(!$current -or (ProcessBirth $current) -ne $browser.birth -or [string]$current.ExecutablePath -ine [string]$browser.path){throw 'BROWSER_PID_OR_CREATION_CHANGED'}
 }
 if($Stage -eq 'stopped'){
  $until=(Get-Date).AddSeconds(10);$quietSince=$null
  do{
   $svc=ServiceView
   $old=Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$before.service_pid) -ErrorAction SilentlyContinue
   $oldAlive=$old -and (ProcessBirth $old) -eq $before.service_birth
   $ports=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|Where-Object {$_.LocalPort -in @(50165,50166) -and $_.LocalAddress -in @('127.0.0.1','::1')})
   if($svc.State -eq 'Stopped' -and !$oldAlive -and $ports.Count -eq 0){if($null -eq $quietSince){$quietSince=Get-Date};if(((Get-Date)-$quietSince).TotalSeconds -ge 5){break}}else{$quietSince=$null}
   Start-Sleep -Milliseconds 100
  }while((Get-Date) -lt $until)
  if($null -eq $quietSince -or ((Get-Date)-$quietSince).TotalSeconds -lt 5 -or $svc.State -ne 'Stopped' -or $oldAlive -or $ports.Count -ne 0){throw 'SCM_OR_BROWSER_LISTENER_RETAINED; run diagnose-browser-processes.ps1'}
 }else{
  if($Stage -eq 'exit' -and @(Get-CimInstance Win32_Process -Filter ("(Name='VELIQ.exe' OR Name='NeExitLag.exe') AND SessionId="+$ownerSession) -ErrorAction SilentlyContinue).Count -ne 0){throw 'GUI_STILL_RUNNING'}
  if($svc.State -ne 'Running'){throw 'SERVICE_NOT_RUNNING'}
  . (Join-Path $PSScriptRoot 'common.ps1')
  $status=Invoke-ServiceIPC 'status'
  if($null -eq (Field $status 'optimizing') -or $null -eq (Field $status 'capture_active')){throw 'STATUS_INCOMPATIBLE'}
  if((Field $status 'optimizing') -ne $false -or (Field $status 'capture_active') -ne $false){throw 'ROUTING_NOT_DISABLED'}
 }
 $policies=@(PolicyView)
 $policies|Format-Table -AutoSize
 if(@($policies|Where-Object {$_.proxy_settings_present}).Count){throw 'POLICY_STILL_PRESENT_OR_FOREIGN; do not delete it manually'}
 Write-Output ('STRUCTURE_PASS stage='+$Stage+'; browser PID/creation unchanged; NETWORK_NOT_AUTOMATICALLY_VERIFIED')
 Write-Output 'Open a NEW vk.ru tab in the existing browser, without Reload policies; page success is the separate real ISP proof.'
}
