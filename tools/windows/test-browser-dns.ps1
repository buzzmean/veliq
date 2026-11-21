<#
.SYNOPSIS
Readonly bounded observation of new/updated native browser flows. No browser restart,
policy change, web request or installation. Actual page/playback is checked by owner.
.EXAMPLE
& .\tools\windows\test-browser-dns.ps1 -DurationSeconds 90
#>
[CmdletBinding()]
param([ValidateRange(10,120)][int]$DurationSeconds=90,[switch]$RequireGoogleDirect)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if($RequireGoogleDirect -and $DurationSeconds -lt 120){throw 'YOUTUBE_ACCEPTANCE_DURATION_REQUIRED: -DurationSeconds 120 -RequireGoogleDirect'}
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'browser-dns-evidence.ps1')
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$baseline=Join-Path $repo 'bin\diagnostics\browser-before-veliq.json'
if(!(Test-Path -LiteralPath $baseline)){throw 'BROWSER_DNS_BASELINE_MISSING: сначала & .\tools\windows\test-browser-startup.ps1 -Phase baseline при уже открытых Chrome/Edge; не закрывайте браузеры.'}
$before=Get-Content -Raw -LiteralPath $baseline|ConvertFrom-Json
function Assert-DNSBrowserIdentity {
 foreach($browser in @($before.browsers)){
  $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$browser.pid) -ErrorAction SilentlyContinue
  if(!$p -or !$p.CreationDate -or $p.CreationDate.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture) -ne $browser.birth -or [string]$p.ExecutablePath -ine [string]$browser.path){throw 'BROWSER_PID_OR_BIRTH_CHANGED; результат без перезапуска не подтверждён'}
 }
}
Assert-DNSBrowserIdentity
$serviceBefore=Get-CimInstance Win32_Service -Filter "Name='VELIQ'"
$serviceProcessBefore=Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$serviceBefore.ProcessId)
if(!$serviceProcessBefore -or !$serviceProcessBefore.CreationDate){throw 'SERVICE_BASELINE_UNAVAILABLE'}
$initial=Invoke-ServiceIPC 'browser.native.status'
$initialBytes=@{}
$initialUsage=Get-BrowserDNSField $initial 'relay_usage'
$initialFailures=Get-BrowserDNSField $initialUsage 'googlevideo_admission_failures'
$after=0L
foreach($r in @(Get-BrowserDNSField $initial 'records' @())){$id=[long](Get-BrowserDNSField $r 'id' 0);if($id -gt $after){$after=$id};$initialBytes[$id]=@([long](Get-BrowserDNSField $r 'sent_bytes' 0),[long](Get-BrowserDNSField $r 'received_bytes' 0))}
$lost=[long](Get-BrowserDNSField $initial 'lost' 0);$maxLost=$lost
$seen=@{};$until=[DateTime]::UtcNow.AddSeconds($DurationSeconds)
Write-Output ('READ_ONLY_OBSERVATION '+$DurationSeconds+'s: откройте YouTube в НОВОЙ вкладке уже открытого Chrome/Edge, проиграйте и перемотайте видео; откройте vk.ru. Браузеры не закрывать. Откройте также google.com и Chrome Web Store. Старые HTTP/2 соединения могут остаться прежними.')
do {
 Assert-DNSBrowserIdentity
 $status=Invoke-ServiceIPC 'status'
 if((Get-BrowserDNSField $status 'connected' $false) -ne $true -or (Get-BrowserDNSField $status 'optimizing' $false) -ne $true){throw 'BROWSER_DNS_SERVICE_NOT_READY: connected/optimizing должны быть True; настройки скрипт не меняет'}
 $snapshot=Invoke-ServiceIPC 'browser.native.status'
 $maxLost=[Math]::Max($maxLost,[long](Get-BrowserDNSField $snapshot 'lost' 0))
 foreach($r in @(Get-BrowserDNSField $snapshot 'records' @())){
  $id=[long](Get-BrowserDNSField $r 'id' 0)
  if($id -le $after -and !$initialBytes.ContainsKey($id)){continue}
  if(!$seen.ContainsKey($id) -and $seen.Count -ge 512){throw 'BROWSER_DNS_OBSERVATION_CAPACITY; ограничение512, сократите нагрузку'}
  $old=$null;if($initialBytes.ContainsKey($id)){$old=$initialBytes[$id]}
  $observation=Get-BrowserDNSDeltaObservation $r -InitialBytes $old
  $seen[$id]=$observation
 }
 Start-Sleep -Milliseconds 500
}while([DateTime]::UtcNow -lt $until)
Assert-DNSBrowserIdentity
$serviceAfter=Get-CimInstance Win32_Service -Filter "Name='VELIQ'"
$serviceProcessAfter=Get-CimInstance Win32_Process -Filter ('ProcessId='+[uint32]$serviceAfter.ProcessId)
if($serviceAfter.ProcessId -ne $serviceBefore.ProcessId -or !$serviceProcessAfter -or !$serviceProcessAfter.CreationDate -or $serviceProcessAfter.CreationDate -ne $serviceProcessBefore.CreationDate){throw 'SERVICE_RESTARTED_DURING_OBSERVATION'}
$rows=@($seen.Values)
$rows|Where-Object {$_.group -ne 'OTHER'}|Sort-Object id|Select-Object -Last 48|Format-Table id,profile_id,domain,action,source,destination,tx,rx,server_hello_complete,failure -AutoSize
$proofRows=$rows
if($RequireGoogleDirect){
 $chromeProfiles=@(Invoke-ServiceIPC 'profiles'|Where-Object {@(Get-BrowserDNSField $_ 'executables' @()|Where-Object {($_ -replace '\\','/').Split('/')[-1] -ieq 'chrome.exe'}).Count -gt 0}|ForEach-Object {Get-BrowserDNSField $_ 'id' ''})
 $proofRows=@($rows|Where-Object {$chromeProfiles -contains $_.profile_id})
}
$verdict=Get-BrowserDNSTransportVerdict $proofRows -RequireGoogleDirect:$RequireGoogleDirect
$usage=Get-BrowserDNSField $snapshot 'relay_usage'
$finalFailures=Get-BrowserDNSField $usage 'googlevideo_admission_failures'
$admissionVerdict=Get-BrowserDNSVideoAdmissionVerdict $initialUsage $usage -RequireDedicated:$RequireGoogleDirect
if($admissionVerdict -eq 'VIDEO_ADMISSION_COUNTERS_UNINSTRUMENTED'){throw $admissionVerdict}
$failureDelta=[long]$finalFailures-[long]$initialFailures
Write-Output ('VIDEO_ADMISSION failures_delta='+$failureDelta+' dedicated_limit='+(Get-BrowserDNSField $usage 'googlevideo_tunnel_limit' 'UNKNOWN')+' other_google_limit='+(Get-BrowserDNSField $usage 'opaque_google_tunnel_limit' 'UNKNOWN')+' scope='+(Get-BrowserDNSField $usage 'admission_scope' 'LEGACY_SHARED')+' duration_seconds='+$DurationSeconds)
if($admissionVerdict -ne 'VIDEO_ADMISSION_STABLE'){throw $admissionVerdict}
Write-Output ('BROWSER_DNS_TRANSPORT verdict='+$verdict+' observed_new_or_updated_flows='+$rows.Count+' retained_records_lost_delta='+($maxLost-$lost)+' browser_pid_birth=UNCHANGED')
Write-Output 'Bounded sampled transport evidence only; no claim of complete no-leak proof or page/video PASS. Opaque Google cannot prove googlevideo. Existing HTTP/2 may be reused; lack of a new hostname flow is NOT a failed page test.'
if($verdict -ne 'TRANSPORT_ROUTES_OBSERVED_PAGE_NOT_VERIFIED'){throw ('BROWSER_DNS_TRANSPORT_NOT_CONFIRMED: '+$verdict+'; сохраните diag-no-vpn.ps1 -Only browser,youtube; значения секретов не присылайте')}
