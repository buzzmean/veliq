$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$path=Join-Path $PSScriptRoot '..\..\tools\windows\diag-no-vpn.ps1'
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($name in @('Prop','Write-YouTubeLocalEvidence','Write-BrowserDNSEvidence','Write-RelayOpenPerformance','Write-TlsWireEvidence','Write-BrowserPathEvidence','Write-NativeIngressEvidence','Write-NativeFirewallEvidence','Write-BrowserFirstByteEvidence')){
 $fn=$ast.Find({param($a)$a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $name},$true)
 if(!$fn){throw "Missing function $name"};Invoke-Expression $fn.Extent.Text
}
function Check($Condition,[string]$Message){if(!$Condition){throw $Message}}
$script:lines=@()
function Say([string]$Line){$script:lines+=@($Line)}
Write-BrowserPathEvidence ([pscustomobject]@{listening=$true}) 'edge'
Check (($script:lines -join "`n") -match 'PAC_LEGACY_UNINSTRUMENTED') 'Old service claimed measured PAC'
$script:lines=@()
Write-BrowserPathEvidence ([pscustomobject]@{
 path='PAC_CONNECT';metrics_lost=2;failure_details_lost=3
 path_metrics=@([pscustomobject]@{profile_id='edge';accepted=10;opened=0;failed=10})
 failure_details=@([pscustomobject]@{profile_id='edge';domain='mtalk.google.com';phase='OPEN';reason='UPSTREAM_OPEN_TIMEOUT';count=10})
 secret='NEVER_LOG'
}) 'edge'
$text=$script:lines -join "`n"
Check ($text -match 'NO_NEW_PAC_TUNNEL_OBSERVED' -and $text -match 'first_open=NOT_OBSERVED') 'Failed OPEN fabricated first tunnel'
Check ($text -match 'domain=mtalk.google.com stage=OPEN reason=UPSTREAM_OPEN_TIMEOUT.*count=10') 'Domain/phase/reason missing'
Check ($text -match 'failure_details_lost=3' -and $text -notmatch 'NEVER_LOG') 'Truncation or safe fields broken'
$script:lines=@()
Write-BrowserPathEvidence ([pscustomobject]@{path='PAC_CONNECT';path_metrics=@([pscustomobject]@{profile_id='chrome';opened=3;first_tunnel_opened_at='2026-10-19T14:00:00Z';listen_to_first_open_ms=10})}) 'browser'
Check (($script:lines -join "`n") -match 'state=PAC_TUNNEL_OBSERVED') 'Actual PAC OPEN missing'
Write-Host 'PASS: separate PAC/native scope, no fabricated first OPEN, scoped failures, old service, safe fields, bounded evidence'

$script:lines=@()
Write-NativeIngressEvidence ([pscustomobject]@{records=@([pscustomobject]@{ingress='PAC_NATIVE_UPSTREAM';sent_bytes=100;received_bytes=100})})
Check (($script:lines -join "`n") -match 'NATIVE_ONLY_UNINSTRUMENTED') 'Legacy PAC/native inferred as native-only'
$script:lines=@()
Write-NativeIngressEvidence ([pscustomobject]@{native_only_state='NATIVE_ONLY_NOT_OBSERVED';native_only_totals=[pscustomobject]@{bidirectional_exchanges=0};pac_native_upstream_totals=[pscustomobject]@{bidirectional_exchanges=100}})
Check (($script:lines -join "`n") -match 'state=NATIVE_ONLY_NOT_OBSERVED') 'Hybrid forged native-only'
$script:lines=@()
Write-NativeIngressEvidence ([pscustomobject]@{native_only_state='NATIVE_ONLY_OBSERVED';native_only_totals=[pscustomobject]@{bidirectional_exchanges=1;sent_bytes=10;received_bytes=20}})
Check (($script:lines -join "`n") -match 'state=NATIVE_ONLY_OBSERVED') 'True native ingress hidden'
$script:lines=@()
Write-NativeIngressEvidence ([pscustomobject]@{native_only_state='NATIVE_ONLY_OBSERVED';native_only_totals=[pscustomobject]@{bidirectional_exchanges=0}})
Check (($script:lines -join "`n") -match 'state=NATIVE_ONLY_INVALID_EVIDENCE') 'Impossible evidence accepted'
$script:lines=@()
Write-NativeFirewallEvidence ([pscustomobject]@{state='APPLIED';known=$true;rule_present=$true;program_matches=$true;effective=$true;secret='NEVER_LOG'})
Check (($script:lines -join "`n") -match 'state=APPLIED.*effective=True' -and ($script:lines -join "`n") -notmatch 'NEVER_LOG') 'Firewall proof/safe output failed'
$script:lines=@()
Write-NativeFirewallEvidence ([pscustomobject]@{state='UNKNOWN_QUERY_TIMEOUT';known=$false})
Check (($script:lines -join "`n") -match 'UNKNOWN: UNKNOWN_QUERY_TIMEOUT') 'Unknown was reported as missing/applied'
Write-Host 'PASS native-only vs PAC upstream and actual firewall evidence under StrictMode'

$script:lines=@()
Write-BrowserFirstByteEvidence ([pscustomobject]@{first_byte_metrics=@(
 [pscustomobject]@{network='net';profile_id='chrome';group='youtube-media';path='PAC_CONNECT';mode='DIRECT_FIRST';replies=1;total_ms=2100;closed_without_reply=0},
 [pscustomobject]@{network='net';profile_id='chrome';group='youtube-media';path='PAC_CONNECT';mode='RELAY_FIRST';replies=2;total_ms=120;closed_without_reply=1}
);secret='NEVER_LOG'}) 'browser'
$text=$script:lines -join "`n"
Check ($text -match 'before_direct_first_avg_ms=2100 after_relay_first_avg_ms=60') 'Observed group comparison lost'
Check ($text -match 'n=2 no_reply=1 avg_ms=60' -and $text -notmatch 'NEVER_LOG') 'First-byte failures/safe fields lost'
$script:lines=@()
Write-BrowserFirstByteEvidence ([pscustomobject]@{first_byte_metrics=@([pscustomobject]@{mode='RELAY_FIRST';replies=0;total_ms=0;closed_without_reply=3})}) 'edge'
Check (($script:lines -join "`n") -match 'before_direct_first_avg_ms=NOT_OBSERVED after_relay_first_avg_ms=NOT_OBSERVED') 'Failures forged zero-ms improvement'
Write-Host 'PASS scoped first-byte comparison and missing samples under StrictMode'

$script:lines=@()
Write-BrowserFirstByteEvidence ([pscustomobject]@{first_byte_metrics=@()}) 'browser'
Check (($script:lines -join "`n") -match 'NO_SAMPLES' -and ($script:lines -join "`n") -notmatch 'UNINSTRUMENTED') 'Empty measured ledger misreported as old service'

$script:lines=@()
Write-BrowserFirstByteEvidence ([pscustomobject]@{first_byte_metrics=@(
 [pscustomobject]@{group='telegram';mode='RELAY_FIRST';replies=1;total_ms=270;closed_without_reply=1;no_reply_reasons=[pscustomobject]@{ORIGIN_DNS_FAILED=1;secret='NEVER_LOG'};no_reply_without_request_payload=1;no_reply_with_request_payload=0},
 [pscustomobject]@{group='anthropic';mode='RELAY_FIRST';replies=1;total_ms=430;closed_without_reply=3;no_reply_reasons=[pscustomobject]@{CLIENT_CLOSED_BEFORE_REQUEST=1;CLIENT_CLOSED_BEFORE_REPLY=1;TIMEOUT=1};no_reply_without_request_payload=1;no_reply_with_request_payload=2},
 [pscustomobject]@{group='youtube-media';mode='RELAY_FIRST';closed_without_reply=34;no_reply_reasons=[pscustomobject]@{}}
)}) 'browser'
$text=$script:lines -join "`n"
Check ($text -match 'group=telegram.*ORIGIN_DNS_FAILED=1' -and $text -match 'group=anthropic.*CLIENT_CLOSED_BEFORE_REQUEST=1.*CLIENT_CLOSED_BEFORE_REPLY=1.*TIMEOUT=1') 'Observed no-reply reasons missing'
Check ($text -match 'without_request_payload=1 with_request_payload=2' -and $text -match 'UNCLASSIFIED_LEGACY=34') 'Legacy total guessed or payload scope lost'
Check ($text -match 'only a preconnect candidate' -and $text -notmatch 'NEVER_LOG') 'Preconnect falsely claimed or unbounded properties logged'
Check ($text -match 'comparison.*telegram.*after_relay_first_avg_ms=270' -and $text -match 'comparison.*anthropic.*after_relay_first_avg_ms=430') 'Known groups not compared'
Write-Host 'PASS exact known groups, factual no-reply reasons, legacy unknowns and safe fixed fields under StrictMode'

$script:lines=@()
Write-TlsWireEvidence ([pscustomobject]@{records=@([pscustomobject]@{id=1;domain='web.telegram.org';tls_wire=[pscustomobject]@{origin_read=[pscustomobject]@{bytes=5;state='TLS_HEADER_ONLY';first_16_hex_masked='1503030002';records=@([pscustomobject]@{type=21;payload_length=2;complete=$false});secret='NEVER_LOG'}}})}) 'browser'
$text=$script:lines -join "`n"
Check ($text -match 'TLS_HEADER_ONLY' -and $text -match 'NOT a complete TLS alert' -and $text -notmatch 'NEVER_LOG') 'TLS header confused with complete alert or arbitrary field leaked'
Write-Host 'PASS safe bounded TLS framing and incomplete alert evidence'

$script:lines=@()
Write-TlsWireEvidence ([pscustomobject]@{records=@([pscustomobject]@{domain='web.telegram.org';origin_attempts=[pscustomobject]@{addresses_tried=2;selected='149.154.167.99:443';negative_cache_skips=1;dns='RELAY_DOH';client_hello_replayed_bytes=1900;state='ORIGIN_BYTES_NO_REPLAY';attempts=@([pscustomobject]@{destination='149.154.167.40:443';reason='ORIGIN_EOF_NO_BYTES'},[pscustomobject]@{destination='149.154.167.99:443';reason='CLIENT_HELLO_RETRY'});secret='NEVER_LOG'}})}) 'browser'
$text=$script:lines -join "`n"
Check ($text -match 'addresses_tried=2 selected=149.154.167.99:443 negative_skips=1 dns=RELAY_DOH' -and $text -match 'ORIGIN_EOF_NO_BYTES' -and $text -notmatch 'NEVER_LOG') 'Scoped per-IP attempt evidence or redaction missing'
Write-Host 'PASS per-IP attempts/selected address without arbitrary properties'

$script:lines=@()
Write-BrowserDNSEvidence ([pscustomobject]@{
 browser_dns=[pscustomobject]@{scope='ATTRIBUTED_NATIVE_BROWSER';queries=3;relay_doh=2;system_dns=1;secure_dns_policy='KNOWN_DOH_AUTHENTICATED_RELAY';encrypted_answers='NOT_OBSERVED';records=@([pscustomobject]@{profile_id='chrome';domain='youtube.com';query_type=1;path='AUTHENTICATED_RELAY_DOH';result='DNS_RESPONSE';addresses=2;secret='NEVER_LOG'})}
 domain_cache=[pscustomobject]@{browser_scoped_addresses=2;browser_scoped_hints_omitted=9;native_first_tls_reply_budget_ms=1200;browser_scoped_hints=@([pscustomobject]@{network='n';profile_id='chrome';address='87.240.137.208';domain='vk.ru';expires='2026-10-23T00:01:00Z';secret='NEVER_LOG'});google_failure_groups=@([pscustomobject]@{network='n';profile_id='chrome';state='RELAY_FIRST';distinct_failed_addresses=2;last_failure='DIRECT_TLS_EARLY_EOF_OR_RESET';secret='NEVER_LOG'})}
 relay_usage=[pscustomobject]@{admission_scope='DEDICATED_GOOGLEVIDEO_12_PLUS_OTHER_GOOGLE_4';googlevideo_active_tunnels=6;opaque_google_active_tunnels=2;googlevideo_shared_limit_active=6;googlevideo_tunnel_limit=12;opaque_google_tunnel_limit=4;google_admission_total_active=8;googlevideo_admission_canceled=3;ordinary_capacity_direct_fallbacks=2}
 secret='NEVER_LOG'
})
$text=$script:lines -join "`n"
Check ($text -match 'relay_https_doh=2 original_resolver=1' -and $text -match 'domain=youtube.com.*AUTHENTICATED_RELAY_DOH') 'DNS path/counters missing'
Check ($text -match 'address=87.240.137.208 domain=vk.ru expires=' -and $text -match 'omitted=9') 'TTL hints/bounded omission missing'
Check ($text -match 'distinct_failures=2.*DIRECT_TLS_EARLY_EOF_OR_RESET' -and $text -match 'known_googlevideo=6/12 opaque_google=2/4 total=8') 'Real failure family/dedicated admission missing'
Check ($text -notmatch 'NEVER_LOG' -and $text -match 'no page/video PASS inferred') 'Secret or fabricated DNS/page proof'
$script:lines=@();Write-BrowserDNSEvidence ([pscustomobject]@{})
Check (($script:lines -join "`n") -match 'browser DNS broker: UNINSTRUMENTED') 'Legacy DNS snapshot not handled safely'
Write-Host 'PASS DNS broker/scoped TTLs/real TLS failure groups/dedicated twelve/four admissions, legacy snapshots and safe fixed fields under StrictMode'

. (Join-Path $PSScriptRoot '..\..\tools\windows\browser-dns-evidence.ps1')
$video=[pscustomobject]@{id=1;owner=[pscustomobject]@{profile_id='chrome'};domain='r1.googlevideo.com';destination='173.194.180.1:443';ingress='NATIVE_TCP';sent_bytes=2000;received_bytes=10000;tls_wire=[pscustomobject]@{origin=[pscustomobject]@{server_hello_complete=$true}};policy=[pscustomobject]@{action='RELAY_REQUIRED';relay_id='VPS-01'};secret='NEVER_LOG'}
$vk=[pscustomobject]@{id=2;owner=[pscustomobject]@{profile_id='chrome'};domain='vk.ru';ingress='NATIVE_TCP';sent_bytes=2000;received_bytes=5000;tls_wire=[pscustomobject]@{origin=[pscustomobject]@{server_hello_complete=$true}};policy=[pscustomobject]@{action='DIRECT'}}
$rows=@((Get-BrowserDNSTransportObservation $video),(Get-BrowserDNSTransportObservation $vk))
Check ((Get-BrowserDNSTransportVerdict $rows) -eq 'TRANSPORT_ROUTES_OBSERVED_PAGE_NOT_VERIFIED') 'Actual named relay/direct transport was hidden'
Check (($rows|ConvertTo-Json -Depth 6) -notmatch 'NEVER_LOG') 'Observation leaked arbitrary fields'
$video.domain='<opaque>'
Check ((Get-BrowserDNSTransportVerdict @((Get-BrowserDNSTransportObservation $video),$rows[1])) -eq 'GOOGLEVIDEO_HOSTNAME_EXCHANGE_NOT_OBSERVED') 'Opaque bytes forged video hostname'
$video.domain='r1.googlevideo.com';$video.received_bytes=5
Check (!(Get-BrowserDNSTransportObservation $video).exchange) 'Five-byte alert forged successful exchange'
$video.received_bytes=10000;$video.ingress='PAC_NATIVE_UPSTREAM'
Check (!(Get-BrowserDNSTransportObservation $video).exchange) 'PAC upstream forged native-only ingress'
$video.ingress='NATIVE_TCP';$video.policy.action='DIRECT'
Check ((Get-BrowserDNSTransportVerdict @((Get-BrowserDNSTransportObservation $video))) -eq 'PROTECTED_DIRECT_OBSERVED') 'Known protected DIRECT missed'
foreach($file in @('test-browser-dns.ps1','browser-dns-evidence.ps1')){
 $t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot ('..\..\tools\windows\'+$file)),[ref]$t,[ref]$e)
 Check ($e.Count -eq 0) ('DNS acceptance parser failed '+$file)
}
Check ((Get-BrowserDNSTransportVerdict @()) -ne 'TRANSPORT_ROUTES_OBSERVED_PAGE_NOT_VERIFIED') 'Empty evidence forged proof'
Write-Host 'PASS named native transport observation, no opaque/PAC/alert/page inference, protected DIRECT detection and acceptance parser; no browser/VPS operations'

$video.policy.action='RELAY_REQUIRED';$video.ingress='NATIVE_TCP';$video.domain='r1.googlevideo.com'
$google=[pscustomobject]@{id=3;owner=[pscustomobject]@{profile_id='chrome'};domain='chromewebstore.google.com';ingress='NATIVE_TCP';sent_bytes=2000;received_bytes=5000;tls_wire=[pscustomobject]@{origin=[pscustomobject]@{server_hello_complete=$true}};policy=[pscustomobject]@{action='DIRECT'}}
$rows=@((Get-BrowserDNSTransportObservation $video),(Get-BrowserDNSTransportObservation $vk))
Check ((Get-BrowserDNSTransportVerdict $rows -RequireGoogleDirect) -eq 'GOOGLE_DIRECT_EXCHANGE_NOT_OBSERVED') 'Google DIRECT proof was not required'
$rows+=@(Get-BrowserDNSTransportObservation $google)
Check ((Get-BrowserDNSTransportVerdict $rows -RequireGoogleDirect) -eq 'TRANSPORT_ROUTES_OBSERVED_PAGE_NOT_VERIFIED') 'Named video relay + VK/Google DIRECT proof missing'
foreach($alias in @('youtubei.googleapis.com','yt3.googleusercontent.com','wide-youtube.l.google.com')){
 $google.domain=$alias
 Check (Get-BrowserDNSTransportObservation $google).protected_direct ('YouTube alias incorrectly accepted as ordinary Google DIRECT '+$alias)
}
Write-Host 'PASS separate Google/WebStore DIRECT requirement and protected YouTube aliases; no page/playback inference'

$google.domain='www.google.com'
$o=Get-BrowserDNSDeltaObservation $google -InitialBytes @(2000,5000)
Check (!$o.exchange -and $o.tx -eq 0 -and $o.rx -eq 0) 'Old cumulative bytes fabricated this-window evidence'
$o=Get-BrowserDNSDeltaObservation $google -InitialBytes @(1000,4000)
Check ($o.exchange -and $o.tx -eq 1000 -and $o.rx -eq 1000) 'Existing HTTP2 fresh exchange delta discarded'
$reset=$false;try{Get-BrowserDNSDeltaObservation $google -InitialBytes @(3000,5000)|Out-Null}catch{$reset=$_.Exception.Message -eq 'NATIVE_FLOW_COUNTERS_RESET'}
Check $reset 'Reset counters fabricated traffic'
$google.domain='www.youtube.com'
Check (!(Get-BrowserDNSDeltaObservation $google -InitialBytes @(2000,5000)).protected_direct) 'Pre-window DIRECT evidence falsely attributed to this test'
$beforeAdmission=[pscustomobject]@{googlevideo_admission_failures=2}
$afterAdmission=[pscustomobject]@{googlevideo_admission_failures=2;admission_scope='DEDICATED_VIDEO';googlevideo_admission_canceled=99}
Check ((Get-BrowserDNSVideoAdmissionVerdict $beforeAdmission $afterAdmission -RequireDedicated) -eq 'VIDEO_ADMISSION_STABLE') 'Cancellation forged capacity failure'
$afterAdmission.googlevideo_admission_failures=3
Check ((Get-BrowserDNSVideoAdmissionVerdict $beforeAdmission $afterAdmission -RequireDedicated) -eq 'VIDEO_ADMISSION_FAILURES_INCREASED') 'Admission failures ignored'
$afterAdmission.googlevideo_admission_failures=1
Check ((Get-BrowserDNSVideoAdmissionVerdict $beforeAdmission $afterAdmission -RequireDedicated) -eq 'VIDEO_ADMISSION_COUNTERS_RESET') 'Restart/reset counters accepted'
$afterAdmission.googlevideo_admission_failures=2;$afterAdmission.admission_scope='LEGACY_SHARED'
Check ((Get-BrowserDNSVideoAdmissionVerdict $beforeAdmission $afterAdmission -RequireDedicated) -eq 'VIDEO_ADMISSION_OLD_SHARED_POOL') 'Old shared pool accepted'
Check ((Get-BrowserDNSVideoAdmissionVerdict ([pscustomobject]@{}) $afterAdmission) -eq 'VIDEO_ADMISSION_COUNTERS_UNINSTRUMENTED') 'Missing metrics forged zero failures'
Write-Host 'PASS fresh delta on pinned HTTP2, no old bytes/reset inference; independent stable video admission and cancellation/legacy/incomplete rejection'

$video.domain='r1.googlevideo.com';$video.policy.action='RELAY_REQUIRED';$google.domain='www.google.com';$google.owner.profile_id='edge'
Check ((Get-BrowserDNSTransportVerdict @((Get-BrowserDNSTransportObservation $video),(Get-BrowserDNSTransportObservation $vk),(Get-BrowserDNSTransportObservation $google)) -RequireGoogleDirect) -eq 'SAME_BROWSER_PROFILE_ROUTES_NOT_OBSERVED') 'Cross-browser traffic fabricated one Chrome profile routes'
Write-Host 'PASS required routes must share one browser profile; cross-browser mixing is not proof'

$script:lines=@();Write-BrowserDNSEvidence ([pscustomobject]@{relay_usage=[pscustomobject]@{video_performance_scope='TLS_WIRE_NOT_FPS';video_connections_omitted=2;video_connections=@([pscustomobject]@{id=7;profile_id='chrome';domain='r.googlevideo.com';admission_ms=20;relay_open_ms=60;first_byte_ms=150;average_receive_mbps=12;receive_span_mbps=20;secret='NEVER_LOG'})}})
$text=$script:lines -join "`n"
Check ($text -match 'video connection: id=7.*admission_ms=20.*relay_open_ms=60.*first_byte_ms=150.*average_rx_mbps=12' -and $text -match 'omitted=2' -and $text -notmatch 'NEVER_LOG') 'Video latency/speed fixed projection unsafe or missing'
$script:lines=@();Write-BrowserDNSEvidence ([pscustomobject]@{})
Check (($script:lines -join "`n") -match 'video performance: UNINSTRUMENTED') 'Old service forged video performance'
Write-Host 'PASS video per-connection timing/rates fixed-field diagnostics and old-service UNINSTRUMENTED'

$script:lines=@();Write-RelayOpenPerformance ([pscustomobject]@{active_sessions=1;waiting_opens=0;recent_opens=@([pscustomobject]@{session_id=3;duration_ms=65;acquire_ms=2;stream_open_ms=63;session_age_ms=10000;detail='SECRET_NOT_PROJECTED'})})
$text=$script:lines -join "`n"
Check ($text -match 'total_ms=65 acquire_ms=2 stream_origin_open_ms=63 session_age_ms=10000' -and $text -notmatch 'SECRET_NOT_PROJECTED') 'Pool open timing projection missing/unsafe'
$script:lines=@();Write-RelayOpenPerformance ([pscustomobject]@{recent_opens=@([pscustomobject]@{duration_ms=1})})
Check (($script:lines -join "`n") -match 'acquire_ms=UNINSTRUMENTED') 'Legacy pool fabricated phase timing'
Write-Host 'PASS pool/session OPEN phase projection, old schema UNINSTRUMENTED, no raw errors'

$observer=Join-Path $PSScriptRoot '..\..\tools\windows\observe-video-relay.ps1'
$t=$null;$e=$null;$a=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $observer),[ref]$t,[ref]$e)
Check ($e.Count -eq 0) 'Video observer parser failed'
foreach($name in @('VideoField','VideoInterval')){$f=$a.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true);Invoke-Expression $f.Extent.Text}
$now=[datetime]::UtcNow;$sample=[pscustomobject]@{received_bytes=2000000;secret='NEVER_LOG'}
Check ((VideoInterval $null $sample $now).state -eq 'BASELINE') 'Old video bytes counted as a fresh rate'
$v=VideoInterval ([pscustomobject]@{at=$now.AddSeconds(-2);bytes=1000000}) $sample $now
Check ($v.state -eq 'MEASURED' -and $v.mbps -eq 4) 'Video interval rate wrong'
Check ((VideoInterval ([pscustomobject]@{at=$now.AddSeconds(-1);bytes=3000000}) $sample $now).state -eq 'COUNTER_RESET') 'Reset produced fake throughput'
$commands=@($a.FindAll({param($n)$n -is [Management.Automation.Language.CommandAst]},$true)|ForEach-Object{$_.GetCommandName()})
Check (!($commands|Where-Object{$_ -match '^(ssh|scp|Start-Process|Stop-Process|Restart-Service|Stop-Service|Start-Service|Set-ItemProperty)$'})) 'Observer mutates browser/service/VPS'
Check ((Get-Content -LiteralPath $observer -Raw) -notmatch "Invoke-ServiceIPC '(?!browser.native.status)") 'Observer calls a mutating IPC'
Write-Host 'PASS read-only 120s video observer, real interval deltas, baseline/reset rejection and bounded schema'

$script:lines=@();Write-BrowserDNSEvidence ([pscustomobject]@{relay_usage=[pscustomobject]@{video_connections=@();video_performance_scope='TLS_WIRE'}})
Check (($script:lines -join "`n") -match 'video performance scope=TLS_WIRE' -and ($script:lines -join "`n") -notmatch 'video performance: UNINSTRUMENTED' -and ($script:lines -join "`n") -notmatch 'video connection:') 'Empty new service ledger confused with missing instrumentation'
Write-Host 'PASS empty video ledger before opening a video is instrumented, not an old-service failure'

$script:lines=@()
Write-NativeIngressEvidence ([pscustomobject]@{youtube_local_ladder=[pscustomobject]@{records=@([pscustomobject]@{domain='rr6---sn-test.googlevideo.com';destination='188.43.67.12:443'},[pscustomobject]@{domain='vk.ru';destination='188.43.67.13:443'},[pscustomobject]@{domain='rr4---sn-other.googlevideo.com';destination='188.43.70.12:443'})}})
$text=$script:lines -join ' '
if($text -notmatch '188.43.67.12:443 label=COMMUNITY_GGC_RANGE_UNVERIFIED' -or $text -match 'GGC: host=vk.ru' -or $text -match '188.43.70.12:443 label='){throw 'GGC_LABEL_SCOPE_WRONG'}
Write-Host 'PASS community GGC prefix label scoped to known googlevideo; no routing verdict'
