#requires -Version 5.1
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\..\tools\windows\diag-no-vpn.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($name in @('Prop','Write-CdnTrialEvidence','Write-OrdinaryAddressEvidence','Write-LocalProbeEvidence')){$f=$ast.Find({param($x)$x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $name},$true);Invoke-Expression $f.Extent.Text}
$script:lines=@();function Say([string]$s){$script:lines+=@($s)}
Write-LocalProbeEvidence ([pscustomobject]@{probes=@([pscustomobject]@{host='discord.com';strategy='catalog-fixture';service='discord';result='NO_TRANSFORM';committed=$false;sent_bytes=1500;received_bytes=0;inspection=[pscustomobject]@{syn_seen=$true;handshake_confirmed=$false;reason='HANDSHAKE_MISSING';sent_packets=@([pscustomobject]@{length=1250;ttl=5;protocol=6;sequence_offset=-10000;tcp_flags=24;fake=$true;timestamp_present=$true;timestamp_delta=-600000;ack_offset=0;md5_present=$false});private_payload='SECRET'}})})
Write-LocalProbeEvidence ([pscustomobject]@{tcp_closures=@([pscustomobject]@{Domain='rr.googlevideo.com';Strategy='candidate';Reason='EARLY_EOF_OR_IO_NO_REPLAY';IOFailure='REMOTE_RESET';Timing=[pscustomobject]@{hello_to_close_ms=1200;last_rx_to_close_ms=200;hello_to_server_hello_ms=150;rx_after_server_hello_observed=6000;ClientApplicationRecord=$true};Packets=[pscustomobject]@{first_close='REMOTE_PACKET';RemoteRST=1;SYNACKTTL=52;RemoteTerminalTTL=117};private_payload='SECRET'});probes=@()})
$s=$script:lines -join ' '
if($s -notmatch 'remote_rst=1' -or $s -notmatch 'remote_terminal_ttl=117' -or $s -notmatch 'ts_delta=-600000' -or $s -notmatch 'hello_to_server_hello_ms=150' -or $s -notmatch 'rx_after_hello_observed=6000'){throw 'Missing TCP/fooling diagnostics'}
if($s -notmatch 'discord.com' -or $s -notmatch 'seq_delta=-10000' -or $s -notmatch 'handshake=False' -or $s -notmatch 'fake=True' -or $s -match 'SECRET'){throw 'Missing or unsafe LOCAL probe table'}
Write-Host 'PASS LOCAL strategy/host headers, handshake and secret allowlist; PS5.1-compatible syntax (runtime separately required)'

$script:lines=@()
Write-LocalProbeEvidence ([pscustomobject]@{failures=@([pscustomobject]@{Domain='googlevideo:sn-test';Reason='MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED';SinceClientHelloMS=8000;SinceLastRXMS=6001;RX=20000;ReceivedAfterHello=19900;Promoted=$true;private_payload='SECRET'});tcp_closures=@([pscustomobject]@{Timing=[pscustomobject]@{ApplicationRecords=65;ApplicationBytes=1064960;ApplicationSpanMS=3400}})})
$s=$script:lines -join ' '
if($s -notmatch 'last_rx_to_failure_ms=6001' -or $s -notmatch 'rx_after_hello=19900' -or $s -notmatch 'promoted=True' -or $s -notmatch 'application_records=65 application_bytes=1064960 application_span_ms=3400' -or $s -match 'SECRET'){throw 'Missing/unsafe sustained or midstream failure evidence'}
Write-Host 'PASS running sustained proof counters and exact failure timing/volume allowlist'

$script:lines=@()
Write-CdnTrialEvidence ([pscustomobject]@{trials=@([pscustomobject]@{Host='rr5---sn-test.googlevideo.com';TX=5791;RX=7109;TrialResult='INCONCLUSIVE_SMALL_EOF';Packets=[pscustomobject]@{first_close='REMOTE_PACKET';RemoteFIN=1;ClientRetransmits=2};Timing=[pscustomobject]@{hello_to_close_ms=290};Sibling=[pscustomobject]@{AgeMS=15000;Reason='RECENT_SAME_SUBGROUP'};private_payload='SECRET'})})
$s=$script:lines -join ' '
if($s -notmatch 'host=rr5---sn-test.googlevideo.com' -or $s -notmatch 'trial_result=INCONCLUSIVE_SMALL_EOF' -or $s -notmatch 'tx=5791 rx=7109' -or $s -notmatch 'hello_to_close_ms=290' -or $s -notmatch 'sibling_age_at_admission_ms=15000' -or $s -match 'SECRET'){throw 'CDN trial evidence missing/unsafe'}
Write-Host 'PASS per-trial exact host/neutral result/close timing/recent sibling allowlist'

$script:lines=@();Write-CdnTrialEvidence ([pscustomobject]@{trials=$null});if(($script:lines -join ' ') -match 'CDN trial: host='){throw 'Null history fabricated a trial'}
Write-Host 'PASS empty history does not fabricate a trial'

$script:lines=@()
Write-CdnTrialEvidence ([pscustomobject]@{trials=@([pscustomobject]@{Host='rr4---sn-test.googlevideo.com';TrialResult='INCONCLUSIVE_SMALL_EOF';slot_active=$false;slot_released_at='2026-10-24T12:00:00Z';slot_release_reason='REMOTE_SMALL_EOF';neutral_short_attempt=2;cooldown_until='2026-10-24T12:00:00Z';secret='HIDDEN'})})
$s=$script:lines -join ' '
if($s -notmatch 'slot_active=False slot_released_at=2026-10-24T12:00:00Z slot_release_reason=REMOTE_SMALL_EOF neutral_short_attempt=2 cooldown_until=' -or $s -match 'HIDDEN'){throw 'Slot release/retry evidence missing or unsafe'}
Write-Host 'PASS per-trial slot release and bounded neutral attempt metadata'

$script:lines=@()
Write-OrdinaryAddressEvidence $null
Write-OrdinaryAddressEvidence ([pscustomobject]@{ordinary=@()})
Write-OrdinaryAddressEvidence ([pscustomobject]@{ordinary=@([pscustomobject]@{Host='akashi.vk-portal.net';Profile='chrome';Stage='DIRECT';Reason='DIRECT_DNS_PEER_SELECTED';DNS='PLANNER_DNS_CANDIDATES';Addresses=@([pscustomobject]@{Address='87.240.137.208:443';Stage='DIRECT';Result='TLS_SERVER_HELLO; NOT_HTTP_PROOF';TX=100;RX=2000;payload='SECRET'});token='SECRET'})})
$s=$script:lines -join ' '
if($s -notmatch 'UNINSTRUMENTED' -or $s -notmatch 'NONE_RECORDED' -or $s -notmatch 'ordinary host=akashi.vk-portal.net profile=chrome stage=DIRECT' -or $s -notmatch 'ordinary address=87.240.137.208:443 stage=DIRECT first_flight=TLS_SERVER_HELLO; NOT_HTTP_PROOF tx=100 rx=2000' -or $s -match 'SECRET'){throw 'Ordinary host/address diagnostics unsafe or missing'}
Write-Host 'PASS ordinary per-host DNS/TLS/route evidence and safe legacy/empty output'

$script:lines=@()
Write-OrdinaryAddressEvidence ([pscustomobject]@{ordinary=@();ordinary_retained=12;ordinary_omitted=12;ordinary_dns_direct_attempts=2;ordinary_scope_denials=1;ordinary_ladder=@([pscustomobject]@{id=7;domain='akashi.vk-portal.net';destination='95.213.5.12:443';stage='RELAY';reason='OPEN_FAILED';TX=0;RX=0;token='SECRET'})})
$s=$script:lines -join ' '
if($s -notmatch 'OMITTED_BY_IPC_BUDGET retained=12' -or $s -match 'NONE_RECORDED' -or $s -notmatch 'DNS DIRECT attempts=2 scope_denials=1' -or $s -notmatch 'ordinary ladder: record_id=7 host=akashi.vk-portal.net' -or $s -match 'SECRET'){throw 'Trimmed ordinary evidence mislabeled or unsafe'}
Write-CdnTrialEvidence ([pscustomobject]@{trials=@([pscustomobject]@{ID=9;trial_id=2;Host='rr5---sn-media.googlevideo.com';Sibling=[pscustomobject]@{MediaBytes=2000000;MediaMatch='EXACT_HOST';MediaHost='rr5---sn-media.googlevideo.com'};slot_active=$true});cdn_endpoint_negatives=@([pscustomobject]@{Host='rr5---sn-media.googlevideo.com';Address='74.125.8.99:443';Reason='MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED';Strategy='catalog-test';private='SECRET'})})
$s=$script:lines -join ' '
if($s -notmatch 'trial_id=2 record_id=9' -or $s -notmatch 'media_rx=2000000' -or $s -notmatch 'CDN endpoint negative: host=rr5---sn-media.googlevideo.com address=74.125.8.99:443' -or $s -match 'SECRET'){throw 'Endpoint/exposure/media metadata unsafe or missing'}
Write-Host 'PASS IPC omission is explicit, actual ordinary ladder hosts, bulk evidence and endpoint-only failures'
