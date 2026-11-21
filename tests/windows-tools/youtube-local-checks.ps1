$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\..\tools\windows\diag-no-vpn.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($name in @('Prop','Write-YouTubeLocalEvidence')){$fn=$ast.Find({param($a)$a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $name},$true);if(!$fn){throw ('Missing '+$name)};Invoke-Expression $fn.Extent.Text}
$script:lines=@();function Say([string]$s){$script:lines+=@($s)}
Write-YouTubeLocalEvidence $null
if(($script:lines -join "`n") -notmatch 'UNINSTRUMENTED'){throw 'Legacy service fabricated ladder'}
$script:lines=@()
Write-YouTubeLocalEvidence ([pscustomobject]@{cache_entries=1;replay_contract='before origin only';stages=@([pscustomobject]@{stage='LOCAL';strategy='fake5x2-disorder';Connections=3;TX=123;RX=65536;Failures=0;Confirmed=1});records=@([pscustomobject]@{id=9;profile='chrome';domain='r1.googlevideo.com';stage='LOCAL';TX=123;RX=65536;Transform=$true;TransformKnown=$true;reason='SUSTAINED_TLS_TRANSPORT_NOT_PLAYBACK_PROOF'});secret='DO_NOT_PRINT'})
$text=$script:lines -join "`n"
if($text -notmatch 'stage=LOCAL strategy=fake5x2-disorder connections=3 tx=123 rx=65536' -or $text -match 'DO_NOT_PRINT'){throw 'Scoped safe metrics broken'}
if($text -notmatch 'not playback PASS'){throw 'Transport promoted to playback proof'}
Write-Host 'PASS YouTube ladder diagnostics, StrictMode, legacy response and secret allowlist (PS7; native PS5.1 not executed)'

$script:lines=@()
Write-YouTubeLocalEvidence ([pscustomobject]@{selection=[pscustomobject]@{Trials=3;TrialSuccesses=2;TrialFailures=1;FailedAfterReply=1;active_trial=$false;contract='one trial';secret='HIDDEN'};cache=@([pscustomobject]@{Profile='chrome';Domain='googlevideo:sn-abc';Streak=2;Stage='RELAY'})})
$text=$script:lines -join "`n"
if($text -notmatch 'trials=3 trial_success=2 trial_fail=1 failed_after_reply=1' -or $text -notmatch 'streak=2' -or $text -match 'HIDDEN'){throw 'Trial cost or subgroup streak missing/unsafe'}
Write-Host 'PASS CDN trial counters including failures after origin reply and consecutive streak'

$script:lines=@()
Write-YouTubeLocalEvidence ([pscustomobject]@{shared_learning=[pscustomobject]@{state='SIGNED_SHARED_LEARNING';rows=@([pscustomobject]@{profile='chrome';group='googlevideo:sn-abc';picker=$false;candidate='catalog-x';state='SHARED_CANDIDATE_REQUIRES_LOCAL_CONFIRMATION'});device_key='HIDDEN_PROOF'}})
$text=$script:lines -join "`n"
if($text -notmatch 'SIGNED_SHARED_LEARNING' -or $text -notmatch 'candidate=catalog-x' -or $text -match 'HIDDEN_PROOF'){throw 'Unsafe or missing shared learning projection'}
Write-Host 'PASS shared learning candidate is diagnostic data, no proof/identity output'

$script:lines=@()
Write-YouTubeLocalEvidence ([pscustomobject]@{selection=[pscustomobject]@{TrialInconclusive=1;ClientInitiatedTrialCloses=1;active_trial=$true;active_domain='googlevideo:sn-x';active_age_ms=300;active_last_rx_age_ms=200;active_state='SHORT_REPLY_WAITING_TERMINAL'};cache=@([pscustomobject]@{Domain='googlevideo:sn-b';TrialAdmission='GLOBAL_TRIAL_ACTIVE';TrialChecks=4;TrialDenials=4});stages=@([pscustomobject]@{service='youtube-media';stage='LOCAL';HelloSamples=2;HelloSumMS=400;HelloMaxMS=300;Inconclusive=1})})
$text=$script:lines -join "`n"
if($text -notmatch 'trial_inconclusive=1' -or $text -notmatch 'client_initiated_trial_closes=1' -or $text -notmatch 'admission=GLOBAL_TRIAL_ACTIVE checks=4 denials=4' -or $text -notmatch 'hello_avg_ms=200'){throw 'Missing neutral/admission/timing evidence'}
Write-Host 'PASS neutral trial, admission reason and LOCAL/RELAY hello latency aggregation'

$script:lines=@()
Write-YouTubeLocalEvidence ([pscustomobject]@{selection=[pscustomobject]@{StrongPromotions=1;PostPromotionFailures=1;RemoteSmallEOFInconclusive=2};records=@([pscustomobject]@{trial_result='SUCCESS_RUNNING';reason='SUSTAINED_CDN_RUNNING_PROMOTED'})})
$text=$script:lines -join "`n"
if($text -notmatch 'strong_promotions=1 post_promotion_failures=1 small_eof_inconclusive=2' -or $text -notmatch 'trial_result=SUCCESS_RUNNING'){throw 'Running promotion/revocation/inconclusive counters missing'}
Write-Host 'PASS explicit running trial success and later revocation diagnostics'

$script:lines=@()
Write-YouTubeLocalEvidence ([pscustomobject]@{selection=[pscustomobject]@{DataTrials=0;Trials=1;TrialInconclusive=1};cache=@([pscustomobject]@{Domain='googlevideo:sn-test';TrialChecks=6;SiblingWaits=6;Sibling=[pscustomobject]@{Reason='RELAY_ACTIVITY_EXPIRED';AgeMS=31000}})})
$s=$script:lines -join ' '
if($s -notmatch 'data_trials=0' -or $s -notmatch 'sibling_waits=6 sibling_reason=RELAY_ACTIVITY_EXPIRED sibling_age_ms=31000'){throw 'Missing meaningful trial/sibling wait evidence'}
Write-Host 'PASS distinct probe/data trial counters and sibling denials/age'

$script:lines=@();Write-YouTubeLocalEvidence ([pscustomobject]@{selection=[pscustomobject]@{PostTrialFailures=1}})
if(($script:lines -join ' ') -notmatch 'post_trial_failures=1'){throw 'Late failure counter missing'}
Write-Host 'PASS late hard failures remain visible after neutral finalization'

$script:lines=@()
Write-YouTubeLocalEvidence ([pscustomobject]@{selection=[pscustomobject]@{active_trial=$true;active_trial_id=2;active_record_id=9;active_host='rr5---sn-media.googlevideo.com';active_destination='74.125.8.99:443';active_record_matches=$true;active_record_result='PROBE_WAITING_DATA'}})
$s=$script:lines -join ' '
if($s -notmatch 'active_trial_id=2 active_record_id=9 active_host=rr5---sn-media.googlevideo.com' -or $s -notmatch 'active_record_matches=True'){throw 'Active exposure cannot be distinguished from old terminal host'}
Write-Host 'PASS active exposure/record/host/IP identity is explicit'
