# Pure generated fixtures; no activation, filesystem credential writes or service calls.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repo 'tools/windows/club-code-common.ps1')
foreach($n in @('club-code-common','New-ClubCodeFile','Set-ClubActivationCode')){$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repo ('tools/windows/'+$n+'.ps1')),[ref]$t,[ref]$e);if($e.Count){throw ('parser '+$n)}}
# This is a non-issued test fixture, never a production code.
$a=New-ClubPendingRecord 'VQ-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA';$b=New-ClubPendingRecord 'VQ-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA'
if(!$a.pending -or $a.request_id.Length -ne 32 -or $a.request_id -eq $b.request_id -or $a.ContainsKey('machine_hash')){throw 'pending record contract'}
foreach($bad in @('test','VQ-short','',"wrong`ncode")){$ok=$false;try{$null=New-ClubPendingRecord $bad}catch{$ok=$true};if(!$ok){throw 'invalid code accepted'}}
Write-Output 'PASS pending record format/random request/invalid code/parser; no production enrollment or SCM operations'
$script:running=$true;$script:starts=0;$script:writes=0;$script:failWrite=$false
function Get-Service {param($Name);$v=[pscustomobject]@{Status=$(if($script:running){'Running'}else{'Stopped'})};$v|Add-Member ScriptMethod WaitForStatus {param($state,$timeout)};return $v}
function Stop-Service {param($Name);$script:running=$false}
function Start-Service {param($Name);$script:running=$true;$script:starts++}
function Write-ClubJson {param($Path,$Value);if($script:failWrite){throw 'injected'};$script:writes++}
Invoke-ClubCodeReplacement -Directory ([IO.Path]::GetTempPath()) -Record $a
if(!$script:running -or $script:starts -ne 1 -or $script:writes -ne 1){throw 'live code rotation order'}
Invoke-ClubCodeReplacement -Directory ([IO.Path]::GetTempPath()) -Record $b -Image
if(!$script:running -or $script:starts -ne 1 -or $script:writes -ne 2){throw 'offline edit touched administrator PC service'}
$script:running=$true;$script:failWrite=$true;$errorCode=''
try{Invoke-ClubCodeReplacement -Directory ([IO.Path]::GetTempPath()) -Record $a}catch{$errorCode=$_.Exception.Message}
if(!$script:running -or $errorCode -notlike 'CLUB_CODE_REPLACEMENT_FAILED*'){throw 'write failure did not restore existing service'}
Write-Output 'PASS mocked live rotation, image remains stopped, failed atomic write restores service; no actual installation or secrets written'
