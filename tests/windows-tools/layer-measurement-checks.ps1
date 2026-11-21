#requires -Version 5.1
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$path=Join-Path $PSScriptRoot '..\..\tools\windows\diag-no-vpn.ps1'
$tokens=$null;$errors=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($name in @('Prop','Write-RelayOpenPerformance','Write-CdnTrialEvidence','Write-OrdinaryAddressEvidence','Write-LocalProbeEvidence')){
 $fn=$ast.Find({param($n)$n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if(!$fn){throw ('MISSING '+$name)};Invoke-Expression $fn.Extent.Text
}
$script:lines=@();function Say([string]$s){$script:lines+=@($s)}
Write-RelayOpenPerformance ([pscustomobject]@{session_creation=[pscustomobject]@{Attempts60s=5;NewSessions60s=4;MaxAttempts60s=8;MaxNewSessions60s=7;Concurrent=1;MaxConcurrent=1;Recent=@([pscustomobject]@{reason='session_replacement';success=$true;factory_ms=75;quic_handshake_ms=42;private_ticket='SECRET'})}})
Write-LocalProbeEvidence ([pscustomobject]@{layer_audit=[pscustomobject]@{PureTS=10;PureTSNegotiationUnknown=2;PureTSNotNegotiated=0;EarlyRetransmitCandidates=3;TimestampOptionRequired=1;Scope='retained only';private_key='SECRET'}})
$s=$script:lines -join ' '
if($s -notmatch 'attempts=5 created=4 max_attempts=8 max_created=7 creating=1 max_concurrent=1' -or $s -notmatch 'QUIC_handshake_ms=42' -or $s -notmatch 'pure_ts=10' -or $s -notmatch 'negotiation_unknown=2' -or $s -notmatch 'early_retrans_candidates=3' -or $s -match 'SECRET|private_ticket|private_key'){throw 'MEASUREMENT_PROJECTION_BAD_OR_UNSAFE'}
$script:lines=@();Write-RelayOpenPerformance $null;Write-LocalProbeEvidence $null
if(($script:lines -join ' ') -notmatch 'UNINSTRUMENTED'){throw 'LEGACY_MEASUREMENT_INVENTED'}
$source=Get-Content -LiteralPath $path -Raw
if($source -notmatch "if\(Want 'layers'\)" -or $source -notmatch "'network-check.exe'" -or $source -notmatch 'DNS_NEGATIVE|NXDOMAIN\+aa' -or $source -notmatch 'LASTEXITCODE'){throw 'MISSING_LAYER_PROBE_GATES'}
Write-Host 'PASS phase0 session/layer evidence, legacy unknowns, secret allowlist, bounded explicit layer helper; PS5.1 syntax only unless run there'
