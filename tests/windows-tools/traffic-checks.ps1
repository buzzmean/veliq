#requires -Version 5.1
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\..\tools\windows\diag-no-vpn.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($name in @('Prop','Write-TrafficEvidence')){$fn=$ast.Find({param($a)$a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $name},$true);if(!$fn){throw ('Missing '+$name)};Invoke-Expression $fn.Extent.Text}
$script:lines=@();function Say([string]$s){$script:lines+=@($s)}
Write-TrafficEvidence $null
if(($script:lines -join "`n") -notmatch 'usage UNKNOWN'){throw 'Missing data invented quota'}
$script:lines=@()
Write-TrafficEvidence ([pscustomobject]@{client=[pscustomobject]@{state='RESTORED';SessionTotal=[pscustomobject]@{Sent=12;Received=123};days=@([pscustomobject]@{profile='chrome';service='youtube-media';subgroup='googlevideo:sn-a';reason='LOCAL_HEALTH_NOT_CONFIRMED';Sent=12;Received=123});epoch='PRIVATE_DEVICE_ID'};server=[pscustomobject]@{state='SIGNED_SERVER_NIC_TRAFFIC';relays=@([pscustomobject]@{relay='VPS-PRIMARY';month_utc='2026-10';known_egress_bytes=2400000000000;monthly_limit_bytes=3000000000000;partial_coverage=$true;warning='BUDGET_AT_RISK'});heartbeat_token='SECRET'}})
$text=$script:lines -join "`n"
if($text -notmatch 'youtube-media' -or $text -notmatch 'BUDGET_AT_RISK' -or $text -notmatch 'partial=True' -or $text -match 'SECRET|PRIVATE_DEVICE_ID'){throw 'Traffic projection missing/unsafe'}
Write-Host 'PASS traffic UTC/session, partial budget, legacy UNKNOWN and secret allowlist'
