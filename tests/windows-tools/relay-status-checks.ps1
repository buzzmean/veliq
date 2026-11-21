#requires -Version 5.1
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$path=Join-Path $PSScriptRoot '..\..\tools\windows\relay-status.ps1'
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($name in @('Read-RelayStatusField','Get-RelayStatusRows')){
 $fn=$ast.Find({param($a)$a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $name},$true)
 if(!$fn){throw ('MISSING '+$name)};Invoke-Expression $fn.Extent.Text
}
$before=[pscustomobject]@{connections=@([pscustomobject]@{authenticated_relay_id='VPS-PRIMARY';TX=100;RX=200})}
$after=[pscustomobject]@{connections=@([pscustomobject]@{authenticated_relay_id='VPS-PRIMARY';configured_address='146.0.77.98:4433';observed_tcp_session_endpoint='146.0.77.98:4433';TX=1100;RX=10200;Active=3;Opens=4;pool_healthy=$true;health='SESSION_ALIVE';probe_rtt_ms=60;private_token='SECRET'})}
$rows=@(Get-RelayStatusRows $before $after 2)
if($rows.Count -ne 1 -or $rows[0].sampled_payload_mbps -ne 0.044 -or $rows[0].active_tunnels -ne 3 -or !$rows[0].pool_healthy){throw 'WRONG_LIVE_DELTA'}
if(($rows|ConvertTo-Json) -match 'SECRET|private_token'){throw 'UNSAFE_PROJECTION'}
$reset=@(Get-RelayStatusRows $after $before 1)
if(!$reset[0].counter_reset -or $null -ne $reset[0].sampled_payload_mbps){throw 'RESET_INVENTED_BANDWIDTH'}
$legacy=@(Get-RelayStatusRows $null ([pscustomobject]@{connections=@([pscustomobject]@{authenticated_relay_id='old'})}) 1)
if($legacy[0].health -ne 'UNINSTRUMENTED' -or $legacy[0].pool_healthy -ne 'UNKNOWN'){throw 'LEGACY_HEALTH_INVENTED'}
if((Get-Content -Raw $path) -match 'relay-client.exe|add-relay-vps.ps1|--mode'){throw 'READ_ONLY_STATUS_REQUIRES_DEPLOYMENT_HELPER'}
Write-Host 'PASS read-only live relay status, byte deltas, reset/legacy evidence, no secrets or SSH/helper'
$path=Join-Path $PSScriptRoot '..\..\tools\windows\diag-no-vpn.ps1'
$ast=[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($name in @('Prop','Write-RelaySelectionEvidence')){$fn=$ast.Find({param($a)$a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $name},$true);if(!$fn){throw ('MISSING '+$name)};Invoke-Expression $fn.Extent.Text}
$script:lines=@();function Say([string]$s){$script:lines+=@($s)}
Write-RelaySelectionEvidence $null
if(($script:lines -join ' ') -notmatch 'UNINSTRUMENTED'){throw 'MISSING_LEGACY_SELECTION'}
$script:lines=@()
$after|Add-Member -NotePropertyName preferred_for_new_opens -NotePropertyValue 'VPS-01'
$after|Add-Member -NotePropertyName selection_reason -NotePropertyValue 'STANDBY_HELD_PRIMARY_RECOVERING'
Write-RelaySelectionEvidence $after
$text=$script:lines -join ' '
if($text -notmatch 'STANDBY_HELD_PRIMARY_RECOVERING' -or $text -match 'SECRET|private_token'){throw 'BAD_SELECTION_EVIDENCE'}
Write-Host 'PASS diag hysteresis/health projection, legacy fallback, secret allowlist'
