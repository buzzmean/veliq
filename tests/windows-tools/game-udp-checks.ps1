$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
foreach($path in @('tools/windows/game-udp-report.ps1','tools/windows/diag-game-udp.ps1','tools/windows/diag-no-vpn.ps1','tools/windows/Close-VeliqGuiForUpdate.ps1')){
 $tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseFile((Join-Path $root $path),[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){throw ($errors|Out-String)}
}
. (Join-Path $root 'tools/windows/game-udp-report.ps1')
$s=[pscustomobject]@{profiles=@([pscustomobject]@{profile_id='pubg';engine=[pscustomobject]@{flows=@([pscustomobject]@{stage='DIRECT';pid=17;variant=[pscustomobject]@{id='must-not-claim-applied'}})}})}
$rows=@(Get-GameUdpRows $s);if($rows.Count -ne 1 -or $rows[0].variant -ne '' -or $rows[0].inbound -ne 0){throw 'Unknown/optional fields under StrictMode or DIRECT misreported'}
$s.profiles[0].engine.flows[0].stage='LOCAL_UDP';$rows=@(Get-GameUdpRows $s);if($rows[0].variant -ne 'must-not-claim-applied'){throw 'Missing selected variant'}
$script=[IO.File]::ReadAllText((Join-Path $root 'tools/windows/diag-game-udp.ps1'))
if($script -match 'Invoke-VpsCommand|\bssh\b|\bscp\b|Invoke-ServiceIPC\s+\x27(?:gameudp.set|optimize)'){throw 'Read-only helper mutates state'}
if(!$script.Contains('capture.changes.marker') -or !$script.Contains('Merge-SimPage') -or !$script.Contains('GAME_CAPTURE_INCOMPLETE')){throw 'Bounded complete evidence missing'}
Write-Host 'PASS game UDP PS parsing, StrictMode/optional fields, read-only bounded capture; no installation/VPS access'
$s.profiles[0].engine.flows[0]|Add-Member -NotePropertyName selection_reason -NotePropertyValue 'LOCAL_FIRST_UNCONFIRMED_ENDPOINT'
$rows=@(Get-GameUdpRows $s);if($rows[0].selection -ne 'LOCAL_FIRST_UNCONFIRMED_ENDPOINT'){throw 'Flow selection evidence lost'}

$close=Get-Content -Raw (Join-Path $root 'tools/windows/Close-VeliqGuiForUpdate.ps1')
if($close -match 'Stop-Process|taskkill|Stop-Service|Invoke-ServiceIPC|chrome://quit'){throw 'GUI update helper touches routing or process kill'}
if(!$close.Contains('WriteByte(2)') -or !$close.Contains('SessionId')){throw 'GUI update not scoped to activation pipe/session'}
