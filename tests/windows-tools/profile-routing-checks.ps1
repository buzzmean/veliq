$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$path=Join-Path $PSScriptRoot '..\..\tools\windows\diag-no-vpn.ps1'
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($name in @('Prop','Get-RelayProfileSummary','Write-RelayProfileAudit')){
 $fn=$ast.Find({param($a)$a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $name},$true)
 if(!$fn){throw "Missing diagnostic function $name"};Invoke-Expression $fn.Extent.Text
}
function Check($Condition,[string]$Message){if(!$Condition){throw $Message}}
$profile=[pscustomobject]@{id='cs2';mode='AUTO'}
$flow=[pscustomobject]@{pid=42;creation_time=10;process_group='cs2';selected_route='RELAY';relay_id='VPS-01';protocol='udp';destination='203.0.113.1:27025';counters=[pscustomobject]@{relayed_packets=28025};policy=[pscustomobject]@{source='profile';fallback='FAIL_OPEN_DIRECT'};secret='NEVER_LOG'}
$snap=[pscustomobject]@{pid=42;birth=10;data=[pscustomobject]@{flows=@($flow)}}
$text=@(Get-RelayProfileSummary $profile $null @($snap))-join "`n"
Check ($text -match 'UNKNOWN_LEGACY_AUTO' -and $text -match 'relayed=28025' -and $text -match 'source=profile') 'Legacy AUTO relay hidden'
Check ($text -notmatch 'NEVER_LOG') 'Unrelated secret-shaped field printed'
$snap.birth=11
$text=@(Get-RelayProfileSummary $profile $null @($snap))-join "`n"
Check ($text -notmatch 'FLOW profile=') 'PID reuse attributed old relay traffic'
$snap.birth=10;$flow.process_group='other'
Check ((@(Get-RelayProfileSummary $profile $null @($snap))-join "`n") -notmatch 'FLOW profile=') 'Another profile misattributed'
$flow.process_group='cs2';$snap.data|Add-Member -NotePropertyName truncated -NotePropertyValue $true
$routing=[pscustomobject]@{default_route='DIRECT';origin='built_in';automatic_relay_allowed=$false}
$text=@(Get-RelayProfileSummary $profile $routing @($snap))-join "`n"
Check ($text -match 'default=DIRECT' -and $text -match 'origin=built_in' -and $text -match 'snapshots_complete=False' -and $text -match 'FLOW profile=') 'Configured DIRECT hid retained relay evidence/truncation'
$manual=[pscustomobject]@{id='manual';mode='MANUAL';relay_id='VPS-01'}
Check ((@(Get-RelayProfileSummary $manual $null @())-join "`n") -match 'default=RELAY') 'Idle configured relay hidden'

# Exercise the real collector under StrictMode without scanning processes or
# reading credentials: two identities of one app, an old service, exact scopes.
$script:lines=@();$script:scopes=@()
function Say([string]$Line){$script:lines+=@($Line)}
function Invoke-IPC([string]$Method,$Payload=$null){
 switch($Method){
  'profiles' {return @([pscustomobject]@{id='cs2';mode='AUTO';executables=@('cs2.exe')})}
  'profiles.routing' {throw 'unsupported IPC method'}
  'processes' {return @([pscustomobject]@{PID=42;CreationTime=10})}
  'capture.diagnostics' {$script:scopes+=@($Payload);return [pscustomobject]@{flows=@($flow)}}
  default {throw "Unexpected method $Method"}
 }
}
Write-RelayProfileAudit
Check ($script:scopes.Count -eq 1 -and $script:scopes[0].pid -eq 42 -and $script:scopes[0].creation_time -eq 10) 'Collector lost PID/birth scope'
Check (($script:lines -join "`n") -match 'relayed=28025') 'Real collector omitted CS relay evidence'
Write-Host 'PASS profile relay diagnostics: legacy AUTO, actual relay evidence, manual defaults, PID/birth/group scope, truncation, safe metadata and old service'
