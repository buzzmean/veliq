[CmdletBinding(SupportsShouldProcess=$true)]
param([string[]]$ProfileIds=@(),[switch]$RestoreGlobalDirect)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
if(!$ProfileIds.Count){throw 'Specify existing profile IDs after reviewing profiles. No profile is migrated implicitly.'}
$status=Invoke-ServiceIPC 'status'
$backup=Join-Path $env:LOCALAPPDATA ('VELIQ\migration-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
if(!$WhatIfPreference){[void](New-Item -ItemType Directory -Path $backup -Force)}
# IPC status contains configuration/metadata, never device private keys/tickets.
if(!$WhatIfPreference){$status|ConvertTo-Json -Depth 20|Set-Content (Join-Path $backup 'before.json') -Encoding UTF8}
foreach($id in $ProfileIds){
 $p=@($status.profiles|Where-Object{$_.id -eq $id})
 if($p.Count -ne 1){throw "Unknown/ambiguous profile ID: $id"}
 if($PSCmdlet.ShouldProcess($p[0].name,'Migrate this profile to AUTO, preserving its selected strategy and relay')){
  $copy=$p[0]|ConvertTo-Json -Depth 20|ConvertFrom-Json;$copy.mode='AUTO'
  [void](Invoke-ServiceIPC 'profile.set' $copy)
 }
}
if($RestoreGlobalDirect -and $PSCmdlet.ShouldProcess('Global failover','Restore DIRECT after OpenAI per-profile protection is verified')){
 $current=Invoke-ServiceIPC 'status'
 $openai=@($current.profiles|Where-Object{($_.PSObject.Properties['app_preset'] -and $_.app_preset -eq 'openai')})
 if(!$openai.Count -or @($openai|Where-Object{$_.mode -ne 'AUTO'}).Count){throw 'OpenAI AUTO profile required before removing the global workaround'}
 $settings=$current.settings;$settings.failover='DIRECT';[void](Invoke-ServiceIPC 'settings.set' $settings)
}
Write-Host "Configuration snapshot: $backup. Reopen applications for new flow decisions. Run the documented real Windows acceptance; this script does not declare PASS."
