#requires -Version 5.1
[CmdletBinding()]
param([string]$Manifest=(Join-Path $env:ProgramData 'VELIQ\service.json'))
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')

function Read-RelayStatusField($Object,[string]$Name,$Fallback=$null) {
 if($null -ne $Object){$p=$Object.PSObject.Properties[$Name];if($null -ne $p){return $p.Value}}
 return $Fallback
}
function Get-RelayStatusRows($Before,$After,[double]$Seconds) {
 foreach($row in @(Read-RelayStatusField $After 'connections' @())){
  $id=Read-RelayStatusField $row 'authenticated_relay_id' 'UNKNOWN'
  $old=@(Read-RelayStatusField $Before 'connections' @() | Where-Object {(Read-RelayStatusField $_ 'authenticated_relay_id') -eq $id}) | Select-Object -First 1
  $tx=[double](Read-RelayStatusField $row 'TX' 0)-[double](Read-RelayStatusField $old 'TX' 0)
  $rx=[double](Read-RelayStatusField $row 'RX' 0)-[double](Read-RelayStatusField $old 'RX' 0)
  $reset=$tx -lt 0 -or $rx -lt 0
  $rate=$null;if(!$reset -and $Seconds -gt 0){$rate=[Math]::Round(($tx+$rx)*8/$Seconds/1e6,3)}
  [pscustomobject]@{
   authenticated_relay_id=$id;configured_address=(Read-RelayStatusField $row 'configured_address' 'UNKNOWN')
   observed_tcp_session_endpoint=(Read-RelayStatusField $row 'observed_tcp_session_endpoint' 'NOT_OBSERVED')
   pool_healthy=(Read-RelayStatusField $row 'pool_healthy' 'UNKNOWN');health=(Read-RelayStatusField $row 'health' 'UNINSTRUMENTED')
   probe_rtt_ms=(Read-RelayStatusField $row 'probe_rtt_ms');probe_observed_at=(Read-RelayStatusField $row 'probe_observed_at')
   active_tunnels=(Read-RelayStatusField $row 'Active' 0);total_opens=(Read-RelayStatusField $row 'Opens' 0)
   sent_payload_bytes=(Read-RelayStatusField $row 'TX' 0);received_payload_bytes=(Read-RelayStatusField $row 'RX' 0)
   sampled_payload_mbps=$rate;counter_reset=$reset;sample_seconds=$Seconds
   new_open_failures=(Read-RelayStatusField $row 'new_open_failures' 0);last_failure_class=(Read-RelayStatusField $row 'last_failure_class' '')
  }
 }
}
# Kept for command-line compatibility. This command describes the live SCM service,
# never mistakes an offline manifest/signed-cache helper for actual traffic proof.
$liveManifest=Join-Path $env:ProgramData 'VELIQ\service.json'
if([IO.Path]::GetFullPath($Manifest) -ne [IO.Path]::GetFullPath($liveManifest)){throw 'LIVE_SERVICE_STATUS_ONLY: -Manifest must name the installed service manifest'}
$before=Invoke-ServiceIPC 'relay.primary.status'
$timer=[Diagnostics.Stopwatch]::StartNew()
Start-Sleep -Seconds 1
$after=Invoke-ServiceIPC 'relay.primary.status'
$timer.Stop()
[pscustomobject]@{
 preferred_for_new_opens=(Read-RelayStatusField $after 'preferred_for_new_opens' 'UNINSTRUMENTED')
 selection_reason=(Read-RelayStatusField $after 'selection_reason' 'UNINSTRUMENTED')
 last_opened_authenticated_relay=(Read-RelayStatusField $after 'last_opened_authenticated_relay' 'NOT_OBSERVED')
 last_open_reason=(Read-RelayStatusField $after 'reason' '')
 standby_hold_until=(Read-RelayStatusField $after 'standby_hold_until')
 primary_healthy_since=(Read-RelayStatusField $after 'primary_healthy_since')
 selection_switches=(Read-RelayStatusField $after 'selection_switches' 0)
} | Format-List
Get-RelayStatusRows $before $after $timer.Elapsed.TotalSeconds | Format-List
$poolIds=@(Read-RelayStatusField $after 'connections' @() | ForEach-Object {Read-RelayStatusField $_ 'authenticated_relay_id'} | Where-Object {$_} | Select-Object -Unique)
if($poolIds.Count -eq 0){$poolIds=@('VPS-PRIMARY','VPS-01')}
foreach($id in $poolIds){
 try{$pool=Invoke-ServiceIPC 'relay.pool.diagnostics' @{relay_id=$id};[pscustomobject]@{relay=$id;active_sessions=$pool.active_sessions;healthy_sessions=$pool.healthy_sessions;active_flows=$pool.active_flows;available_capacity=$pool.available_capacity;saturation_events=$pool.saturation_events;session_failures=$pool.session_failures} | Format-List}
 catch{Write-Host ('pool '+$id+': UNAVAILABLE_OR_NOT_CONFIGURED')}
}
Write-Host 'Read-only live IPC; no SSH, deployment, build or credential files. Actual opens/endpoint/bytes prove usage. Preferred route is future selection only. Probe RTT is not bandwidth; sampled payload includes existing pinned streams. Missing/stale probes are explicit. For monthly NIC budget: relay-traffic.ps1.'
