#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')
function TrafficField($Object,[string]$Name,$Default=$null){if($null -ne $Object){$p=$Object.PSObject.Properties[$Name];if($null -ne $p -and $null -ne $p.Value){return $p.Value}};return $Default}
$s=Invoke-ServiceIPC 'traffic.status'
$c=TrafficField $s 'client';$server=TrafficField $s 'server'
Write-Host ('Client: '+(TrafficField $c 'state')+'; '+(TrafficField $c 'scope'))
Write-Host ('Session bytes: '+((TrafficField $c 'SessionTotal')|ConvertTo-Json -Compress))
Write-Host ('UTC day bytes: '+((TrafficField $c 'DayTotal')|ConvertTo-Json -Compress))
@(TrafficField $c 'days' @()) | Select-Object day_utc,profile,service,subgroup,reason,logical_relay,Sent,Received | Format-Table -AutoSize
Write-Host ('Server: '+(TrafficField $server 'state')+'; '+(TrafficField $server 'error' '')+'; '+(TrafficField $server 'scope'))
foreach($row in @(TrafficField $server 'relays' @())){
 [pscustomobject]@{relay=(TrafficField $row 'relay');month_utc=(TrafficField $row 'month_utc');known_GB=[math]::Round([double](TrafficField $row 'known_egress_bytes' 0)/1e9,3);limit_GB=[math]::Round([double](TrafficField $row 'monthly_limit_bytes' 0)/1e9,1);forecast_GB=$(if(TrafficField $row 'forecast_valid' $false){[math]::Round([double](TrafficField $row 'forecast_bytes' 0)/1e9,1)}else{'UNKNOWN'});known_from=(TrafficField $row 'known_from');partial=(TrafficField $row 'partial_coverage' $true);warning=(TrafficField $row 'warning')} | Format-List
}
Write-Host 'No SSH/deployment. Missing/partial server data never proves zero usage or available quota. Provider billing period may differ from UTC calendar month.'
