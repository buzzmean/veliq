#requires -Version 5.1
<# Read-only 2-minute wire-level observation. No browser/process/policy/VPS changes.
Start this BEFORE opening a video in the existing browser. No playback PASS inferred.
#>
param([ValidateRange(10,180)][int]$DurationSeconds=120,[string]$OutputFile='')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')
function VideoField($o,[string]$n,$fallback=$null){if($null -ne $o){$p=$o.PSObject.Properties[$n];if($null -ne $p){return $p.Value}};return $fallback}
function VideoInterval($previous,$current,[datetime]$at){
 if($null -eq $previous){return [pscustomobject]@{state='BASELINE';mbps=-1}}
 $elapsed=($at-$previous.at).TotalSeconds
 $bytes=[long](VideoField $current 'received_bytes' 0)
 if($elapsed -le 0 -or $bytes -lt $previous.bytes){return [pscustomobject]@{state='COUNTER_RESET';mbps=-1}}
 return [pscustomobject]@{state='MEASURED';mbps=([double]($bytes-$previous.bytes)*8/$elapsed/1000000)}
}
if(!$OutputFile){$OutputFile=Join-Path $PSScriptRoot '..\..\bin\diagnostics\video-relay.csv'}
$parent=Split-Path -Parent ([IO.Path]::GetFullPath($OutputFile));[void][IO.Directory]::CreateDirectory($parent)
$previous=@{};$rows=New-Object 'Collections.Generic.List[object]';$start=[datetime]::UtcNow;$end=$start.AddSeconds($DurationSeconds);$omitted=[long]0;$resets=0
Write-Host 'Read-only video relay observation: open/play/seek in the ALREADY OPEN browser. Browser/GUI will not be restarted. Rates include TLS; no playback/FPS PASS inferred.'
try{
 while([datetime]::UtcNow -lt $end){
  $native=Invoke-ServiceIPC 'browser.native.status'
  $usage=VideoField $native 'relay_usage'
  $videoProperty=if($null -ne $usage){$usage.PSObject.Properties['video_connections']}else{$null}
  if($null -eq $videoProperty -or $null -eq $videoProperty.Value){throw 'VIDEO_PERFORMANCE_UNINSTRUMENTED: update service first'}
  $connections=@($videoProperty.Value)
  $at=[datetime]::UtcNow;$omitted=[Math]::Max($omitted,[long](VideoField $usage 'video_connections_omitted' 0))
  foreach($v in @($connections)){
   $key=([string](VideoField $v 'id'))+'|'+([string](VideoField $v 'started'))
   $old=$null;if($previous.ContainsKey($key)){$old=$previous[$key]}
   $rate=VideoInterval $old $v $at
   if($rate.state -eq 'COUNTER_RESET'){$resets++}
   if($previous.Count -ge 256 -and !$previous.ContainsKey($key)){$previous.Clear();$omitted++}
   $previous[$key]=[pscustomobject]@{at=$at;bytes=[long](VideoField $v 'received_bytes' 0)}
   $rows.Add([pscustomobject][ordered]@{
    time_utc=$at.ToString('o');offset_s=[Math]::Round(($at-$start).TotalSeconds,3);id=(VideoField $v 'id');profile=(VideoField $v 'profile_id');domain=(VideoField $v 'domain');destination=(VideoField $v 'destination');state=(VideoField $v 'state');rate_state=$rate.state
    interval_rx_mbps=$rate.mbps;average_rx_mbps=(VideoField $v 'average_receive_mbps' -1);receive_span_mbps=(VideoField $v 'receive_span_mbps' -1)
    admission_ms=(VideoField $v 'admission_ms' -1);relay_open_ms=(VideoField $v 'relay_open_ms' -1);first_byte_ms=(VideoField $v 'first_byte_ms' -1);write_to_first_byte_ms=(VideoField $v 'write_to_first_byte_ms' -1);max_read_gap_ms=(VideoField $v 'max_read_gap_ms' -1);rx=(VideoField $v 'received_bytes' 0);tx=(VideoField $v 'sent_bytes' 0)
   })
  }
  if($rows.Count -gt 4320){throw 'VIDEO_PERFORMANCE_LOCAL_ROW_BOUND'}
  Start-Sleep -Milliseconds 1000
 }
} finally {
 if($rows.Count -gt 0){$rows | Export-Csv -LiteralPath $OutputFile -NoTypeInformation -Encoding UTF8}
}
if($rows.Count -eq 0){Write-Host 'NO_VIDEO_CONNECTIONS_OBSERVED; no CSV created; NOT playback PASS';return}
Write-Host ('OBSERVATION COMPLETE; rows='+$rows.Count+' omitted_at_least='+$omitted+' resets='+$resets+' file='+$OutputFile+'; NOT playback PASS')
