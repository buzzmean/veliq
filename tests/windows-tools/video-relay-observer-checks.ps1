$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Join-Path ([IO.Path]::GetTempPath()) ('veliq-video-observer-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
try{
 $observer=Join-Path $root 'observe-video-relay.ps1'
 Copy-Item (Join-Path $PSScriptRoot '..\..\tools\windows\observe-video-relay.ps1') $observer
 $fake=@'
$script:sample=0
function Invoke-ServiceIPC([string]$Method){
 if($Method -ne 'browser.native.status'){throw 'UNEXPECTED_IPC'}
 $script:sample++
 if($script:sample -le 2){return [pscustomobject]@{relay_usage=[pscustomobject]@{video_connections_omitted=0;video_connections=@()}}}
 [pscustomobject]@{relay_usage=[pscustomobject]@{video_connections_omitted=0;video_connections=@([pscustomobject]@{id=1;started='2026-10-23T00:00:00Z';profile_id='chrome';domain='r.googlevideo.com';destination='173.194.151.68:443';received_bytes=([long]$script:sample*500000);sent_bytes=1000;admission_ms=1;relay_open_ms=65;first_byte_ms=150;state='RECEIVING';secret='NEVER_EXPORT_THIS'})}}
}
'@
 [IO.File]::WriteAllText((Join-Path $root 'common.ps1'),$fake,(New-Object Text.UTF8Encoding($true)))
 $csv=Join-Path $root 'samples.csv'
 & $observer -DurationSeconds 10 -OutputFile $csv
 $rows=@(Import-Csv -LiteralPath $csv)
 if($rows.Count -lt 2 -or $rows.Count -gt 12){throw 'BAD_SAMPLE_COUNT'}
 if($rows[0].rate_state -ne 'BASELINE' -or [double]$rows[0].interval_rx_mbps -ne -1){throw 'OLD_BYTES_FORGED_RATE'}
 if(@($rows|Where-Object{$_.rate_state -eq 'MEASURED' -and [double]$_.interval_rx_mbps -gt 0}).Count -lt 1){throw 'REAL_RATE_NOT_RECORDED'}
 if((Get-Content -LiteralPath $csv -Raw) -match 'NEVER_EXPORT_THIS'){throw 'UNEXPECTED_PROPERTY_LEAK'}
 Write-Host 'PASS video observer main loop/CSV/StrictMode/sampling baseline and positive deltas; fake IPC only, no browser/service/VPS access'
}finally{Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue}
