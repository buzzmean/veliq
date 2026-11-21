Set-StrictMode -Version Latest
function Assert-DirectPlusEvidence($Report,$Evidence,[int]$PIDValue,[string]$Exe,[string]$Route,[string]$VpsIP,[string]$Destination,[int]$Count) {
 if($Report.pid -ne $PIDValue -or $Report.exe -ine $Exe -or $Report.creation_time -eq 0){throw 'PID/exe/creation association failed'}
 $attempts=@($Report.attempts);if($attempts.Count -ne $Count -or @($attempts|Where-Object{!$_.success -or $_.destination -ne $Destination}).Count){throw 'Connection/HTTP/TLS failures or wrong destination; inspect attempts'}
 $sources=@($attempts|ForEach-Object{$_.response_source}|Sort-Object -Unique)
 if($Route -eq 'RELAY'){if($sources.Count -ne 1 -or $sources[0] -ne $VpsIP){throw 'RELAY response source mismatch'}}else{if($sources.Count -ne 1 -or $sources[0] -eq $VpsIP){throw 'Native egress response source mismatch; VPN may be active'}}
 if($Evidence.truncated){throw 'Capture truncated; cannot establish route absence'}
 $flows=@($Evidence.flows|Where-Object{$_.pid -eq $PIDValue -and $_.creation_time -eq $Report.creation_time -and $_.exe -ieq $Exe -and $_.destination -eq $Destination -and $_.protocol -eq 'tcp' -and $_.ip_version -eq 'IPv4'})
 if($flows.Count -ne $Count){throw 'Expected exactly one attributed target flow per independent connection'}
 $captured=0L;$relay=0L;$direct=0L;$plus=0L;$replies=0L;$bytes=0L;$capturedBytes=0L;$directBytes=0L;$relayBytes=0L;$replyBytes=0L
 foreach($f in $flows){$captured+=$f.counters.captured_packets;$capturedBytes+=$f.counters.captured_bytes;$directBytes+=$f.counters.direct_bytes;$relayBytes+=$f.counters.relayed_bytes;$replyBytes+=$f.counters.relay_reply_bytes;$relay+=$f.counters.relayed_packets;$direct+=$f.counters.direct_packets;$plus+=$f.counters.direct_plus_packets;$replies+=$f.counters.relay_reply_packets;$bytes+=$f.counters.direct_plus_bytes
 if($Route -eq 'RELAY' -and ($f.selected_route -ne 'RELAY' -or $f.relay_id -ne 'VPS-01')){throw 'Relay route mismatch'}
 if($Route -eq 'DIRECT_PLUS' -and $f.selected_route -ne 'DIRECT_PLUS'){throw 'DIRECT+ transform did not apply to every connection'}
 if($Route -eq 'DIRECT_PLUS' -and ($f.counters.direct_plus_packets -le 0 -or $f.counters.direct_plus_bytes -le 0)){throw 'DIRECT+ modification counters missing for a connection'}
 if($Route -eq 'DIRECT' -and $f.selected_route -ne 'DIRECT'){throw 'DIRECT route mismatch'} }
 if($captured -le 0 -or $capturedBytes -le 0){throw 'No captured packets'}
 if($Route -eq 'DIRECT_PLUS' -and ($plus -le 0 -or $bytes -le 0 -or $relay -ne 0)){throw 'No real DIRECT+ modification/evidence or relay leak'}
 if($Route -eq 'DIRECT' -and ($direct -le 0 -or $directBytes -le 0 -or $relay -ne 0 -or $plus -ne 0)){throw 'DIRECT counter mismatch'}
 if($Route -eq 'RELAY' -and ($relay -le 0 -or $relayBytes -le 0 -or $replyBytes -le 0 -or $replies -le 0 -or $direct -ne 0 -or $plus -ne 0)){throw 'RELAY counter mismatch'}
 return $sources[0]
}
function Get-StrategyMeasurement($Report,[bool]$Available) {
 $a=@($Report.attempts);$times=@($a|Where-Object{$_.success}|ForEach-Object{[double]$_.response_rtt_ms}|Sort-Object);$success=$times.Count
 $rtt=0.0;$jitter=0.0;if($success){$rtt=($times|Measure-Object -Average).Average};$previous=$null;$deltas=@();foreach($v in $a|Where-Object{$_.success}){if($null -ne $previous){$deltas+=[Math]::Abs([double]$v.response_rtt_ms-$previous)};$previous=[double]$v.response_rtt_ms};if($deltas.Count){$jitter=($deltas|Measure-Object -Average).Average}
 $loss=1.0;if($a.Count){$loss=1.0-($success/[double]$a.Count)}
 return @{route_id='controlled-target';rtt=[long]($rtt*1e6);jitter=[long]($jitter*1e6);loss=$loss;failure_rate=$loss;load=0;stability=(1-$loss);available=$Available;samples=$success;observed_at=[DateTimeOffset]::UtcNow.ToString('o')}
}

function Assert-LocalEffectiveProfile($Snapshot,[string]$Exe,[string]$ID,[string]$Mode,[string]$StrategyID='') {
 $p=Get-AcceptanceProfile $Snapshot $Exe
 if($null -eq $p -or $p.id -ne $ID -or $p.mode -ne $Mode){throw "Effective profile is not the requested $Mode test profile for $Exe; another custom profile may take precedence"}
 if($Mode -eq 'MANUAL' -and (Get-AcceptanceValue $p 'relay_id' '') -ne 'VPS-01'){throw 'Effective relay profile is not VPS-01'}
 if($Mode -eq 'DIRECT_PLUS' -and (Get-AcceptanceValue $p 'local_strategy_id' '') -ne $StrategyID){throw 'Effective local strategy differs from the test profile'}
}
