$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Isolated CI preparation only. Queries the real OS, writes no configuration and
# supplies no snapshot/fingerprint to the test. Production still queries afresh
# with its unchanged eight-second budget and fails if that real query fails.
$job=Start-Job -ScriptBlock {
 $ErrorActionPreference='Stop'
 $ProgressPreference='SilentlyContinue'
 Get-NetAdapter | Out-Null
 Get-NetIPAddress | Out-Null
 Get-NetConnectionProfile | Out-Null
 Get-NetRoute -PolicyStore ActiveStore | Out-Null
 Get-DnsClientServerAddress | Out-Null
 if(Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue){Get-DnsClientDohServerAddress | Out-Null}
 netsh winhttp show proxy | Out-Null
 if($LASTEXITCODE){throw 'WinHTTP read-only query failed'}
}
try {
 if(!(Wait-Job -Job $job -Timeout 45)){throw 'Read-only network provider warmup timed out; native acceptance cannot start'}
 Receive-Job -Job $job -ErrorAction Stop | Out-Null
 if($job.State -ne 'Completed'){throw 'Read-only network provider warmup failed'}
 Write-Host 'PASS: real Windows network providers initialized; acceptance must obtain its own fresh snapshot'
} finally {
 if($job.State -eq 'Running'){Stop-Job -Job $job}
 Remove-Job -Job $job -Force
}
