$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../tools/windows/exitlag-observation.ps1')
$p=@([pscustomobject]@{Pid=7;Created='first';Name='ExitLag'})
$tcp=@([pscustomobject]@{OwningProcess=7;LocalAddress='127.0.0.1';LocalPort=1000;RemoteAddress='192.0.2.1';RemotePort=443;State='Established'},[pscustomobject]@{OwningProcess=8;LocalAddress='127.0.0.1';LocalPort=1001;RemoteAddress='192.0.2.2';RemotePort=443;State='Established'})
$udp=@([pscustomobject]@{OwningProcess=7;LocalAddress='0.0.0.0';LocalPort=2000})
$rows=@(ConvertTo-ExitLagEndpoints $p $tcp $udp)
if($rows.Count -ne 2 -or $rows[0].Pid -ne 7){throw 'foreign process included'}
if($rows[1].RemoteAddress -ne 'NOT_EXPOSED_BY_OS' -or $null -ne $rows[0].RttMs){throw 'fabricated remote/RTT'}
$p[0].Created='second';$next=@(ConvertTo-ExitLagEndpoints $p $tcp $udp)
if($rows[0].Key -eq $next[0].Key){throw 'PID reuse merged identities'}
$bounded=@(ConvertTo-ExitLagEndpoints $p $tcp $udp 1);if($bounded.Count -ne 1){throw 'unbounded output'}
Write-Host 'PASS passive endpoint fixtures; no processes, network or tracing accessed'
