# Authenticated session lease renewal

Production authorization remains 30 minutes. The negotiated `neexitlag/3` protocol
uses bounded authenticated QUIC DATAGRAM request/ACK control on the original
connection. It bypasses application stream counts and connection receive credit,
with a separate 16-frame inbox and one-message reassembly (at most nine 1024-byte
fragments). Lost fragments/ACKs retry using the retained receipt. One bounded
sender and an independent hard-deadline watchdog prevent blocked enqueue or CP
requests from extending authorization. The relay reserves handshake stream headroom
without increasing its 64 application-flow limit. Client pools keep their existing 48-flow reservations.
The application TCP streams, UDP flow IDs, destination sockets and QUIC connection
are not replaced at renewal. The service requests a fresh ticket via the existing
signed device proof. Both sides still support `/2`; legacy sessions cannot renew
and retain the old 25-minute admission rotation and 30-minute hard expiry.
Upgrading only Windows cannot add renewal support to an old VPS relay.
**The relay binary must eventually be updated too; this change does not deploy it.**

Renewal starts at approximately 18.5--20 minutes (two thirds of the lease minus
bounded 0--5% jitter). Each attempt has at most a 3-second budget, clipped to the
remaining local authorization. Failed attempts retry after at most 10 seconds.
The server verifies same device ID, mTLS key fingerprint and relay audience before
consuming the one-shot ticket and atomically extending the lease. Expired sessions
cannot be resurrected. Device revocation remains enforced by ticket validation,
OPEN authorization checks and the live expiry/revocation sweeper.

A monotonic renewal sequence and SHA-256 digest retain **one** receipt per session.
An identical sequence/ticket can retrieve that receipt on the same authenticated
QUIC connection, without consuming the ticket again or extending the deadline.
That is ACK recovery, not another ticket acceptance. Reusing the ticket for a new
sequence or another session is rejected. Old sequences and changed payloads are
rejected. Partial/lost/reordered datagrams cannot desynchronize a stream.
CP outage permits existing traffic only until its actual authorization deadline;
it never grants an indefinite extension. The client uses conservative monotonic
local deadlines; the relay is authoritative. Renewal-capable sessions no longer
drain due to the old authorization-rotation timer. Other idle/resource retirement
is unchanged. Destination flow idle timeout remains 60 seconds and is separate
from authorization; deterministic acceptance keeps both flows active.

## Diagnostics and failures

`status` relay-pool sessions include `lease` with supported/state, server/local
deadlines, attempts, renewals, failures, receipt retries and last error. The pool
retains bounded recent session-end events. Authorization expiry and revocation
have dedicated QUIC close codes, TCP evidence causes and counters, and are not
reported as generic session transport failures. Relay Prometheus metrics include
renewals/rejections, expiries, revocations and OPEN rejections by reason.

OPEN evidence distinguishes stream capacity, caller cancellation, ACK timeout,
ACK EOF, stream reset, destination denial, flow capacity, upstream dial timeout,
connection refusal, other upstream dial failure and authorization/session death.
Recent open events retain a bounded underlying error detail. A healthy session
means the QUIC connection is alive, not that every destination can be opened.
The historical eight generic failures cannot be classified retrospectively from
that label; these diagnostics distinguish their causes on a new run.

Protected UDP retains its route after a real mapping/session loss. A bounded,
single-opener retry recreates only that flow's relay mapping using the provider's
fresh authenticated session selection. The failed datagram is **not replayed**;
future outbound packets retry. `UDP_RELAY_RECOVERING` is explicit packet-loss
evidence rather than BLOCK forever or fictitious successful relay bytes. No DIRECT
fallback is permitted. Adaptive media does not restart DIRECT probation or alter
its endpoint-cache learning when a relayed mapping is recovered. Replacement
mapping recovery after actual failure is separate from seamless scheduled renewal.

## Accelerated acceptance (no 65-minute Discord run)

Linux/Windows CI runs the real mTLS/QUIC integration tests automatically. A short
lease is configured only through `relay.Config.Acceptance` by isolated test
fixtures. The production relay CLI/environment has **no short-lease option**.
The dedicated acceptance test allows an explicit 60--90 second override; other
regressions use short in-process fixtures for failure injection.

On Windows, from the repository root:

```powershell
.\tools\windows\build-e2e.ps1
.\tools\windows\acceptance-lease-renewal.ps1 -LeaseSeconds 60
```

Or download the exact-commit Windows E2E artifact and invoke its bundled script:

```powershell
.\tools\windows\acceptance-lease-renewal.ps1 -BinaryDirectory . -LeaseSeconds 60
```

The helper has a worst-case timeout below ten minutes. It checks native Windows
QUIC/TCP/UDP continuity with unchanged stream/flow IDs, exactly one established
relay TCP destination connection and the original two live relay mappings across
two renewals, advancing deadlines/counters, then authorization/recovery and native
capture regressions. stdout/stderr and summary JSON are retained under
`bin/lease-acceptance`. It does not stop the installed service, change profiles,
read production credentials or access the VPS. This is an isolated Windows runtime
acceptance, not a claim of WinDivert/Internet or Discord latency acceptance.

For a Windows service binary update, preserve installed credentials and state:

```powershell
git switch codex/direct-plus-flowseal
git pull --ff-only origin codex/direct-plus-flowseal
.\tools\windows\build-e2e.ps1
Stop-Service neexitlag
(Get-Service neexitlag).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
Copy-Item .\bin\windows-e2e\neexitlag-service.exe "$env:ProgramData\neexitlag\neexitlag-service.exe" -Force
Start-Service neexitlag
(Get-Service neexitlag).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
.\tools\windows\acceptance-lease-renewal.ps1 -LeaseSeconds 60
```

Run elevated only for the service update; the isolated acceptance needs no driver
installation/elevation. The deployed VPS continues legacy behavior until its relay
binary is updated in a separately authorized deployment. No credentials need rotation.
