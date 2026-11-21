# TCP burst admission and complete revocation publication

TCP interception keeps 128 concurrent setup workers. An additional bounded wait
allows up to 384 setup operations in total, including active work. The queue
never blocks the WinDivert packet receiver or TCP accept loop. FIFO semaphore
admission has a five-second wait budget, separate from the existing upstream
OPEN timeout. Waiting SYNs remain intercepted; protected traffic is never
reinjected DIRECT. Hard pending exhaustion and admission expiry fail closed with
`TCP_ADMISSION_LIMIT` / `TCP_ADMISSION_TIMEOUT`. These are actual bounded resource
failures, rather than a failure whenever the 128 workers are temporarily busy.

`tcp_admission.state` / `wait_ms` in flow evidence distinguish queue wait from
`relay_open` latency. Hot-attach/profile transitions and shutdown cancel queued
setup. Active application pipes hold no setup permits, including while their
first buffered ClientHello write is blocked by the destination. TCP state remains
bounded at 8192 entries; delegated DIRECT+ sockets now share that state bound
instead of a separate lifetime limit of 128 (the existing evidence alias bound
of 1024 still applies). No routing or strategy decisions change.

Relay limits remain eight sessions of 48 reservations, with one probe reservation
per session: **376 application flows maximum per relay**, shared by TCP and UDP.
The admission queue does not create relay capacity. A relay at its genuine hard
capacity may still fail protected opens closed; established flows are not evicted
or replayed. OPEN timeouts, relay/server limits and lease renewal are unchanged.

Revocation publication queries **only revoked IDs, without a SQL LIMIT**, inside
the serialized configuration publication transaction. It does not use the bounded
admin device listing. A single statement reads a complete committed snapshot;
stream/scan/DB/signing/commit errors abort publication and return no document.
The last committed config stays intact. A revoke committed before the snapshot
is included; a concurrent later revoke is included by its subsequent serialized
publication. No partial or truncated list is signed.

Signed configuration, its HTTP download/serving/heartbeat refresh and cache have
a dedicated **1 MiB** bound. Tickets/proofs/other documents retain their 64 KiB
limit. Oversized revocation sets or whole configs explicitly fail publication;
there is no clipping. A partial index supports the revoked-ID query. Upgrade the
control plane **and every config consumer (client/relay)** before publishing
configs larger than 64 KiB: older binaries cannot consume the larger document.
This change does not deploy anything to the VPS.

## Automated validation

```sh
go test -race ./platform/windows -run TestTCPAdmission
go test -race ./tests/integration -run TestPoolTCPBurst
NEEXITLAG_TEST_DATABASE_URL='postgres://TEST_DATABASE' \
  go test -race -v ./services/control-plane -run 'TestRevoked|TestPostgresRevocation'
```

Native Windows (normal and race jobs in Verify):

```powershell
go test -race -timeout 90s -v ./platform/windows -run 'TestTCPNativeAdmissionBurst|TestTCPNativeQueuedSetupCancellation'
```

Native tests deliberately fill all 128 setup permits, then admit 160/256 protected
connections on both SYN and deferred-ClientHello paths. They use real Windows TCP
sockets, an authenticated local QUIC relay and fresh one-shot tickets, retain the
same sockets across repeated bidirectional exchanges, and inspect complete flow
evidence for no DIRECT bytes, no BLOCK and correct relay counters. One established
flow exchanges data while setup is saturated. Only privileged driver reinjection
is substituted; these tests do not claim public-Internet Windows acceptance.
Integration independently retains 160/256/320 authenticated relay TCP sockets,
using a 128-connection setup window (pool waiters remain 256). Setup includes
first real echo I/O so the target has actually accepted the connection before
its test slot is reused. This avoids overflowing the Windows loopback target's
implementation-defined SOMAXCONN backlog with completed-but-not-yet-accepted
connections. A repeat listen call cannot adjust that Winsock backlog; no
ineffective reconfiguration or production listener/packet-queue change is used.
All sockets remain held for three further rounds; no failure is retried/ignored.
Windows CI repeats these bursts three times both normally and with the race detector.
PostgreSQL tests cover 1500/5000 IDs, revoke #5000, HTTP/cache/verifier updates,
large-config heartbeat refresh, concurrent publications, and real query/commit/
size failures. Existing Windows driver lifecycle checks remain enabled. No long
manual lease or Discord test is required.
