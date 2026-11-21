# Windows simultaneous capture: UDP admission and lifecycle

## Runtime result and confirmed causes

The operator's Happ-OFF Windows rerun on b39a07c reports three healthy relay
sessions, 140 active flows and zero relay-open/session/creation failures. The
previous single-session limit is fixed. This follow-up does not claim a new
simultaneous application PASS. The supplied report correlates 350 dropped
required UDP packets plus 25 adaptive media packets exactly with the 375 worker
saturation drops; the raw ZIP was not attached to this working session.

The code retained one of 64 capture semaphore slots for the entire UDP flow,
including a DNS request's roughly 60-second idle lifetime. This independent
capture ceiling rejected flows before the healthy pool could open them.

## Bounded admission and resource accounting

Capture now admits at most **512 pending/active UDP forwarders**. Ordinary UDP
can occupy at most **384**, leaving **128 reserved places for adaptive media**.
Media may use otherwise free ordinary capacity; total never exceeds 512. This
covers the pool's 376 application leases plus DIRECT-first adaptive flows. It
does not increase pool limits or promise all 512 flows can simultaneously use
relay: TCP and UDP still share actual relay capacity, whose genuine exhaustion
remains an explicit fail-closed error for required traffic.

A separate 64-slot semaphore bounds concurrent setup only and is released as
soon as OpenUDP/OpenAdaptiveUDP returns, rather than on flow close. Admitted
flows waiting for setup share the existing 750ms total budget (not an extended
network timeout); the 512 lifetime admission bound also bounds these waiters.
This prevents a simultaneous UDP burst from filling all 256 pool-creation
waiters before the first session exists. Local setup admission timeout has an
explicit UDP_OPEN_CAPACITY cause. There is no unbounded setup queue. Each lease
owns at most two forwarding goroutines, one idle ticker, one bounded 32-packet
capture queue and its existing transport resources. Capture payload storage is
at most 512 * 32 * 1472 = 24,117,248 bytes (23 MiB), plus approximately 0.75 MiB
queue slots and <=68 bytes of IPv4/UDP headers per template. Templates no longer
retain an arbitrary original UDP payload. Transport receive queues have their
own existing bounds (up to another 23 MiB at this theoretical UDP maximum), and
QUIC sessions/socket buffers are separately bounded by existing transport limits.
Goroutine stacks start small and can grow; these are payload bounds, not an exact
process RSS guarantee. No queue depth, network timeout or health threshold grew.

Admission never evicts an active flow, including media, to make room for DNS.
An actual rejected required/adaptive flow is BLOCK, with
`failure_cause=UDP_WORKER_CAPACITY` and real `worker_saturation_drops` packet
counters. Ordinary fail-open policies retain their existing DIRECT behavior.
The bounded 8192 capture tuple table has a separate `UDP_FLOW_TABLE_CAPACITY`
reason. Reservations are released only after forwarding/receive goroutines close.

## Deterministic UDP idle retirement

DNS (destination UDP/53, never treated as adaptive media) retires after five
seconds without traffic. Other forwarded UDP, including adaptive media, retires
after thirty seconds. A one-second ticker checks activity; both queued outbound
and successful inbound refresh activity. Pending outbound prevents retirement.
These local windows are shorter than the existing server's 60-second idle lease;
Adaptive health/route snapshots are acquired outside the shared capture-map
lock, since an adaptive transition can hold its own mutex during relay open.
This avoids stalling unrelated capture ingress on that open. Lifecycle
correctness no longer depends on a separate 10-second cleanup ticker winning a
race against the server. Ordinary non-forwarded/BLOCK bookkeeping retains its
existing bounded cleanup.

Idle retirement is serialized with capture ingress: check activity/queue, close
the tracked datagram (release the Engine tuple), mark `UDP_IDLE_EXPIRED`, remove
only this capture entry. A later packet creates a fresh flow/evidence ID and opens
an authenticated relay handle normally; nothing is replayed, and it does not stay
BLOCK. Old receive publications cannot attach to the replacement tuple. A pending
packet at the exact boundary prevents retirement. A read ending after local idle
is normal retirement, even if the server close was observed concurrently. A read
or send failure while traffic is active still records `TRANSPORT_FAILED` and
fails closed. Idle retirement does not change Discord probation/cadence thresholds,
endpoint learning, or the one-way decision during a live flow's lifetime.

## TCP packet disposal versus routing failure

`RecordBytes("drop")` counts a packet, not an implicit routing decision. Explicit
`RecordDrop(cause,fatal)` / `RecordFailure` carry the failure semantics:

- Already-closed TCP mappings discard FIN/RST/tail retransmissions with
  `last_drop_cause=TCP_TEARDOWN_TAIL`; counters remain visible and successful
  bidirectional RELAY evidence stays RELAY.
- Policy blocks and admission/open failures are fatal and still set BLOCK /
  `relay_required_blocked` for required policies.
- Unexpected upstream read or write errors in the TCP pipe explicitly record
  `TCP_RELAY_READ_FAILED` / `TCP_RELAY_WRITE_FAILED`, even after successful replies.
  An upstream EOF or application-side reset/close is a normal lifecycle event,
  not invented transport loss. After normal teardown, errors from intentional
  socket closing do not create a second failure.
- Fatal failure evidence is sticky: subsequent packet observations cannot turn
  it back into successful RELAY. A nonfatal tail drop cannot clear a prior failure.

The existing relay maps destination TCP close/reset to stream EOF; without a
server protocol change, EOF cannot establish *why* the remote application ended.
Application acceptance must still verify actual loading/requests, not just bytes.

## Simultaneous proof

The YouTube checker validates the applied chain's exact `tcp-disorder` action
(rather than comparing a configured ID like `p2-youtube-c10ec666-disorder` with
`disorder`). Old literal `disorder` evidence remains compatible if no chain was
exported. DIRECT_PLUS, configured_baseline, real direct_plus_packets > 0 and
zero relayed bytes remain mandatory. A name containing disorder with a different
recorded chain does not pass.

The helper still uses bounded incremental update cursors and cumulative upserts;
it requires complete evidence, zero required DIRECT bytes/packets, zero real
protected/media failures and responding required executables. It now requires
**both capture_queue_drops_delta=0 and worker_saturation_drops_delta=0**, and rejects
missing/reset counters. `failure_cause` is checked independently of final route.
An idle/teardown label cannot override a genuine failure. Operator-observed
video, web/app responsiveness and Discord voice remain separate requirements.

## Incremental Windows update and rerun

First close selected/protected apps and the GUI. Leave Happ OFF. No driver,
enrollment, credentials, config or VPS update is needed. From the checkout:

```powershell
git switch codex/direct-plus-flowseal
git pull --ff-only origin codex/direct-plus-flowseal
git rev-parse HEAD
New-Item -ItemType Directory -Force .\bin\windows-e2e | Out-Null
$env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go build -trimpath -o .\bin\windows-e2e\neexitlag-service.exe .\services\client-service\cmd\service
if ($LASTEXITCODE -ne 0) { throw 'Service build failed' }
```

In an elevated PowerShell in the same checkout, replace only the service binary:

```powershell
$ErrorActionPreference='Stop'
$replacement=(Resolve-Path '.\bin\windows-e2e\neexitlag-service.exe').Path
$svc=Get-CimInstance Win32_Service -Filter "Name='neexitlag'"
if (!$svc) { throw 'Existing installed service required' }
$installed=if ($svc.PathName -match '^"([^"\r\n]+)"') {
    $Matches[1]
} elseif ($svc.PathName -match '^(.+?\.exe)(?:\s|$)') {
    $Matches[1]
} else { throw 'Cannot parse installed service path' }
if ($installed -eq $replacement) { throw 'Build and installed paths must differ' }
$acl=Get-Acl -LiteralPath $installed
$backup=$installed+'.before-udp-lifecycle-'+(Get-Date -Format 'yyyyMMddHHmmss')+'.bak'
Stop-Service neexitlag
(Get-Service neexitlag).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
Copy-Item -LiteralPath $installed -Destination $backup
Copy-Item -LiteralPath $replacement -Destination $installed -Force
Set-Acl -LiteralPath $installed -AclObject $acl
if ((Get-Acl -LiteralPath $installed).Sddl -ne $acl.Sddl) { throw 'ACL mismatch' }
if ((Get-FileHash $installed).Hash -ne (Get-FileHash $replacement).Hash) { throw 'Binary mismatch' }
Start-Service neexitlag
(Get-Service neexitlag).WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
```

Run the unchanged GUI normally, enable optimization and preserve existing AUTO
profiles. Start capture **before** opening all selected applications together:

```powershell
.\tools\windows\capture-simultaneous.ps1 -DurationSeconds 120 -PollMilliseconds 500 -RelayId VPS-01 -ReportDirectory .\bin\simultaneous-final
```

Launch Chrome YouTube (video/seek), Edge ChatGPT, ChatGPT desktop/Codex requests
and Discord together. Keep a voice session active and note responsiveness and
voice ping over time. Exercise unrelated DIRECT control traffic as before.
The helper must show complete evidence, zero queue/worker drops, zero leaks,
zero real protected/media failures and valid YouTube evidence. Retain the whole
timestamped report directory; successful idle UDP closures and TCP tail drops
should now be distinguishable in pages. A transport evidence PASS alone is not
final simultaneous application PASS. Do not merge PR #8 before that real rerun.

Rollback: close selected apps, stop service, restore the saved binary and its ACL,
start service. Never delete ProgramData or replace credentials/config for this update.

## Changed files and regression scope

- `platform/windows/capture_windows.go`: bounded admission, receiver-aware idle
  lifetime, serialized retirement/reopen, explicit failures, header-only templates.
- `platform/windows/udp_lifecycle.go`: admission/reserve and exact idle boundary.
- `platform/windows/packet.go`: bounded reply template construction.
- `platform/windows/evidence.go`, `failure_evidence.go`: cause/lifecycle fields,
  explicit fatal versus nonfatal drops, sticky real failures.
- `platform/windows/local_strategy.go`, `local_tcp_buffer.go`: preserve existing
  local-strategy fail-block evidence using the explicit fatal-drop API; routing
  and transforms are unchanged.
- `platform/windows/tcp_capture_windows.go`, `tcp_state.go`, `tcp_lifecycle.go`:
  tail disposal and upstream-copy failure classification.
- `platform/windows/lifecycle_test.go`: 512-slot bound/reserve, repeated DNS churn,
  queued work at exact idle boundary, fatal/teardown evidence, header retention.
- `platform/windows/udp_forward_windows_test.go`: native Windows forward loops,
  160 concurrent relayed DNS + eight actual native adaptive UDP echo flows,
  DNS retirement without media starvation, same-tuple reopen, active session
  loss fail-closed, actual TCP pipe request/reply/close followed by seven tail drops.
- `tools/windows/simultaneous-checks.ps1`, `capture-simultaneous.ps1`:
  applied-chain validation, explicit failures, queue and worker zero-drop gates.
- `tests/windows-tools/simultaneous-checks.ps1`: PS5.1/PS7 fixtures, configured
  strategy ID, retained strict conditions, fatal versus idle/tail and 702 complete
  incrementally accumulated flow rows.
- `.github/workflows/verify.yml`: native Windows lifecycle race step in addition
  to existing Windows build/tests, signed-driver lifecycle and PS5.1/PS7 checks.
- `tools/windows/build-e2e.ps1`: bundle this document with the tools.

The Windows forward-loop regression uses a controlled relay double and local UDP
echo solely as deterministic tests; it is not Internet/application acceptance.
