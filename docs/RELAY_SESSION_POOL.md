# Bounded relay sessions and simultaneous Windows retest

## Confirmed bottleneck and limits of the diagnosis

At fd06ea3 the service published one transport.Client per relay. Every TCP and UDP
flow used a bidirectional QUIC stream on that one connection. The unchanged relay
advertises at most 64 streams and enforces MaxFlows=64 per session. OpenStreamSync
waited for credit, tying up new-flow opens until their deadlines. The 64-stream
ceiling is reproduced by the integration regression. The reported 62 visible
protected app flows exclude probes, pending opens and diagnostic flows; it is not
a complete session occupancy count. A healthy ~57 ms probe route does not prove
capacity to open more streams. Timeouts have not been increased.

This confirms an architectural admission bottleneck consistent with the Windows
startup failure. It does not prove every one of the 103 reported errors had that
same cause. The actual simultaneous-final ZIP is not present in this workspace;
its supplied summary cannot establish packet-by-packet causality for all 115/3737
capture queue drops. New per-flow open/queue evidence and pool samples allow the
rerun to distinguish credit/admission stalls, ticket/session errors, relay rejection
and post-open queue pressure. Zero queue drops is a strict retest target, not an
Internet result inferred from CI.

## Architecture and compatibility

A stable routing provider now owns a pool for each configured relay ID/address:

* At most **8 live/creating sessions** per pool. Creation is single-flight, only
  when no eligible existing session has capacity. At most 256 callers can await
  pool creation/transient stream credit. Session creation keeps the existing
  three-second budget; individual routing/capture deadlines remain unchanged.
* At most **48 reserved/open flows per session**, counting pending opens. One slot
  per session is reserved for real measurement/readiness probes. Normal app
  admission is 47/session, at most **376 app flows** and 384 total flows across
  eight sessions. This retains at least 16 physical stream slots of headroom
  below the existing server limit for auth/credit/close processing. Session-local
  application saturation never makes health probes wait behind application flows.
* New flows choose the least occupied eligible session. QUIC credit admission uses
  nonblocking OpenStream; credit exhaustion is a typed capacity event. That
  session is briefly excluded (100 ms) while another/new session can accept work.
  Hard capacity fails clearly and remains fail-closed for RELAY_REQUIRED.
* Each new session calls the existing control-plane Ticket endpoint with a freshly
  generated signed device proof/nonce, then DialWithTicket with the resulting
  fresh one-shot ticket. An uncertain/failed authentication attempt is never
  retried with the old ticket. mTLS, certificate verification, ALPN, no 0-RTT,
  ticket audience/device binding and replay verification are unchanged.
* Sessions all dial the same configured authenticated VPS endpoint, with the same
  existing relay egress implementation. No alternate VPS, local proxy, default
  route, credentials or server egress settings are introduced. Real observed
  source IP still belongs in the operator's external proof.
* Existing handles remain bound to their session. No established TCP stream or
  sent UDP datagram is migrated/replayed. A setup on a dead session can select a
  peer before an application handle/bytes have been returned. A live-session OPEN
  rejection is not retried. Rejected target/policy opens remain failures.
* A failed session is removed independently; healthy peers and their flows stay
  open. Only losing all sessions can report aggregate transport failure. Capacity
  errors and a probe's demonstrably dead session with healthy peers do not become
  whole-VPS quality observations. Genuine unanswered probes on a live session
  keep the existing scoring/loss behavior; numerical scoring and policies are
  unchanged. Saturation itself does not force a route-unhealthy signal.
* Legacy `/2` sessions drain new admissions after 25 minutes and retain the
  server's 30-minute hard authorization expiry. Renewal-capable `/3` sessions
  renew authorization independently of admission and do not drain solely due to
  age. Existing handles stay attached; no application data migrates or replays.
  Idle surplus sessions still close after two minutes. See
  [authenticated lease renewal](RELAY_LEASE_RENEWAL.md) for control capacity,
  replay-safe receipts, hard expiry, and accelerated Windows acceptance.

**No VPS/control-plane deployment is required for this change.** The repository's
current relay defaults are MaxSessions=128 globally and MaxFlows=64 per session;
there is no one-session-per-device restriction. The auth API issues a new ticket
for each valid new proof, uses a 100-request burst/20 per second limiter, and the
relay accepts each fresh ticket once. Four sessions for the 160-flow stress test
are within these existing bounds. Tests use the unchanged server and real ticket
verification; the PostgreSQL integration also exercises real CP proof consumption
and pool expansion. The live VPS was not accessed or modified. Fleet-wide session
capacity is still shared: eight sessions is a client hard maximum, not a promise
that a globally exhausted 128-session server will accept every client.

## Diagnostics and queue attribution

```powershell
. .\tools\windows\common.ps1
Invoke-ServiceIPC 'relay.pool.diagnostics' @{relay_id='VPS-01'} | ConvertTo-Json -Depth 24
```

Includes active/healthy/creating sessions, live/reserved flows per session,
creation reason, draining status, actual/available and hard aggregate capacities,
waiters, saturation and stream-credit events, session/creation failures, cumulative
open count/failure reasons/latency sum/max, and the last 32 open events with
session ID, protocol, destination, latency and sanitized failure reason. Packet
local-drop diagnostics aggregate live and retired session counters without resets.
No ticket, private key, payload or credential is logged.

Flow snapshots additionally contain `relay_open.duration_ms/failure_reason` and
`udp_queue.capacity/high_water/drops_during_open/drops_after_open/max_wait_ms`.
Queue capacity remains **32**, UDP workers remain **64**; neither was raised.
High-water is maximum observed depth. `drops_during_open` means initial UDP setup;
`drops_after_open` also includes later send pressure/adaptive fallback waits.
Residence time is measured on dequeue, including failed-open draining. Compare
these with the same endpoint's pool open events and global counter deltas. TCP
opens do not run under the UDP queue lock. Removing the stream-credit wait removes
one concrete source of stalled queue consumers; hardware/driver/other sources
must still be checked if the real rerun reports drops.

## Bounded complete incremental capture

Legacy capture.marker/capture.diagnostics remain compatible and conservative.
New capture.changes.marker and capture.changes expose **update** cursors. Advancing
only a flow-birth marker would miss later direct bytes or failure on an old flow.
Pages contain at most 32 cumulative records / 58 KiB. Consumers replace snapshots
by ledger_id + flow_id, never sum repeated cumulative counters. Tuple reuse gets
new flow IDs; final prior records remain available. Concurrent changes move to a
later cursor; they cannot fall behind it. JSON serialization happens outside the
capture ledger lock.

The current diagnostic cache remains 1024 rows, with a separate bounded 1024-row
retired history for exporting final/reclaimed records. A late packet restores
retained cumulative DIRECT+ metadata instead of treating an ACK as a new route.
A cursor that misses overwritten history reports evidence_lost; service restart
or a future/foreign cursor is rejected. Such a run cannot claim no leaks or PASS.
Legacy truncation/loss checks have not been weakened.

The helper below drains every page, writes immutable page files and bounded pool
samples, retains at most 8192 distinct flow snapshots, and limits capture to
600 seconds / 4096 pages (defaults 120 seconds / 2048 pages). It rejects lag,
restart, missing target evidence, any required-flow DIRECT packet/byte, protected
BLOCK/open failures, missing bidirectional relay bytes per required executable,
invalid YouTube TCP DIRECT+ evidence, failed adaptive media transports and
nonzero capture_queue_drops delta. Missing protected counters cannot default to
zero. Capture draining has a 15-second final grace beyond the selected duration,
then fails incomplete; per-IPC deadlines stay bounded. UDP/QUIC records remain
in the page archive and are not falsely required to have TCP transform counters. A successful
transport evidence gate explicitly requires separate real application observations;
it is not a browser load/video/voice success claim.

## Exact Windows build and service update

Pause/close protected applications and exit the GUI before stopping the service.
Use the existing Windows checkout with Go 1.25:

```powershell
git switch codex/direct-plus-flowseal
git pull --ff-only origin codex/direct-plus-flowseal
git rev-parse HEAD
go build -trimpath -o .\bin\windows-e2e\neexitlag-service.exe .\services\client-service\cmd\service
if($LASTEXITCODE -ne 0){throw 'Service build failed'}
```

The GUI executable has no changes in this follow-up. To rebuild the full GUI/tools
bundle optionally run `.\tools\windows\build-desktop.ps1 -Output .\bin\release`
and `.\tools\windows\build-e2e.ps1`. Matching successful Verify artifacts also
provide windows-real-e2e-tools and VELIQ-win-x64; the service bundle includes
this instruction. Never combine binaries/scripts from different HEADs for proof.

From elevated PowerShell in the checkout, replace the existing SCM binary only:

```powershell
$ErrorActionPreference='Stop'
$replacement=(Resolve-Path '.\bin\windows-e2e\neexitlag-service.exe').Path
$svc=Get-CimInstance Win32_Service -Filter "Name='neexitlag'"
if(!$svc){throw 'Existing service required'}
$installed=if($svc.PathName -match '^"([^"\r\n]+)"'){$Matches[1]}elseif($svc.PathName -match '^(.+?\.exe)(?:\s|$)'){$Matches[1]}else{throw 'Cannot parse service path'}
if($installed -eq $replacement){throw 'Build and installed paths must differ'}
$acl=Get-Acl -LiteralPath $installed
$backup=$installed+'.before-pool-'+(Get-Date -Format 'yyyyMMddHHmmss')+'.bak'
Stop-Service neexitlag
(Get-Service neexitlag).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
Copy-Item -LiteralPath $installed -Destination $backup
Copy-Item -LiteralPath $replacement -Destination $installed -Force
Set-Acl -LiteralPath $installed -AclObject $acl
if((Get-Acl -LiteralPath $installed).Sddl -ne $acl.Sddl){throw 'ACL mismatch'}
if((Get-FileHash $installed).Hash -ne (Get-FileHash $replacement).Hash){throw 'Binary mismatch'}
Start-Service neexitlag
(Get-Service neexitlag).WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
```

No uninstall/reinstall, enrollment, WinDivert driver or credentials/config change.
Rollback: stop service, restore `$backup` to `$installed`, restore `$acl`, restart.
The existing machine fail-open behavior during service stop/crash is unchanged;
resume protected apps only after the service is running and optimizing.

## Focused simultaneous retest, Happ completely OFF

Start the existing GUI normally and enable optimization. Preserve Chrome's working
configured_baseline/disorder AUTO, Edge/OpenAI RELAY_REQUIRED and Discord AUTO.
Start capture **before** opening fresh application connections:

```powershell
.\tools\windows\capture-simultaneous.ps1 -DurationSeconds 120 -PollMilliseconds 500 -RelayId VPS-01 -ReportDirectory .\bin\simultaneous-final
```

While it runs, start Chrome YouTube video/seek, Edge ChatGPT, ChatGPT desktop/Codex
workspace and Discord messages+voice together. Record actual load times, streaming,
Codex requests, Discord connection errors, audible continuity and ping over time.
Keep an unrelated DIRECT control active. No VPN, synthetic impairment or alternate
strategies. Do not reset/retry away failed initial attempts in the report.

Expected transport evidence: multiple healthy pool sessions as demand grows,
per-session reservations <=48, zero normal-capacity open failures, zero required
DIRECT bytes/packets, no protected BLOCK, positive bidirectional relay bytes for
msedge.exe/ChatGPT.exe/codex.exe/Discord.exe, YouTube actual disorder transforms
with configured_baseline and zero relay bytes, complete cursor pages and zero
capture_queue_drops delta. Session saturation counters can increase during normal
scale-up; saturation alone is not failure. After pool fallback, Discord's actual
voice result still requires observation. Do not call simultaneous PASS from CI.

Keep all page/pool/quality/status files and proof.json/FAIL.json. Zip the run folder
only, not ProgramData/config/credentials. A missing app, truncated/lost evidence,
positive leak, queue drop, blocked protected flow or slow/broken real application
is not a simultaneous PASS. No merge of PR #8 is performed by this workflow.
