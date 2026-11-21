# HOT ATTACH — applications may already be running

Normal usage: leave Chrome, Edge, ChatGPT/Codex and Discord running, open VELIQ
and enable Optimize (or start the already-installed service with automatic
optimization enabled). No process restart, manual reconnect, elevation of the GUI
or user PowerShell is part of this product flow. Changing an application profile
also reconciles its existing connections automatically. Disabling and re-enabling
Optimize repeats the attach procedure without restarting application processes.

This change implements network reconnection, not a claim that every application
retries every interrupted request. The real Windows/ISP browser and Discord
acceptance below remains a release gate. CI cannot establish YouTube playback,
ChatGPT authentication/session recovery or Discord voice latency/messages.

## Protection boundary and activation

The service publishes enabled classification **before** capture handles start.
Previously it started capture while Classify still returned DIRECT, and a
midstream packet was explicitly pinned to DIRECT. Both behaviors prevented
attaching to already-running applications.

Before processing captured TCP, the backend records a bounded snapshot of
established native IPv4 TCP tuples, PID and native creation time. New SYN_SENT
rows are excluded. A reconciliation generation uses this fixed target set; it
does not repeatedly enumerate every new connection as a reconnect target.
Already captured fresh connections with the current policy revision are retained.
Late old native traffic absent from the initial snapshot is quarantined when
observed, with a reset derived from that exact packet's sequence space.

Protection starts at the installed capture boundary. Bytes sent before capture
installation or while Optimize/service is OFF cannot be retroactively protected.
Existing WinDivert service stop/crash remains machine fail-open. HOT ATTACH is
not a crash-persistent firewall or a promise that pre-enablement DIRECT traffic
never existed. Do not interpret the intentional OFF interval in the developer
re-enable test as a protected interval.

While attached, attributable old selected TCP packets are not reinjected DIRECT
under a required policy. Inbound original-path traffic is also fenced. New SYNs
use the current normal classifier, authenticated relay or native DIRECT+ engine;
old stream bytes are never migrated, re-opened or replayed on a different egress.
A genuine fresh required relay failure stays fail-closed under the existing rules.

## Targeted reconnect

For old established native IPv4 TCP, the privileged service uses
`GetExtendedTcpTable` plus exact-tuple `SetTcpEntry(DELETE_TCB)`. It revalidates the
current owner and native process creation time immediately before deletion.
Windows supplies no PID argument to SetTcpEntry; cached tuples alone are never
authority. Stale birth, changed owner, missing rows and the service's own PID are
rejected/skipped. Listen/TIME_WAIT entries and loopback destinations are excluded.
No process is terminated, suspended, injected into or read for application memory.
No adapter, machine route, DNS cache, system proxy or unrelated application is reset.

Observed old selected TCP also gets a payload-free inbound RST derived from its
ACK/sequence space. RSTs are never answered with another RST. This permits
convergence when native table reconciliation is unavailable or an old connection
was created during installation; it does not authorize forwarding its data DIRECT.

There is one coalescing reconciliation worker, an 8192-row native table/target
bound, and an eight-second reconciliation window with 250ms rechecks. Capacity,
owner-table/API errors and timeout produce HOT_ATTACH_INCOMPLETE, not success.
Application retry/backoff time is independent of that network reconciliation
window. A fixed target snapshot plus fresh-policy entry validation prevents the
worker from chasing new connections in a reset loop. PID/tuple reuse is checked
again before an API action; real Windows stress remains part of release signoff.

## Profile activation and UDP

Profile/settings/local strategy/signed profile/AUTO commit updates use the optional
backward-compatible backend Reconfigure contract. A short read/write policy barrier installs a per-application transition fence,
then releases the global packet gate while affected handles abort and canceled
setup drains. Unrelated ingress continues even if a selected socket close waits
for I/O. A second short publication barrier advances the private policy-cache
epoch and removes that fence. Native/DIRECT UDP does not retain stale forwarding
permission; canceled relay opens keep a tuple tombstone until Engine cleanup. Existing affected proxy
sockets close **before** the new policy is published (abortive native close drops
pending old DIRECT sends); old native mappings are
quarantined. New connections then classify with a content revision of that
application's profile/settings/matching local strategies. Scores, route health,
sessions and unrelated applications' strategy revisions are not migration triggers.
Idempotent profile writes do not reconnect an application. Delegated native
DIRECT+ close releases its alias under a separate mutex so retirement cannot
re-enter the TCP state lock or attribute late old packets to a new policy epoch.

Retirement is scoped to selected application IDs; unrelated DIRECT entries and
sockets remain untouched. Intentional close errors do not become TRANSPORT_FAILED.
Buffered old ClientHello/datagrams are discarded, not flushed on an obsolete
DIRECT policy or replayed through a new route. Those packet disposals remain
observable as HOT_ATTACH_UDP_RETIRED. Active UDP admission/queues retain the prior
512/384/128 limits, 64 setup limit, 32-packet queue and idle windows.

Existing native UDP is classified on the next outgoing datagram; it needs no SYN.
Cached DIRECT/unselected UDP entries invalidate on the publication epoch or on
newly available ownership, so adding a profile to an already-running UDP app
cannot retain its old DIRECT cache.
On profile changes an affected captured UDP handle is closed, removed from the
routing Engine before a replacement can open, and the next datagram gets the
current authenticated route/adaptive decision. Protocols with NAT rebinding/path
validation may recover; encrypted UDP/QUIC/voice cannot be transparently replayed
or guaranteed recoverable by inventing protocol state. Discord probation/cadence
thresholds and cache policy are unchanged. Real voice/messages recovery must pass.

## IPv6 and attribution limits

Transparent IPv6 relay remains unsupported. Selected protected/DIRECT+ IPv6,
including pre-existing TCP, is now guarded instead of pinning an old DIRECT
permission. Supported TCP framing receives a local reset to let the application
try its normal alternatives. GUI continues to show IPv6 unsupported; this is not
IPv6 relay support and does not prove every application chooses IPv4 automatically.
Unparseable IPv6 fragments/extensions and unavailable/ambiguous process ownership
retain the existing documented attribution limits. No universal leak-proof
firewall claim is made for those cases. Required release testing must cover the
actual client network's IPv4/IPv6 behavior and retain these diagnostics.

## Evidence and GUI

`status.hot_attach` and optional authenticated `hot_attach.status` expose epoch,
reason, start/completion timestamps, scanned rows, reset requests, remaining
native targets, UDP retirements, quarantined packets and concrete errors:

- HOT_ATTACH_PREPARING: only affected apps are fenced while old handles drain.
- HOT_ATTACH_RECONNECTING: targeted reconciliation is running.
- HOT_ATTACH_NETWORK_READY: old attributable native targets have drained; the
  capture guard is armed. It is **not** application-level PASS.
- HOT_ATTACH_INCOMPLETE: bounded reconciliation failed/timed out; GUI warns and
  diagnostics retain the cause. Active selected old traffic remains guarded.

Per-flow `hot_attach` includes epoch, policy revision and lifecycle states:
PREEXISTING, RETIRED, RESET_REQUESTED, NEW_FLOW, ROUTE_OPENED/FAILED/USED,
TRANSFORM_APPLIED and IPV6_UNSUPPORTED, each prefixed HOT_ATTACH_. Reset/table
inspection is metadata with zero captured packets; it never manufactures traffic.
Old-policy counters retire before new-policy reset evidence, so a permitted
pre-activation DIRECT byte cannot be mislabeled a new required-route leak.
Existing packet/open/loss/fatal-failure counters remain authoritative.

Normal GUI shows automatic reconnection progress and incomplete status. Diagnostics
show reset/pending counts. No restart instructions remain in the normal AUTO flow.
The GUI and service both need this build to display the new state (old GUI/service
contracts continue to tolerate missing optional fields).

## Regression coverage

Portable tests cover enable-before-capture/rollback, disable/re-enable generations,
scoped/idempotent profile updates, policy revisions isolated across applications,
fresh flow retention, exact reset tuple/sequence/no payload/no RST loop, table bounds,
old-policy evidence isolation, no fake captured packets, guarded pre-existing IPv6
and actual DIRECT+ transform evidence. Desktop tests cover transition/error/ready
status and optional IPC compatibility.

Native Windows tests create **owned test children** first, keep their PID/native
birth unchanged, then reset only the selected real TCP socket twice. The child
reconnects automatically; another child's same-target TCP socket remains alive.
Wrong owner/stale creation time is rejected. Test cleanup stops only those owned
fixtures after assertions, never product/user processes. A native UDP test retires
only the affected app handle, reopens the same tuple without process restart and
checks zero required DIRECT bytes. Existing 160 DNS + eight adaptive UDP load,
relay pool authentication/tickets, TCP pipe failure/teardown and signed-driver
lifecycle regressions are retained, including native race and PS5.1/PS7 fixtures.

The native socket test is controlled loopback validation of the Windows reset API;
it is not real browser relay acceptance or Internet performance evidence.

## Real Windows release acceptance (developer/operator test only)

Build/install the matching service and GUI using existing tools; preserve
ProgramData, profile files, credentials and ACLs. No VPS update is needed:

```powershell
git switch codex/direct-plus-flowseal
git pull --ff-only origin codex/direct-plus-flowseal
.\tools\windows\build-e2e.ps1
.\tools\windows\build-desktop.ps1
```

For binary replacement use the existing ACL-preserving SCM update procedure in
[WINDOWS_CAPTURE_LIFECYCLE.md](WINDOWS_CAPTURE_LIFECYCLE.md#incremental-windows-update-and-rerun).
The earlier maintenance suggestion to close sensitive apps during a service-off
binary update is not a product restart requirement after Optimize. This release
test intentionally keeps apps alive across controlled OFF/ON windows; traffic
while OFF is DIRECT and outside the protection assertion.

With Happ completely OFF, first run Chrome YouTube, Edge ChatGPT, ChatGPT/Codex
and Discord. Then start VELIQ/enable Optimize through the GUI with the existing
profiles. Observe automatic recovery without restarting/reconnecting an app.
To collect strict incremental developer proof for two OFF/ON cycles:

```powershell
.\tools\windows\acceptance-hot-attach.ps1 -StageSeconds 60 -ReportDirectory .\bin\hot-attach-final
```

This helper itself is **not** part of normal user UX. It refuses missing already-
running apps, preserves initial root PID/path/birth checks during both stages,
advances bounded evidence cursors, rejects loss/restart/incomplete generations,
and requires fresh required bidirectional relay and YouTube DIRECT+ configured-
baseline/disorder/real transform/zero relay evidence. Both queue and worker drop
deltas must be zero. It never launches or restarts applications or modifies profiles.
It does temporarily toggle Optimize and restores the original ON/OFF state even
on failure; restoration errors are saved explicitly. Existing profiles/credentials
are untouched. Reports explicitly retain
OPERATOR_OBSERVATION_REQUIRED for application acceptance.

Release requires all eight observations, not merely a transport-proof PASS:

1. Apps were already running before service/Optimize; original root PID and native
   creation times remain unchanged.
2. Targeted native flows reconnect within the bounded reconciliation window;
   actual fresh selected flows appear under current policies during application use.
3. No required DIRECT packet/byte leak after the installed protection boundary.
4. YouTube resumes video/seek via actual configured DIRECT+ with zero relay bytes.
5. Edge, ChatGPT desktop/web and Codex requests recover through VPS-01.
6. Discord messages and real voice recover automatically, with voice observations
   over time; network bytes alone cannot prove voice quality.
7. An unrelated persistent DIRECT control application/socket stays connected and
   retains its process/connection identity; no machine/network reset occurred.
8. Disable/re-enable repeats convergence without any process restart or manual
   reconnect, with complete bounded evidence and zero queue/worker saturation drops.

Do not merge or claim this release requirement passed until that external Windows
run succeeds. A non-retrying application request or unsupported IPv6 behavior is
an acceptance failure to diagnose, not grounds to invent success or kill the app.
