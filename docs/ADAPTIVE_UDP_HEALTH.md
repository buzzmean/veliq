# Adaptive media-candidate UDP health

The real Happ-OFF Discord report (130 ms ↔ 5000 ms) shows intermittent DIRECT
connectivity, not complete absence of UDP. The previous first-reply latch disabled
all subsequent health checks and wrote a healthy endpoint observation immediately.
Two replies / 580 bytes never proved useful voice. This fix does not assert voice
latency is fixed: that requires the Windows/ISP retest below.

## State and thresholds

Only the existing explicitly classified high-port UDP media candidates use this
monitor. DNS/53 and UDP/443 are not media candidates; UDP/443 and Discord TCP retain
RELAY_REQUIRED VPS-01. Chrome/YouTube AUTO, OpenAI required routing, VPS deployment,
authentication and credentials are unchanged. No protocol payload parsing or
Discord address/port allowlist is used.

* `DIRECT_PROBATION`: start the bounded three-second window on the first
  **successful outbound send**, not socket creation. Forward immediately; there
  is no buffer/delay while waiting for confirmation. Require replies in at least
  four distinct 250 ms bins, spanning at least 750 ms, in a rolling 1.5 s window
  (windows have 250 ms bucket granularity).
  Outbound must also occupy four bins spanning 750 ms, with a successful send
  within 500 ms and at/after the first reply. Even a large single burst cannot
  confirm. Healthy continuous traffic normally confirms in about 0.75–1 second.
* Insufficient confirmation by the deadline: `FLOW_RELAY_FALLBACK`, reason
  `DIRECT_INSUFFICIENT_REPLIES`. A valid reply at the confirmation boundary is
  evaluated as evidence; a timeout by itself does not confirm anything.
* `DIRECT_CONFIRMED`: retain DIRECT while monitoring a rolling two-second window.
  With ongoing outbound (four occupied bins, span >=750 ms, last send <=500 ms),
  require inbound in four bins spanning >=750 ms. When cadence stays below this
  floor for **two additional seconds**, fall back with `DIRECT_LIVENESS_LOST`.
  Isolated/rare replies do not reset the degradation clock; only sustained cadence
  does. A short gap/read timeout does not switch the route. With active continuous
  outbound, complete loss or persistent sparse replies normally switch within
  about 3–4 seconds after degradation starts, including rolling-window history.
  No ongoing outbound means idle, not a connectivity failure. Sparse keepalive-only
  outbound does not justify a confirmed-flow liveness failure; initial probation
  remains bounded and cannot be confirmed by keepalives alone.
* `FLOW_RELAY_FALLBACK` is one way for this flow's lifetime. It opens the existing
  authenticated pinned RELAY_REQUIRED transport. Failure to open relay blocks
  this candidate; it never reverts to DIRECT. No previously sent datagram is
  replayed. A real atomic send error can retry only that unsent datagram.

These are conservative **transport cadence floors**, not protocol-aware loss,
RTT, voice quality, or a target ratio of sent/received packets. Asymmetric UDP is
not assumed to have one response per send. Some slow/bursty non-media protocols
can fall back conservatively if explicitly put into this candidate class.
The 250 ms bins permit ordinary jitter/batching; four bins plus the true time
span reject a single event/boundary burst. The rolling window and separate grace
avoid reacting to one Windows read/deadline race. Native socket `net.Error`
timeouts are still normalized to polling timeouts. Read health polls are bounded
to 250 ms after traffic starts, and sends also check health before choosing the
transport for that datagram. Existing caller read cancellation is preserved.

Each flow stores exactly 16 bins (four seconds of ring capacity), scalar counters
and timestamps, never packet payload/history. Existing engine/worker/state bounds
and idle cleanup remain. Endpoint observations are network + application +
destination scoped, max 1024, two-minute TTL. Only confirmation writes DIRECT
success. Failed probation/liveness writes relay preference. A cached failure
opens required relay directly, reason `LEARNED_RECENT_DIRECT_FAILURE`. Healthy
cache entries do not bypass fresh-flow probation. Other existing flows retain
independent monitors and routes.

## Evidence

`capture.diagnostics` flow `udp_health` contains `state`, `reason`,
`probation_replies`, `probation_reply_bytes`, `probation_duration_ms`,
`reply_bins`, `outbound_bins` and `degraded_duration_ms`. Probation counters freeze
on confirmation or fallback. Cadence/degradation evidence freezes at fallback,
so a later snapshot retains the actual triggering evidence. Health snapshots on
send, receive and timeout do not manufacture packets or bytes. Independent
DIRECT/RELAY counters remain actual transport events. `FLOW_RELAY_FALLBACK` is the
state/fallback policy; insufficient-replies/liveness-lost is the cause, not a
change to a global policy. Failed required-relay setup also retains this cause in
`udp_health`, alongside the existing blocked/transport-failed evidence.

GUI adaptive DIRECT status requires `DIRECT_CONFIRMED`; a missing legacy field,
single reply, or probation cannot claim confirmation. Advanced details include
state/reason, probation counters/duration and rolling cadence. Confirmation proves
transport traffic only, never Discord latency.

## Exact Windows rebuild and update

Close Discord and exit the old GUI through its tray first. In the existing repo,
with Go 1.25 and .NET SDK 8 available:

```powershell
git switch codex/direct-plus-flowseal
git pull --ff-only origin codex/direct-plus-flowseal
go build -trimpath -o .\bin\windows-e2e\neexitlag-service.exe .\services\client-service\cmd\service
if ($LASTEXITCODE -ne 0) { throw 'Service build failed' }
.\tools\windows\build-desktop.ps1 -Output .\bin\release
```

From an elevated PowerShell in that same checkout, update the **existing** SCM
binary without uninstall/enrollment/configuration changes:

```powershell
$ErrorActionPreference='Stop'
$replacement=(Resolve-Path '.\bin\windows-e2e\neexitlag-service.exe').Path
$svc=Get-CimInstance Win32_Service -Filter "Name='neexitlag'"
if(!$svc){throw 'Existing neexitlag service required'}
$installed=if($svc.PathName -match '^"([^"\r\n]+)"'){$Matches[1]}elseif($svc.PathName -match '^(.+?\.exe)(?:\s|$)'){$Matches[1]}else{throw 'Cannot parse service path'}
if($replacement -eq $installed){throw 'Build and installed binary paths must differ'}
$acl=Get-Acl -LiteralPath $installed
$backup=$installed+'.before-udp-'+(Get-Date -Format 'yyyyMMddHHmmss')+'.bak'
Stop-Service neexitlag
(Get-Service neexitlag).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
Copy-Item -LiteralPath $installed -Destination $backup
Copy-Item -LiteralPath $replacement -Destination $installed -Force
Set-Acl -LiteralPath $installed -AclObject $acl
if((Get-Acl -LiteralPath $installed).Sddl -ne $acl.Sddl){throw 'Original service ACL must be preserved'}
if((Get-FileHash -LiteralPath $installed).Hash -ne (Get-FileHash -LiteralPath $replacement).Hash){throw 'Binary mismatch'}
Start-Service neexitlag
(Get-Service neexitlag).WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
```

Run `bin\release\VELIQ.exe` as the normal user from a non-elevated shell.
Alternatively extract service/tools and GUI artifacts from the **same new Verify
HEAD**, set `$replacement` to that extracted service executable and use the same
update block. Keep tools beside the GUI. No VPS or credentials changes are needed.
Rollback: stop service, restore `$backup` to `$installed`, restore `$acl`, restart.

## Focused real Windows Discord retest (Happ completely OFF)

1. Start updated GUI/service, enable optimization, keep Discord AUTO and VPS-01.
   Open Discord fresh so the test uses new UDP flows. Do not change Chrome's
   known-working policy, OpenAI policy, or the existing VPS.
2. Join voice, transmit/receive continuously for at least 60 seconds. Log in-app
   ping over time (including 130 ↔ 5000 spikes), reconnects and audible continuity.
   Capture once/second while voice is active. For example, in PowerShell from
   the checkout (IPC access under the existing installation's ACL):

   ```powershell
   . .\tools\windows\common.ps1
   $dir=New-Item -ItemType Directory -Force ('.\bin\discord-health-'+(Get-Date -Format 'yyyyMMddHHmmss'))
   for($i=0;$i -lt 60;$i++){
     foreach($process in @(Get-Process Discord -ErrorAction SilentlyContinue)){
       $capture=Invoke-ServiceIPC 'capture.diagnostics' @{pid=$process.Id}
       $capture|ConvertTo-Json -Depth 24|Set-Content (Join-Path $dir.FullName ("{0:D3}-{1}.json" -f $i,$process.Id)) -Encoding UTF8
     }
     Start-Sleep -Seconds 1
   }
   Invoke-ServiceIPC 'status'|ConvertTo-Json -Depth 24|Set-Content (Join-Path $dir.FullName 'status.json') -Encoding UTF8
   ```

3. For each exact UDP source/destination + PID/birth/flow_id, verify either sustained
   `DIRECT_PROBATION → DIRECT_CONFIRMED`, or one-way fallback with the correct
   insufficient/liveness reason. A few intermittent replies must not hold DIRECT
   forever. After fallback require actual relayed bytes **and relay replies**;
   a route label alone is not success. Do not subtract initial lost probes.
   Cached-failure new flows may start directly on required relay. Idle/silent
   outbound is not a confirmed-flow failure test.
4. Verify Discord TCP and UDP/443 still require VPS-01; an unrelated DIRECT control
   and other established flow routes stay unchanged. Save scoped JSON and the
   ping/voice observations. If real voice remains unstable on relay, retain that
   result as a separate runtime failure: unit/CI cadence tests cannot prove it fixed.

## Changed files and automated checks

* `core/routing/adaptive_udp.go`, `udp_health.go`: one-way transport + fixed-ring
  probation/liveness; `adaptive_udp_test.go`, `udp_health_test.go`: read timeout,
  single/burst/sparse replies, sustained health/recovery, stopped inbound, idle,
  scoped cache and simultaneous independent flows.
* `platform/windows/capture_windows.go`, `evidence.go`, `evidence_test.go`: publish
  metadata on send/receive/timeout, immutable snapshots, actual counters unchanged.
* `apps/desktop-core/Models.cs`, `DesktopViewModel.cs`,
  `tests/desktop/FlowPolicyTests.cs`: backward-compatible DTO and confirmed status.
* `services/client-service/flow_policy_test.go`: UDP/443 required/DNS not media.
* `tools/windows/build-e2e.ps1`: include this instruction in the downloadable
  service/tools archive. This document and `AUTO_FLOW_ROUTING.md`: semantics
  and focused update/retest.

Run `go build ./...`, `go test -race -p 2 -timeout 120s ./...`, `go vet ./...`,
`GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...`, and
`dotnet test tests/desktop/Veliq.Client.Tests.csproj --nologo`.
Windows Verify additionally runs native Go/WPF, PS 5.1/7 acceptance fixture checks,
WinDivert start/stop and browser instrumentation regressions. These are not a
Discord Internet/voice latency measurement.
