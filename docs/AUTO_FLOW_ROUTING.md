# AUTO per-flow routing: implementation and Windows verification

Status: implementation for Windows verification. Local/unit/CI checks are NOT a
real Windows/ISP release gate. The operator's Happ-OFF YouTube disorder/video/seek
baseline is accepted; it is not a new measurement made by this change. VPS-01,
its credentials, deployment, mTLS, tickets, replay/public-only checks are untouched.

## Decision model

Each selected application has an immutable decision snapshot per new flow.
Specific domain/protocol/CIDR/port/network rules outrank learned target results,
then the application preset, then the application default/global route selector.
Domain suffix boundaries, more specific suffix/CIDR and narrower ports are
explicit; equal specificity uses configuration order. No cross-application rule
lookup occurs. TCP never changes upstream after opening it. Profile changes apply
to new connections. UDP's explicit DIRECT-first probe is the single exception:
only that UDP flow can transition once to relay; other established flows stay put.

Actions: DIRECT, DIRECT_PLUS(strategy), RELAY(relay ID), RELAY_REQUIRED(relay ID),
BLOCK. Fallback: FAIL_OPEN_DIRECT, RELAY_REQUIRED, FLOW_RELAY_FALLBACK, BLOCK.
RELAY_REQUIRED is enforced again in the transport engine through the pinned flow
policy. A transport-open/session/worker/state failure cannot silently select
DIRECT for that protected flow. Legacy profiles without these fields keep their
previous global fallback semantics. The temporary global BLOCK workaround is
not reset by an upgrade or by clicking AUTO.

The current curated AUTO roles are conservative:

* ChatGPT: all attributed root/helper TCP and UDP require authenticated VPS-01.
* Edge: protected browser role, with consistent VPS-01 egress for the selected
  browser. This conservatively relays the whole selected Edge application, not the
  machine; it is not a claim that every Edge destination needs relay. Advanced
  scoped rules can override this application preset deliberately.
* Discord: all TCP control/update/API, and UDP/443, require relay. High-port UDP
  (>=1024, never UDP/443) is a **media candidate**, not proven voice identification.
  It first uses a native DIRECT UDP socket in bounded probation. A single reply
  or burst is not success: sustained bidirectional cadence must confirm DIRECT.
  Insufficient probation or sustained cadence degradation can transition only
  that flow once to authenticated relay. Missing/failed relay blocks that flow.
  See [adaptive UDP health](ADAPTIVE_UDP_HEALTH.md) for thresholds, evidence,
  exact update commands and the focused Windows Discord retest. Confirmed success
  and failure use the bounded two-minute application/network/endpoint cache
  (1024 entries). Old media datagrams are not replayed; probe loss is real.
  Flow state uses the existing bounded two-minute UDP idle-flow table. No server
  IP or Discord version is hardcoded.
* Chrome: adopts an existing selected DIRECT+ configuration when the user changes
  that working profile to AUTO, bound to a fresh VPN-free network fingerprint and
  that strategy's content revision. Thus the reported working YouTube disorder
  baseline is retained without running the seven candidates again. Changing the
  network or the selected strategy content invalidates this binding. Updating
  Discord's presets does not invalidate Chrome's pending ClientHello or binding.

## Late TCP/SNI decision

An AUTO/rule flow which needs domain evidence enters the **existing** transparent
TCP redirect. The app handshake terminates at the existing local TCP listener,
not a TLS listener. At most 128 concurrent decision workers retain at most 32 KiB,
32 reads and two seconds of original first bytes each. The existing TLS record /
ClientHello assembler yields only outer SNI; fragmented HTTP Host is also handled.
No certificate generation, TLS decryption, inner ECH inference or payload logging.
An ECH extension (including indistinguishable GREASE), incomplete/missing SNI or
unsupported framing takes the configured opaque-name fallback;
protected fallback blocks instead of leaking DIRECT. No upstream application
bytes are written before the decision. Explicit fail-open on upstream setup failure
gets a separate bounded three-second native dial; required/block policies never do. The unchanged buffered stream is written
once, followed by bounded streaming copies and half-close support.

DIRECT and authenticated relay use the selected pinned upstream. DIRECT+ uses a
native upstream socket registered by exact source/destination **before its SYN**.
Only those backend-created sockets bypass the normal service-self exclusion.
They enter the existing native DIRECT+ packet-transform/reassembly path, retaining
sequence/ACK/options/fake safeguards. No stream-level Write splitting is presented
as packet disorder. Original app endpoint evidence receives the delegated packet
counters through a bounded alias. Normal service/relay/control-plane traffic is
never re-intercepted. No additional capture backend, WinDivert pipeline, winws or
GoodbyeDPI is created. Existing native YouTube DIRECT+ remains the native path.

Limits: TCP states 8192, redirect open/decision workers 128, live delegated sockets
128, evidence aliases 1024 (pruned with TCP state), normal evidence ledger 1024 and
existing IPC 32 flows/60 KiB limits. Failures remain explicit. This new deferred
path, particularly delegated DIRECT+, still requires external Windows runtime
verification; a green build does not certify it.

## Process groups and updates

The service reuses process discovery. Identity is PID + creation time + executable
path. Parent PID and parent birth metadata are queried without process memory
reads. Ancestry is bounded to 16 hops. No basename-only global codex/WebView rule.

ChatGPT's curated helpers are codex.exe, codex-windows-sandbox-service.exe and
codex-computer-use-swift.exe. They inherit through validated ancestry, or through
a curated helper manifest confined to the selected install/package. The latter
also permits SCM-started helpers inside that install. Helpers outside it require
valid ancestry; inaccessible/unattributable processes are not guessed into a group.
A previously attributed live helper retains the group after its root exits; a
reused PID/different image does not borrow the binding. A generic WebView process
in another application does not inherit it. Existing explicit helper profiles
cannot override an established application's group merely by matching a path.

Discord app-N.N.N.N versions are matched only under the selected install root;
its Update.exe is confined to that install. ChatGPT MSIX identity supports a new
package version under the same WindowsApps root, package name, publisher ID and
relative root exe. No concrete Codex hash, version directory or diagnostic IP.
Publisher IDs are package identity metadata, **not** an independently performed
Authenticode verification. Arbitrary layouts require a manifest/explicit profile;
the program does not invent publisher/signature evidence.

## Learning and bounded automatic measurement

Cache key: network fingerprint + stable application identity + application-scoped
configuration revision + protocol + observed hostname + destination port. DIRECT,
DIRECT+, RELAY results include score, outcome, timestamps and expiry. Recently
failed candidates are quarantined for five minutes; successful probe evidence is
valid for fifteen minutes. Cache persistence is bounded, atomic and inside the
existing protected service state directory. Other applications' configuration
changes cannot alter this application's revision. No payloads, secrets or raw
browser network logs are stored in it.

The normal AUTO button starts the bundled auto-optimize.ps1 as the ordinary GUI
user. Privileged capture stays in the authenticated service. No UAC is requested.
Chrome has a finite YouTube HTTPS adapter using the existing seven candidates,
real DIRECT/RELAY controls and exact socket/target proof. A lease/cooldown bounds
work to one attempt per application/network per ten minutes, at most sixteen
leases. Failed/quarantined candidates are excluded. Browser cold startup has a separate 45-second readiness budget with a final
deadline snapshot; navigation/HTTPS measurement keeps its own timeout. The worker has a ten-minute
limit, bounded output and private per-run proof files. It does not run in a
continuous background traffic loop. Other applications without an application-
level adapter use their scoped preset/default; no generic TCP ACK is called
application success. Discord/OpenAI do not keep retrying the already unsuccessful
DIRECT+ launch candidates.

Automatic browser trials use a separate disposable profile and a validated
birth-scoped root/descendant application profile. They can run while normal Chrome
is open: regular Chrome flows never acquire the probe profile. Probe profiles
expire and are never persisted. Only flows from that root's current process family
are queried. Profile ID reuse cannot lend an old trial's process binding. The
seven strategies/QUIC policy and certificate/socket/target checks are unchanged.
`TRANSFORM_APPLIED` alone cannot populate a success. Instrumentation ambiguity or
loss of evidence cannot create a winner or a 100% loss measurement.

A successful document trial does not prove video playback, login or Discord voice.
A preserved operator-confirmed baseline is labeled `configured_baseline`, not a
new measured PASS. Unknown applications have no invented HTTPS adapter. The GUI
shows AUTO and observed routes normally; strategy IDs, TTL and manual selectors
are in Advanced/Diagnostics. Diagnostics expose process group, PID/birth, domain,
source/destination, route, strategy, relay, actual counters, fallback cause,
learning source, fingerprint and relay-required block state. Truncation continues
to prevent negative/no-traffic assertions.

## Stop/crash and IPv6 boundary

A running service's RELAY_REQUIRED transport failure blocks the affected flow;
other applications retain their own policies. Transparent proxy connections close
on stop. The existing WinDivert stop/crash guarantee remains machine fail-open:
there is no persistent firewall/driver policy after service exit. Consequently
**RELAY_REQUIRED is not a crash-persistent no-leak firewall**. If that is required,
a separately designed per-application persistent OS guard is needed; this change
does not silently install one or leave Windows permanently blocked. Test stop and
crash with protected applications closed/paused; independent control must reconnect
DIRECT. Do not describe service-off OpenAI reconnects as protected.

Transparent IPv6 relay/transform remains unsupported. Selected protected and
all IPv6 which would require deferred domain classification or monitored UDP
fallback are blocked, including bounded-state saturation; unrelated
DIRECT IPv6 remains native. Existing midstream TCP is not silently moved. No IPv6
support claim without an actual Windows runtime test. System DNS remains unchanged;
only identified application flows are covered. A system resolver's DNS query is
not reclassified as ChatGPT/Discord traffic or called application-aware DNS.

## Build and safe update over the current installation

From a clean checkout on Windows with Go 1.25 and .NET SDK 8 (build tools only):

```powershell
git switch codex/direct-plus-flowseal
git pull --ff-only origin codex/direct-plus-flowseal
go build -trimpath -o .\bin\windows-e2e\neexitlag-service.exe .\services\client-service\cmd\service
.\tools\windows\build-desktop.ps1 -Output .\bin\release
.\tools\windows\build-e2e.ps1
```

Or download **windows-real-e2e-tools** and **VELIQ-win-x64** from the SAME
successful Verify HEAD. The GUI archive now includes tools/windows; keep them
beside VELIQ.exe so AUTO never asks users to locate a test script.
Close the old GUI via tray Exit; close the target apps before the service update.
No uninstall, reinstall, enrollment, driver replacement or VPS command is needed.
From elevated PowerShell, set only the extracted bundle path:

```powershell
$replacement=(Resolve-Path 'C:\neexitlag-artifacts\auto\neexitlag-service.exe').Path
$svc=Get-CimInstance Win32_Service -Filter "Name='neexitlag'"
if(!$svc){throw 'Existing service required; do not provision a new installation'}
$installed=if($svc.PathName -match '^"([^"\r\n]+)"'){$Matches[1]}elseif($svc.PathName -match '^(.+?\.exe)(?:\s|$)'){$Matches[1]}else{throw 'Cannot parse existing service path'}
$acl=Get-Acl -LiteralPath $installed
$backup=$installed+'.before-auto.bak'
Stop-Service neexitlag -ErrorAction Stop
(Get-Service neexitlag).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
Copy-Item -LiteralPath $installed -Destination $backup -Force
Copy-Item -LiteralPath $replacement -Destination $installed -Force
Set-Acl -LiteralPath $installed -AclObject $acl
if((Get-Acl -LiteralPath $installed).Sddl -ne $acl.Sddl){throw 'Original service ACL must be preserved'}
if((Get-FileHash -LiteralPath $installed).Hash -ne (Get-FileHash -LiteralPath $replacement).Hash){throw 'Binary copy mismatch'}
Start-Service neexitlag -ErrorAction Stop
(Get-Service neexitlag).WaitForStatus('Running',[TimeSpan]::FromSeconds(15))
```

Credentials, service.json, enrollment, trust, IPC token, existing state and global
BLOCK remain in place. For rollback stop service, copy `.before-auto.bak` over the
same path, restore `$acl`, restart. Before making profile changes save an IPC status
snapshot as below; configuration rollback is explicit, not a destructive reset.
Run the updated GUI without elevation from the extracted GUI directory. The bundled helper is launched with process-scoped PowerShell execution policy
for that child only, without elevation or a persistent machine/user policy change.
Enforced enterprise Group Policy remains authoritative; if it blocks the helper,
the GUI retains diagnostics instead of pretending measurement succeeded.

## Exact migration and real Windows acceptance, Happ OFF

No real Windows machine is attached to this development session. Do not mark the
following gates PASS from CI/local transport fixtures. Keep the working MANUAL /
DIRECT_PLUS settings until the corresponding migration is verified.

1. Happ completely OFF. Start updated GUI normally; enable optimization. From the
   matching checkout, snapshot configuration/metadata, without credentials:

   ```powershell
   . .\tools\windows\common.ps1
   Invoke-ServiceIPC 'status' | ConvertTo-Json -Depth 20 | Set-Content .\before-auto-status.json -Encoding UTF8
   Invoke-ServiceIPC 'profiles' | Format-Table id,name,mode,relay_id,local_strategy_id
   ```

2. **Chrome baseline first:** retain its current DIRECT_PLUS disorder setting.
   Confirm YouTube opens, play 30+ seconds, seek, and capture actual googlevideo
   DIRECT_PLUS modification counters with zero relay bytes. This is a regression
   gate for the new binary, not a request to rediscover the known candidate.

3. Select Chrome, click **AUTO · Оптимизировать**. Its existing selected strategy
   is bound to the fresh network/strategy revision; `configured_baseline` must skip
   finite trials. Keep Chrome running; HOT ATTACH reconnects its selected TCP flows. Repeat playback/seek and
   zero-relay check. A new network may start bounded isolated verification; normal
   Chrome must remain unaffected by the temporary process-scoped profile.

4. **Edge:** first confirm the existing MANUAL VPS-01 ChatGPT web works. Switch to
   AUTO only after that regression passes. The curated protected browser preset
   uses consistent authenticated VPS-01 egress. Verify real ChatGPT login/API use,
   positive relay request/reply bytes and no selected Edge DIRECT payload flows.

5. **ChatGPT Windows app:** keep global BLOCK for this first gate. Select its root
   ChatGPT.exe profile, click AUTO. Keep the app and relevant helpers running. Verify HOT ATTACH and
   login and workspace, exact PID/birth/path/group evidence for ChatGPT.exe and all
   observed codex helpers. If any helper is unattributed, stop migration and inspect
   its ancestry/install identity; do not remove global protection or assume it has
   no traffic. No hardcoded hash/path should be necessary for supported layouts.

6. **Remove only the workaround:** after those identities are verified, migrate the
   selected existing profile IDs (replace the examples with the IDs from step 1):

   ```powershell
   .\tools\windows\migrate-auto.ps1 -ProfileIds 'YOUR-CHATGPT-PROFILE-ID','YOUR-DISCORD-PROFILE-ID' -WhatIf
   .\tools\windows\migrate-auto.ps1 -ProfileIds 'YOUR-CHATGPT-PROFILE-ID','YOUR-DISCORD-PROFILE-ID'
   # Only after real protected-group route evidence is verified:
   .\tools\windows\migrate-auto.ps1 -ProfileIds 'YOUR-CHATGPT-PROFILE-ID' -RestoreGlobalDirect
   ```

   Keep apps running; HOT ATTACH applies updated policies to fresh connections. The script saves before.json under the invoking user's private
   LocalAppData. It never touches /etc/neexitlag or enrollment files. Explicit
   `-RestoreGlobalDirect` requires an OpenAI AUTO profile and does not itself prove
   all helpers have passed runtime acceptance; the operator gate above is required.

7. **Relay failure with service still running:** use the existing controlled relay
   failure mechanism from Windows acceptance or temporarily block only this
   Windows client's relay TCP transport, with an explicit timed rollback. Never
   stop/reinstall the VPS. Establish fresh OpenAI/Edge connections: affected flows
   must show BLOCK / relay_required_blocked / fallback reason, zero DIRECT and no
   mixed egress. An unrelated native control app must continue to receive DIRECT
   responses. Restore client relay access and use fresh connections for recovery;
   blocked old TCP is not migrated. Retain stdout/stderr/status/scoped capture.

8. **Discord:** migrate its root Discord.exe versioned identity to AUTO. Start
   updater -> Starting -> login -> messages -> voice. Both Discord.exe update/API
   and its install-scoped Update.exe must relay-required; unrelated Update.exe
   must remain unchanged. Verify high-port UDP is only called a media candidate,
   `udp_health.state` is DIRECT_CONFIRMED with sustained cadence (not just positive
   reply counters), and measure the
   in-app voice latency against the reported ~310 ms relay baseline. No latency
   improvement is claimed until measured. Keep UDP/443 separate.

9. **Voice failure:** on the Windows client, temporarily drop only the selected
   media endpoint's DIRECT UDP traffic, with a timed undo. After failed probation or sustained
   confirmed cadence degradation only that UDP tuple may use VPS-01; existing other Discord UDP/TCP and
   Chrome flows must retain their routes. Verify new real relayed datagrams and
   replies; do not replay or subtract the lost initial probes. Remove the rule.
   Then test a new DIRECT media flow and idle cleanup/TTL.

10. **Simultaneous:** Chrome video+seek, Edge ChatGPT web, ChatGPT app workspace,
    Discord messages+voice and an unrelated DIRECT echo control together. Save
    scoped evidence by PID+creation/source/marker; check zero relay Chrome payload,
    zero DIRECT OpenAI payload, control TCP relay and responding DIRECT media.
    Verify profile edits change only new connections. Repeat after Discord update
    and a Codex helper path/version change. Happ stays OFF throughout.

11. **Stop/crash:** pause/close geo-sensitive apps, retain independent native
    control, run the existing stop/crash acceptance. Control must reconnect DIRECT
    and Windows must not stay blocked. Restore service and verify protection before
    reopening sensitive applications. Service-off traffic is explicitly outside
    RELAY_REQUIRED protection in this WinDivert fail-open design.

12. **Deferred/domain test:** use an Advanced test profile with TCP hostname A ->
    RELAY_REQUIRED and B -> DIRECT_PLUS plus explicit incomplete/ECH fallback. Use
    two controlled certificate-valid endpoints and simultaneous connections from
    one executable. Verify exact source-to-upstream evidence, original byte stream,
    one pipeline, zero native DIRECT for A, actual modifications for B, and no
    route transfer after connection establishment. Missing outer SNI must take the
    configured fallback. Test bounds, relay outage, service stop, concurrent opens
    and delegated-socket cleanup. This gate is mandatory before calling the late
    proxy path production verified.

## Relay capacity and simultaneous follow-up

The service now publishes a bounded authenticated session pool per VPS instead
of a single 64-stream client. See [session pool, incremental capture and exact
Windows retest](RELAY_SESSION_POOL.md). The reported real simultaneous test at
fd06ea3 failed; CI does not supersede that result. New real Windows verification
is required. Existing application policies and DIRECT+ strategy are unchanged.

HOT ATTACH activation/reconnect semantics, GUI state, safety boundary and release acceptance: [WINDOWS_HOT_ATTACH.md](WINDOWS_HOT_ATTACH.md). Old controlled test steps that close apps for a binary/service update are maintenance precautions, not a product requirement to restart apps after Optimize.
