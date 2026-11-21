# Real Windows / public-Internet acceptance

> This document records the earlier UDP stage. The owner reports it passed on real
> Windows. Current TCP/web acceptance and changed size/IPv6 limits are documented
> in [WINDOWS_TCP_WEB.md](WINDOWS_TCP_WEB.md); do not repeat the proven UDP stages
> as a prerequisite for TCP acceptance.

**Status: manual simultaneous Windows DIRECT/RELAY E2E confirmed by the operator.**
The operator reports test-game.exe: 30 captured, 30 relayed, 0 direct, 27 relay
replies, RELAY/VPS-01, echo source = VPS public IP; concurrently control-client.exe:
30 captured, 0 relayed, 30 direct, 30 replies, DIRECT, echo source = client public IP.
These are operator-reported real results, not a cloud execution. The revised
automated acceptance still needs its Windows/VPS rerun. Cloud has no Windows
runtime, VPS address or SSH binding; local regression checks do not replace it.
Phase 0–6 checkpoint fa7cdc1 is preserved; pre-work checkpoint is 80eef79.

This stage changes Windows IPv4 UDP capture/discovery, diagnostics, ordinary test
applications and deployment/acceptance tooling. GUI, scoring, the relay wire
protocol and the existing demo are retained.

## Windows preparation

Use a dedicated Windows 10/11 x64 test PC, elevated PowerShell 5.1+ or PowerShell7,
Go1.25+, Git and Windows OpenSSH client. SSH needs an existing key/agent and a
verified known_hosts entry. The VPS login must be root or have noninteractive
sudo. Do not paste private keys or tokens into chat. Synchronize both host clocks.

Clone a fresh checkout so existing working files are preserved:

```powershell
git clone --branch codex/windows-real-e2e https://github.com/buzzmean/neexitlag.git neexitlag-e2e
cd neexitlag-e2e
Set-ExecutionPolicy -Scope Process RemoteSigned
```

Set `$VPS_PUBLIC_IP`, `$SSH_USER`, `$SSH_PORT` to the operator's actual values.
There is no example IP default; private, loopback and documentation addresses are
rejected by the deployment/acceptance commands.

```powershell
.\tools\windows\setup-e2e.ps1 -VpsPublicIP $VPS_PUBLIC_IP -SSHUser $SSH_USER -SSHPort $SSH_PORT
.\tools\windows\acceptance.ps1 -VpsPublicIP $VPS_PUBLIC_IP -SSHUser $SSH_USER -SSHPort $SSH_PORT
```

Setup builds the Windows service, selected/control executables and Linux backend
binaries, fetches official pinned WinDivert, creates scoped private credentials,
uploads via verified SSH, installs VPS units, enrolls the device using private-CA
HTTPS and installs/recovery-configures the Windows service. It refuses to replace
an existing Windows service or unrelated VPS identity. A same-VPS private bundle
can be reused after an ingress/enrollment failure. Keep `.e2e` private; it contains
operator CA/admin credentials as well as client state. No key material is printed.
The service receives only its device identity/certificate, trust, probe token and
IPC credentials, never the CA signing key or bootstrap admin token.

Open provider/host firewall ingress before enrollment: TCP8443 (HTTPS), UDP4433
(QUIC), UDP40000 (authenticated echo). Preserve SSH access. Setup does not enable
UFW, rewrite existing firewall rules, or change Windows default routes. For an
already active UFW installation, the corresponding rules are:

```sh
sudo ufw allow 8443/tcp
sudo ufw allow 4433/udp
sudo ufw allow 40000/udp
```

Provider security-group rules are separate. VPS minimum: Ubuntu24.04 LTS or Debian
with systemd, x86_64, public IPv4, approximately1GB RAM and a few GB free disk.
The public echo endpoint must also be reachable from the VPS itself. Acceptance
measures actual VPS echo egress rather than guessing its source IP, accommodating
provider NAT when public-IP hairpin works. Unsupported hairpin produces a clear
failure; it is not treated as route proof.

## Rerun on the already installed Windows/VPS pair

Use elevated PowerShell from the repository root and the existing private bundle
and `$VPS_PUBLIC_IP`, `$SSH_USER`, `$SSH_PORT`. This readiness update adds service
IPC, so rebuild/reinstall the service, preserving credentials and state:

```powershell
git switch codex/network-quality-v1
git pull --ff-only origin codex/network-quality-v1
if ($LASTEXITCODE -ne 0) { throw "git pull failed" }
.\tools\windows\uninstall.ps1
.\tools\windows\setup-e2e.ps1 -Reinstall -VpsPublicIP $VPS_PUBLIC_IP -SSHUser $SSH_USER -SSHPort $SSH_PORT
.\tools\windows\acceptance.ps1 -VpsPublicIP $VPS_PUBLIC_IP -SSHUser $SSH_USER -SSHPort $SSH_PORT
```

MANUAL A/B/C waits up to 60 seconds for service connected, optimizing, capture,
effective temporary selected/control profiles and a **real relay session/open
ACK**, independently of rolling quality. The additive owner-authenticated
`acceptance.readiness` IPC returns the normal snapshot plus `relay_transport`:
connected, flow_open, checked_at and failure reason. It opens/closes one UDP flow
on the current authenticated relay, using only the configured probe destination;
no echo packets, artificial RTT/loss or arbitrary destination probes are sent.
A closed/replaced session cannot certify readiness. Ordinary `status` does not
invent or cache flow-open evidence, and old services need upgrading for this gate.

AUTO D instead has a 135-second total startup/selection budget and requires the
same base/session proof, healthy rolling quality with at least 20 network samples
and 3 rounds, eligible finite score, automatic routing enabled and **natural
optimizer primary VPS-01**. It never forces a winner; a healthy relay losing to
DIRECT remains NOT EXERCISED. Returning to MANUAL after relay restoration uses
MANUAL readiness again.

Polling uses a monotonic deadline with a final fresh check at/after the boundary;
ready evidence at that check passes without requiring three more GUI polls.
A final IPC call can finish beyond the nominal budget (bounded flow-open timeout
3s and IPC timeout). A false final check names backend/profile/transport/quality/
AUTO eligibility blockers. Diagnostics retain both the exact last readiness
snapshot/conditions/mode and a separate current status snapshot, avoiding confusion
when state changes just after timeout.

The concurrent
route proof uses 10 unmeasured warm-up datagrams on the **same PID and UDP socket**,
then 100 measured datagrams at 200ms intervals with 3 seconds final reply grace.
Separate run nonces exclude late warm-up replies from measured statistics.
Warm-up counts/loss remain visible in the reports; measured loss above 10% fails,
and measured traffic is never retried to obtain a pass. Capture counters include
warm-up; exclusive DIRECT/RELAY assertions apply to all captured test traffic.
Actual measured send windows must overlap, not just process lifetimes.

A and B independently require the exact PID/creation time/path/destination,
`observed_sources`, `selected_route`, `relay_id`, `captured_packets`,
`relayed_packets`, `direct_packets`, and `relay_reply_packets`. Truncated capture
proof fails. Existing profiles are retained; temporary profiles have priority and
the readiness check verifies they are effective before sending traffic.

Reports live under `.e2e/reports/<run>-*`: each child has JSON, `.stdout` and
`.stderr`; each failed stage saves status and per-PID capture diagnostics before
restoration. IPC errors are recorded if the service is unavailable. The final
report links child artifacts even when a client returns zero replies. Existing
fault/failover stages remain strict: a naturally DIRECT AUTO winner is still
NOT EXERCISED, so the full suite can fail even when A/B/C pass.

For fresh deployments `.gitattributes` forces LF for shell/Python/systemd files;
setup also normalizes only staged deployment source, protecting older CRLF
checkouts without modifying credentials/binaries. SQL uses explicit standard
strings and doubled apostrophes; password input and generated SQL stay private.

## Evidence and acceptance results

`test-game.exe` and `control-client.exe` are two copies of one ordinary UDP test
program with different absolute executable paths and real PIDs. Neither embeds a
relay client or supplies process metadata to the service. The kernel capture
backend identifies socket owners, executable paths and creation times. Both send
128-byte authenticated sequence/nonce probes to the same public target.

The echo target returns its actual observed source address/port, authenticated by
HMAC-SHA256. Replies are no larger than requests; unknown/bad/reply packets are
rejected and replies are limited to100/s (burst200). This is an authenticated
acceptance target, not an anonymous public echo/reflector or relay proxy.

The service's `capture.diagnostics` IPC method reports real counters:
`captured_packets`, `relayed_packets`, `direct_packets`, `dropped_packets`,
`reinject_packets`, `loop_prevention_packets`, `relay_reply_packets`, plus PID,
absolute executable, creation time, source/destination, selected route and relay.
Global reinjection counts include restored relay replies. Loop-prevention counts
are observed service-origin packets explicitly bypassed by PID, not fabricated
recapture statistics. Payloads/tokens are not logged. Flow evidence is bounded,
expires after5minutes, and is frame-size limited; truncated reports are flagged.

Acceptance prints PASS/FAIL for:

- A: selected exe in MANUAL RELAY, verified capture counters/replies and VPS echo
  egress. This does not depend on GUI status or manufactured RTT.
- B: unselected control exe DIRECT, with a different echo source and zero relay
  counters for its real PID/creation time.
- C: A and B process lifetimes overlap.
- F: service QUIC transport is recognized by its actual PID and bypass counters;
  its packets never enter application relay routing.
- D: AUTO must first actually choose the healthy relay from real measurements;
  stopping the remote relay must yield native DIRECT packets and both egress
  sources within the same application's report. The script waits through normal
  route lifetime/confirmation. If AUTO prefers DIRECT, D is FAIL/NOT EXERCISED;
  it never forces a score or injects synthetic impairment to claim a transition.
- Short control-plane outage: existing authenticated session and valid LKG survive,
  while the control application remains DIRECT. Expired-cache behavior is a
  separate unit-test scope, not an Internet runtime claim.
- E: an active control stream survives graceful service stop and forced process
  termination; SCM recovery restarts capture.
- Driver dependency error: a temporary wrong DLL hash rejects capture, while the
  control stream remains DIRECT. This is validation-failure acceptance, not a
  simulated kernel-driver crash.
- Default routes remain identical.

Reports and per-client metadata are in `.e2e/reports`. Exit0/overall PASS requires
all stages, including D. Any prerequisite failure creates FAIL/NOT RUN entries.
The script restores settings/manifest, removes only its temporary custom profiles,
restarts remote services it stopped, and records restoration failures. It stops
and kills the test service deliberately; use a dedicated test PC.

## Manual runs and operations

```powershell
.\tools\windows\build-e2e.ps1
.\tools\windows\fetch-windivert.ps1
.\tools\windows\start.ps1
.\tools\windows\stop.ps1
.\tools\windows\uninstall.ps1
```

Uninstall removes the neexitlag SCM entry and preserves credentials/driver state
for explicit rollback. It does not remove a shared WinDivert driver.

Explicit upgrade or reinstall on the same dedicated PC, using the existing private
`.e2e/bundle` and the same VPS/owner (elevated PowerShell from the repository):

```powershell
git switch codex/network-quality-v1
git pull --ff-only origin codex/network-quality-v1
.\tools\windows\uninstall.ps1
.\tools\windows\setup-e2e.ps1 -Reinstall -VpsPublicIP $VPS_PUBLIC_IP -SSHUser $SSH_USER -SSHPort $SSH_PORT
.\tools\windows\acceptance.ps1 -VpsPublicIP $VPS_PUBLIC_IP -SSHUser $SSH_USER -SSHPort $SSH_PORT
```

Uninstall waits for SCM deletion and releases its service controller handle. If
another Services window holds deletion pending, close it before retrying. A plain
install still refuses an existing directory; `-Reinstall` explicitly reuses it.
The installer checks matching owner, targets and supplied credential/trust bytes
before mutation. It replaces the service binary/driver, preserves identity,
certificate, trust, valid IPC token and state, and reapplies protected ACLs:
SYSTEM/admins only, GUI owner root traversal/read and IPC token read only.
Mismatched bundles or reparse points are refused; credentials are not silently
rotated or deleted. `install.ps1 -Reinstall` is also available for direct installs
with the same required arguments, after SCM uninstall.

For **harness-only updates**, no service reinstall is needed:

```powershell
git switch codex/network-quality-v1
git pull --ff-only origin codex/network-quality-v1
.\tools\windows\acceptance.ps1 -VpsPublicIP $VPS_PUBLIC_IP -SSHUser $SSH_USER -SSHPort $SSH_PORT
```

Client completion retains the native process handle, performs timed then full
wait and refresh, and requires an actual integer exit code. Report `error` is
optional under StrictMode. Non-zero exits remain failures even if counters look
successful; code and artifact paths are retained. Exit zero still requires real
PID/creation identity, loss consistency/limit and A/B source/capture route proof.
Windows CI exercises actual redirected `Start-Process` completion as well as
reinstall filesystem/ACL operations with SCM mocked; neither is live VPS E2E.

Normal application probing, with service profile deciding its route:

```powershell
.\bin\windows-e2e\test-game.exe -target "${VPS_PUBLIC_IP}:40000" -token-file .\.e2e\bundle\windows\echo.token -count 100 -interval 100ms -report .\.e2e\game.json
.\bin\windows-e2e\control-client.exe -target "${VPS_PUBLIC_IP}:40000" -token-file .\.e2e\bundle\windows\echo.token -count 100 -interval 100ms -report .\.e2e\control.json
```

The program displays destination, sequence, sent/received, monotonic RTT, jitter,
loss and observed echo sources. Comparing the two reports compares actual DIRECT
and RELAY paths. The app never secretly selects a route through its own tunnel.

VPS operations:

```sh
sudo systemctl status neexitlag-control-plane neexitlag-relay neexitlag-echo
sudo systemctl restart neexitlag-relay
sudo systemctl stop neexitlag-relay
sudo systemctl start neexitlag-relay
sudo journalctl -u neexitlag-relay --since '10 minutes ago'
curl --fail http://127.0.0.1:9090/healthz
curl --fail http://127.0.0.1:9090/metrics
curl --fail http://127.0.0.1:9092/metrics
```

TLS control-plane health uses `/etc/neexitlag/control/ca.pem` with curl --cacert.
Metrics bind loopback, not public ingress. CP, relay and echo use separate Linux
users and private file scopes. PostgreSQL listens locally; CA/admin/signing keys
are unavailable to relay/echo users. Relay permits only the test VPS destination
CIDR, enforces mTLS + device-bound tickets and persists its replay cache.
Certificate expiry30days is intentional; production renewal is not implemented.

## Windows boundary and remaining verification

Native code captures outbound unfragmented IPv4 UDP, preserving application
socket tuple in replies. FLOW events provide identity; a unique owner from
GetExtendedUdpTable resolves first-packet races. Both IPv4 and IPv6 ownership
tables are queried because an IPv4 packet can originate from a dual-stack socket.
This does **not** implement IPv6 interception. Ambiguous/unknown/exited identities
remain DIRECT. PID cache checks creation time on hits and has cleanup. Socket/
flow association and capture pins are bounded and idle-cleaned.

The service explicitly bypasses its own PID; reinjected impostor packets are
excluded from the capture filter. Failed relay setup/send/receive switches to
DIRECT by reinjecting original application packets and draining pending payloads.
Existing TCP is never migrated. The TCP/web branch adds transparent IPv4 TCP;
IPv6 relay transport remains unsupported. Selected RELAY datagrams >1472 bytes
are dropped, including the first packet; 1101..1472-byte datagrams use bounded
fragments and require the updated VPS relay. IPv4 IP
fragments bypass interception. These limits must be assessed before real games. Service/driver abrupt failure behavior still
needs actual Windows A–F reports. Linux cannot establish kernel reinjection safety.

After A–F pass, add an absolute `cs2.exe` custom profile through authenticated IPC
with mode AUTO. The routing engine needs no rewrite and no game IP is hardcoded.
The test VPS relay allowlist currently permits only its echo host; enabling other
public destinations is a separate deliberate operator policy change, retaining
mTLS/tickets. No real CS2 session or Internet improvement has been verified.

[Cloud verification and its limits](WINDOWS_E2E_CLOUD_VERIFICATION.md).
