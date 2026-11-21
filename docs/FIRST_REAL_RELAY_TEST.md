# First real relay test on the existing VPS

Use the existing VPS **2.56.177.4**. No region/server purchase is involved. This
CLI exercises real sockets through the existing relay; it does not replace the
Windows WinDivert per-process acceptance. Local CI is regression evidence, not
an Internet performance result. Root passwords, CA/device keys and tokens must
stay out of Git, shell arguments, public artifacts and reports.

## A. Commands for the existing VPS

Download the successful **Relay release and route test** workflow artifacts for
`codex/real-relay-deployment` (section D). Upload the Linux artifact zip using your
normal SSH client; SSH passwords are entered interactively, never pasted into a
script. The existing SSH port remains unchanged (add `-P PORT`/`-p PORT` if needed).

```powershell
scp .\VELIQ-relay-linux-amd64.zip root@2.56.177.4:/root/
ssh root@2.56.177.4
```

On Ubuntu/Debian, prerequisites and release verification:

```bash
apt-get update
apt-get install -y ca-certificates curl python3 unzip
mkdir -p /root/neexitlag-release
unzip -o /root/VELIQ-relay-linux-amd64.zip -d /root/neexitlag-release
cd /root/neexitlag-release
cat HEAD_COMMIT
sha256sum -c SHA256SUMS
systemctl status neexitlag-relay neexitlag-control-plane neexitlag-echo --no-pager || true
```

If the previous neexitlag deployment is already installed, **reuse its credentials,
control plane and protected client bundle**. Update only the release binary/unit:

```bash
bash deploy/vps/update.sh bin/relay
```

The new unit accepts the old `/etc/neexitlag/public/relay.env` and restricts egress
to its actual `VPS_PUBLIC_IP/32`. It always enables device mTLS and signed-ticket
ALPN. An update does not rotate keys, erase replay state or update PostgreSQL.
It restarts sessions; choose a test window. Failed restart/health restores the
previous binary/unit and reports failure. Keep an older successful artifact if
an operator-initiated later rollback is required.

For the first TCP echo test, update the existing authenticated echo service (UDP
continues working); its service user/token are unchanged:

```bash
install -m 0755 bin/remote-echo /opt/neexitlag/bin/.remote-echo.new
mv -f /opt/neexitlag/bin/.remote-echo.new /opt/neexitlag/bin/remote-echo
install -m 0644 deploy/vps/neexitlag-echo.service /etc/systemd/system/
systemctl daemon-reload
systemctl restart neexitlag-echo
curl --fail http://127.0.0.1:9092/healthz
```

If a control plane is already configured elsewhere, standalone relay installation
uses its enrolled credentials and public signing trust. Prepare a private directory
with **only** `ca.pem`, `server.pem`, `server.key`, `trust.json`, `heartbeat.token`.
The server certificate must cover the actual VPS IPv4; `trust.json` must contain
that control plane's ticket issuer. No signing key or admin token belongs on the
relay. Edit the non-secret env file before running:

```bash
cp deploy/vps/example.env /root/relay.env
sed -i 's@REPLACE_TARGET_IPV4@2.56.177.4@' /root/relay.env
# Set RELAY_CONTROL_PLANE and its trusted CA file if using a different HTTPS CP.
bash deploy/vps/install.sh --relay-only bin/relay /root/private-relay-credentials /root/relay.env
```

If no neexitlag backend is installed yet, use the existing controlled enrollment
workflow on **this same VPS**. Check that `/etc/neexitlag` does not exist first.
Never generate a new bundle over the existing deployment:

```bash
# Provisioning writes private files with 0700/0600, never prints key values.
bin/vps-provision -vps-ip 2.56.177.4 -out /root/neexitlag-private
cp -a bin /root/neexitlag-private/bin
cp -a deploy/vps /root/neexitlag-private/units
bash deploy/vps/install.sh /root/neexitlag-private 2.56.177.4
```

This retains the existing PostgreSQL-backed CP, signed registry, device enrollment,
server/device certificates, device-bound one-use tickets, replay cache and live
revocation architecture. The legacy full-backend installer remains intentionally
fresh-install-only, refusing identity replacement. Relay-only install is repeatable
with identical credentials/env. Explicit config changes are made to the root-owned
env; never overwrite credentials accidentally.

The relay runs as `neexitlag-relay`, with read-only credential access and a private
writable replay/config directory. systemd restarts failures, sends SIGTERM for
shutdown, and enforces its existing graceful shutdown timeout. Logs go to journald;
use the host's existing journald retention/rotation policy. No unbounded log file
is created, and no packet payload/secret is logged.

## B. Ports to open

| Port | Purpose | Exposure |
|---|---|---|
| UDP 4433 | Ticket-authenticated QUIC relay; carries UDP and TCP flows | Windows test source / Internet as required |
| TCP 8443 | HTTPS signed config/enrollment/ticket requests | Authorized test client/operator |
| UDP 40000 | Authenticated UDP echo | Test client and relay egress |
| TCP 40000 | Authenticated TCP echo smoke | Test client and relay egress |
| TCP 9090 / 9092 | Relay/echo health and Prometheus metrics | **Loopback only** |
| TCP 5432 | PostgreSQL for the existing CP | **Loopback only** |
| Existing SSH port | Administration | Existing rule; retain it |

TCP 4433 is not required: the relay TCP payload runs inside QUIC over UDP 4433.
For already enabled UFW, the minimum controlled-test ingress rules are:

```bash
ufw allow 4433/udp
ufw allow 8443/tcp
ufw allow 40000/udp
ufw allow 40000/tcp
```

Prefer `ufw allow from CLIENT_PUBLIC_IP to any port PORT proto ...` for CP/echo
where client addresses are known; include the relay's egress for echo. Apply the
same rules to the provider firewall. Installer scripts do not enable UFW, change
SSH/default routes or flush firewall rules. The target is one explicit controlled
echo endpoint; no Internet scan or open echo/proxy service is introduced.

## C. Relay health

Run on the VPS:

```bash
systemctl is-active neexitlag-relay
curl --fail http://127.0.0.1:9090/healthz
curl --fail http://127.0.0.1:9090/metrics
journalctl -u neexitlag-relay -n 100 --no-pager
```

Health means the relay process/listener is alive, not that Windows/Internet
forwarding, CP enrollment or destination delivery passed. Prometheus can scrape
`http://127.0.0.1:9090/metrics` locally; use SSH forwarding or a separately managed
private network for remote scraping. Never expose private metrics broadly.

## D. Download the Windows test client

Open GitHub Actions → **Relay release and route test** → successful run on
`codex/real-relay-deployment`. Download artifact
`VELIQ-route-test-windows-amd64` (legacy download alias retained), then extract
**`neexitlag-route-test-windows-amd64.exe`** and `SHA256SUMS` into the existing
Windows repository/work directory. No Go installation or driver is needed for
this CLI. Verify the exe hash with `Get-FileHash -Algorithm SHA256` against the
artifact checksum. The matching Linux artifact is `VELIQ-relay-linux-amd64` (legacy alias retained).

Use the already enrolled `.e2e/bundle/windows/device` and existing out-of-band
trust/echo token. **Do not copy server CA signing keys into Windows test state.**
If starting the controlled workflow above for the first time, copy only
`/root/neexitlag-private/windows` from VPS to `.e2e/bundle/windows`. Protect this
private client directory using the current Windows user's SID:

```powershell
$private = (Resolve-Path .\.e2e).Path
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls $private /inheritance:r /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
```

For explicit first enrollment, supply the bootstrap token **file** once. Existing
identity/certificate files are reused; the CLI never overwrites an existing cert:

```powershell
.\neexitlag-route-test-windows-amd64.exe --relay 2.56.177.4:4433 --target 2.56.177.4:40000 --control-plane https://2.56.177.4:8443 --enroll-token-file .\.e2e\bundle\windows\admin.token --count 30 --report .\.e2e\reports\enrollment-test.json
```

After successful enrollment, remove this private bootstrap token copy from the
Windows test state; it is not a normal benchmark credential. Existing Windows
setup already performs that cleanup. Keep the device identity/cert, trust and echo
token protected. The CLI verifies HTTPS CA, signed config, exact relay ID/address,
certificate/key match and requests a fresh device-bound ticket for each session.

## E. DIRECT vs RELAY benchmark and Internet smoke

Run from Windows **outside the VPS**. Ensure `neexitlag-route-test*.exe` is not
itself covered by an AUTO/MANUAL WinDivert profile (use DIRECT or stop the routing
service for this standalone socket benchmark). Defaults use the existing private
`.e2e/bundle/windows` paths; override `--state`, `--trust`, `--ca`, `--cp-ca` and
`--echo-token-file` if needed.

```powershell
.\neexitlag-route-test-windows-amd64.exe --relay 2.56.177.4:4433 --target 2.56.177.4:40000 --control-plane https://2.56.177.4:8443 --count 100 --report .\.e2e\reports\real-route.json
```

UDP routes are probed in paired concurrent rounds. Every result comes from an
actual authenticated nonce echo with a timer; stale/bad replies cannot become
successful measurements. Failed probes remain visible; no sample retransmission
is added. DIRECT uses a normal UDP socket; RELAY uses the actual existing secure
QUIC DATAGRAM provider.

Full external smoke adds DIRECT/RELAY TCP authenticated round trips, distinct UDP
observed egress sources, an explicit invalid-ticket rejection and real expiry of
an **unused signed** ticket:

```powershell
.\neexitlag-route-test-windows-amd64.exe --relay 2.56.177.4:4433 --target 2.56.177.4:40000 --tcp-target 2.56.177.4:40000 --control-plane https://2.56.177.4:8443 --smoke --report .\.e2e\reports\real-smoke.json
```

Expiry normally waits about two minutes (max five minutes); the CLI does not forge
an expiry, sign a fake ticket or alter clocks. Authentication timeout/capacity/
unavailability is **NOT** a successful rejection. JSON/stdout contain observations
and errors, never tickets, tokens or private keys. Exit 1 reports actual failure,
including missing UDP replies, TCP timeout, invalid authentication proof or absent
external egress distinction. Ordinary benchmarks preserve nonzero loss rather than
requiring artificial 0%; inspect every loss/error before drawing conclusions.

Linux uses `bin/neexitlag-route-test-linux-amd64` with identical flags and protected
paths. Testing on localhost or from the VPS itself is not final Internet evidence.
For an external target you control, deploy the same authenticated echo there and
explicitly update `RELAY_ALLOW_CIDRS` to that destination before testing. Testing an
echo on the relay VPS proves the Internet relay path, not relay→game-server quality.

To exercise the unavailable error in a dedicated test window, stop **only** relay
and rerun the benchmark from Windows, then restart it:

```bash
systemctl stop neexitlag-relay
# Run Windows benchmark: must fail clearly, never invent RELAY measurements.
systemctl start neexitlag-relay
```

To exercise timeout, temporarily drop echo ingress in the **existing test firewall**
(leave SSH/CP/relay rules intact), rerun a bounded benchmark, then restore that rule.
No replies must remain failed probes with a clear timeout. Automated regression
checks also cover real local socket timeouts and a nonresponding relay; these local
fixtures are not labeled Internet results.

## F. Interpret RTT / jitter / loss

Median/p95 are nearest-rank actual reply RTT statistics. Jitter is mean absolute
variation between successive successful replies. UDP packet loss is unanswered
sent authenticated probes / sent probes; successful/failed/attempted counters are
shown separately from transport-open errors. This is end-to-end echo loss, not a
claim about which hop/kernel/queue dropped it. A lack of samples is unavailable,
not a fabricated zero. TCP smoke is request/response delivery over a reliable
stream; it is not a packet-loss measurement.

Recommendation comes from the **existing optimizer's ranked rolling quality
scores and health eligibility** (60-second window, minimum 20 sent-network samples
and 3 rounds). Sustained loss, bursts and jitter can outweigh a small RTT gain.
No separate RTT-only/fake winner is introduced. CLI recommendation is a measured
ranking snapshot; it does not bypass the service's lifetime/confirmation policy,
change profiles or migrate existing flows. If evidence is insufficient, that is
printed explicitly. Report metrics cover measured probes; ranking uses the current
rolling window and signed relay load, so long/slow runs may have a shorter scoring
sample set.

Compare repeated real runs under similar load and retain JSON plus exact artifact
commit. Lower RTT alone does not prove better game quality. No Internet improvement
is claimed until the external Windows/VPS measurements actually show it.

## G. Completely remove relay from the VPS

Stop/remove only the relay service and executable, preserving credentials/state:

```bash
cd /root/neexitlag-release
bash deploy/vps/uninstall.sh
```

Explicit removal of relay credentials, replay/config state and dedicated user:

```bash
bash deploy/vps/uninstall.sh --purge-relay-data
```

This does not delete the shared CP/PostgreSQL/echo services or unrelated state.
Remove only firewall rules you added specifically for relay (`ufw delete allow
4433/udp` if that was your exact rule); remove temporary echo rules/services only
when no other acceptance uses them. Keep the existing SSH rule. Private setup
bundles/backups under `/root` are intentionally not silently deleted; explicitly
remove the chosen private bundle only when no rollback/test client needs it.
