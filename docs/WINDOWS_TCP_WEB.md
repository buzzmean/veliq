# Windows TCP and browser acceptance

This branch adds an IPv4 transparent TCP redirector beside the proven UDP path.
It does **not** claim a new real Windows/VPS PASS. Existing UDP E2E results remain
historical evidence; new TCP, HTTPS and browser results require the commands below.
No route scoring, ticket authentication, default route or global DNS setting changes.

## Implementation and boundaries

Outbound IPv4 TCP SYN -> exact GetExtendedTcpTable owner (PID, creation time,
exe path, full tuple) -> existing profile classifier -> existing Engine.OpenTCP
-> device-mTLS/ticket-authenticated relay -> destination. Before reflecting a SYN
into the local TCP listener, the service opens the real relay TCP flow and receives
its destination-open ACK. On opening failure, DIRECT policy reinjects the original
SYN unchanged. BLOCK-on-failure suppresses it. No application payload is replayed.
The listener response is reflected back with the original destination tuple.
Only IP/port headers/checksums change; Windows owns TCP sequence/ACK/retransmission,
TLS, HTTP/2, WebSocket and application data pass unchanged. Requests and destination observations are nonce-bound HMAC-SHA256 authenticated;
the shared token is never sent, including the plaintext HTTP test. No MITM or certificate
substitution. Loopback IPv4 and unknown process identities bypass; service-owned
sockets bypass even if a profile names the service executable.

All packets of an existing TCP connection keep its decision. A broken established
relay connection closes; its next connection can use DIRECT. Seamless migration of
an established TCP connection across egress IPs is not possible. Service stop/crash
releases capture handles; **new** connections are DIRECT; active proxied connections
can reset. This is connection fail-open, not preservation of live TCP streams.

Limits: 8192 total TCP mappings (DIRECT entries included), 128 concurrent opens,
5s opening deadline, 20s orphan-open expiry, 2min DIRECT idle, 15s unaccepted relay expiry, 2h accepted relay idle,
4min closed virtual-port quarantine; active entries never evicted for capacity.
Each relay connection uses bounded QUIC windows and two 32KiB copy buffers.
The internal listener admits only exact reflected mappings; physical inbound
connections to its port are dropped. It cannot be used as an unauthenticated proxy.
Saturation follows DIRECT/BLOCK failure policy. Cleanup closes both sockets.

Diagnostics add protocol/IP version and bytes. TCP `captured_packets/bytes` and
`direct_packets/bytes` count outbound original IP packets/bytes; `relayed_packets`
counts reflected outbound packets, `relay_reply_packets` reflected listener replies;
`relayed_bytes/relay_reply_bytes` count successfully copied stream payload bytes.
TCP read boundaries are **not** counted as packets. UDP counters retain packet
semantics and now include byte evidence. Capture does not parse TLS, so the GUI
never infers HTTPS success from port 443 or QUIC success from UDP/443.

### UDP/QUIC

The old 1100-byte budget could not carry QUIC's >=1200-byte Initial. Small payloads
still use the exact v1 datagram encoding. Payloads 1101..1472 use two canonical v2
QUIC DATAGRAM fragments with per-session packet sequence, length and offset.
Reassembly allows at most 64 incomplete packets/session, <=1472 bytes each, fixed
2s lifetime, reordered fragments, no retry/FEC or reliable stream substitution.
Loss of one fragment means loss of the packet. Invalid fragments are rejected.
**Update the VPS relay and Windows service together** before testing QUIC; older
relays accept small v1 traffic but cannot decode v2 fragments. This is not negotiated
as a new capability. IPv4 fragmentation/jumbograms and payloads >1472 remain
unsupported; oversized selected RELAY datagrams are dropped, never silently DIRECT.
No Internet performance improvement is claimed. Local nested HTTP/3 through the
real authenticated relay is a regression test, not public-Internet acceptance.

### DNS and IPv6

Windows DNS Client queries may originate from `svchost.exe`, rather than the browser.
They remain DIRECT; never select/redirect the shared DNS service. Browser-owned
DoH follows its TCP/UDP profile. DNS cache can mean no new DNS packet. No blanket
DNS privacy guarantee or application-aware DNS service is implemented. Browser
acceptance stores Chromium's default-redacted netlog and a DNS event summary;
inspect host-resolver/DoH events for your chosen browser. A DNS lookup by the
acceptance harness is **not** attributed as browser DNS evidence.

IPv6 relay transport is **unsupported**, not advertised as supported. A separate
NETWORK handle suppresses attributable new selected RELAY/BLOCK IPv6 TCP/UDP flows,
without redirecting them into IPv4. Other IPv6 traffic passes unchanged. SOCKET
handles are **sniff/receive-only** to observe identity before SYN; WinDivert cannot
reinject socket events. The guard does not block IPv6/dual-stack socket bind.
It accepts bounded extension chains, rejects fragments/jumbograms as unsupported,
and pins existing TCP midstream to DIRECT. Unknown identity, unsupported packets,
state saturation and pre-existing flows follow the existing fail-open policy.
Consequently this is **not a leak-proof IPv6 guarantee**. Restart the selected
browser after enabling its profile. Driver lifecycle and ordinary IPv4/IPv6
loopback passthrough are native regressions, not an external IPv6 relay PASS.
GUI reports unsupported/blocked packet evidence honestly.

## 1. Update without discarding enrolled credentials

From an elevated Windows PowerShell in the checkout (service briefly stops):

```powershell
git fetch origin
git switch codex/windows-tcp-web
git pull --ff-only origin codex/windows-tcp-web
.\tools\windows\build-e2e.ps1
# Preserve service.json, token, device keys, trust and ACLs:
.\tools\windows\uninstall.ps1
.\tools\windows\setup-e2e.ps1 -VpsPublicIP 2.56.177.4 -SSHUser root -SSHPort 22 -Reinstall
```

Setup reuses the existing deployment and credentials. Update the VPS relay binary
separately (do not create a new VPS, reenroll or overwrite the CA):

```powershell
scp .\bin\windows-e2e\linux\relay root@2.56.177.4:/tmp/neexitlag-relay-new
scp -r .\deploy\vps root@2.56.177.4:/tmp/neexitlag-tcp-update
ssh root@2.56.177.4 'bash /tmp/neexitlag-tcp-update/update.sh /tmp/neexitlag-relay-new'
Restart-Service neexitlag
```

Git enforces LF for scripts. `update.sh` checks ELF/health/metrics and rolls back
binary/unit on failure, preserving authentication state.

## 2. Controlled destination on the existing VPS

Upload `bin/windows-e2e/linux/web-test-target` and then run the following on the
existing VPS. The destination test certificate is separate from relay/CP trust:

```bash
sudo install -m 0755 /tmp/web-test-target /opt/neexitlag/bin/web-test-target
sudo install -d -m 0750 -o root -g neexitlag-echo /etc/neexitlag/web-test
sudo sh -c 'umask 077; openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout /etc/neexitlag/web-test/key.pem -out /etc/neexitlag/web-test/ca.pem \
  -subj /CN=neexitlag-web-test -addext "subjectAltName=IP:2.56.177.4" \
  -addext "basicConstraints=critical,CA:TRUE"'
sudo chown root:neexitlag-echo /etc/neexitlag/web-test/*.pem
sudo chmod 0640 /etc/neexitlag/web-test/*.pem
sudo systemd-run --unit=neexitlag-web-test --property=User=neexitlag-echo \
  --property=Group=neexitlag-echo --property=NoNewPrivileges=yes \
  --property=ProtectSystem=strict --property=ProtectHome=yes \
  --property=Restart=on-failure /opt/neexitlag/bin/web-test-target \
  -listen :40080 -tls-listen :40443 -quic-listen :40443 \
  -cert /etc/neexitlag/web-test/ca.pem -key /etc/neexitlag/web-test/key.pem \
  -token-file /etc/neexitlag/echo/echo.token
sudo journalctl -u neexitlag-web-test -n 30 --no-pager
```

First upload from Windows:
`scp .\bin\windows-e2e\linux\web-test-target root@2.56.177.4:/tmp/web-test-target`.
Open TCP40080, TCP40443 and UDP40443 to the Windows public IP and VPS public IP
in the provider and host firewalls. Keep existing UDP4433 relay ingress unchanged.
Do **not** open the internal Windows interception listener. Example UFW rules:

```bash
sudo ufw allow from WINDOWS_PUBLIC_IP to any port 40080 proto tcp
sudo ufw allow from WINDOWS_PUBLIC_IP to any port 40443 proto tcp
sudo ufw allow from WINDOWS_PUBLIC_IP to any port 40443 proto udp
sudo ufw allow from 2.56.177.4 to any port 40080 proto tcp
sudo ufw allow from 2.56.177.4 to any port 40443 proto tcp
sudo ufw allow from 2.56.177.4 to any port 40443 proto udp
```

For standard-port acceptance use `-tls-listen :443 -quic-listen :443`, add only
`AmbientCapabilities=CAP_NET_BIND_SERVICE` to the transient service, and substitute
443 in the rules and URL. Do not replace a service already listening on 443.
The signed relay destination allowlist must already include the controlled target
(the existing VPS /32 deployment does); never turn it into an open proxy.

## 3. Simultaneous HTTP/TLS/HTTP2/WebSocket acceptance

```powershell
scp root@2.56.177.4:/etc/neexitlag/web-test/ca.pem .\.e2e\web-test-ca.pem
.\tools\windows\acceptance-tcp-web.ps1 -HttpURL http://2.56.177.4:40080 `
  -HttpsURL https://2.56.177.4:40443 -EndpointCA .\.e2e\web-test-ca.pem `
  -TokenFile .\.e2e\bundle\windows\echo.token
```

No Go installation needed if using the `windows-real-e2e-tools` artifact from this
branch's successful Verify run. Both executables use ordinary sockets, not the
relay API or an explicit proxy. The harness first waits for effective profiles, capture and the real authenticated
relay session/open ACK through existing acceptance.readiness IPC, without waiting
for route quality. This opens/closes a readiness flow and sends no UDP test payload;
it does not repeat historical UDP E2E. TCP destination/route proofs must also pass
during the separate warm-up. Each stage then measures concurrent
selected/control connections against the same endpoint. Every attempt must succeed;
no retry hides failed connections. Proof combines process identity, destination,
actual TLS/HTTP2/WS exchange, endpoint nonce/source, overlap and real capture/byte
counters. JSON alone cannot PASS. Failure retains stdout/stderr, reports, status
and capture diagnostics. Default routes must remain identical. Temporary profiles
and optimization state are restored; private identity/credentials are preserved.

## 4. Chrome/Edge and real DNS/QUIC

Close all processes of the selected browser first. The profile selects the full
executable path, including its network-service child processes. The test launches
an isolated headless profile with CDP bound to loopback, never attaches to personal
browser data. Trust the short-lived **destination** test CA explicitly in the test
Windows user's certificate store (or use an already-trusted destination cert):

```powershell
certutil -user -addstore Root .\.e2e\web-test-ca.pem
$chrome='C:\Program Files\Google\Chrome\Application\chrome.exe'
.\tools\windows\acceptance-browser.ps1 -ChromePath $chrome `
  -URL https://2.56.177.4:40443 -HttpURL http://2.56.177.4:40080 `
  -TokenFile .\.e2e\bundle\windows\echo.token -Mode TCP
.\tools\windows\acceptance-browser.ps1 -ChromePath $chrome `
  -URL https://2.56.177.4:40443 -TokenFile .\.e2e\bundle\windows\echo.token -Mode QUIC
```

TCP mode requires real browser HTTP, HTTPS/HTTP2 and WSS observations with HMAC
proofs and matching destination flow counters. It temporarily disables QUIC only
in that test browser. QUIC mode enables it
and requires an actual HTTP/3 response plus matching UDP relay counters; enabling
QUIC or seeing UDP443 alone is not PASS. Alt-Svc discovery gets six navigations,
without forcing QUIC or a relay winner. If Chromium rejects HTTP/3 with a local
test root, use a controlled DNS name and publicly trusted certificate; do not add
certificate bypass/forced-QUIC flags. Browser default background networking is
suppressed to isolate evidence. No certificate-error bypass is used. For actual
browser DNS behavior, use a controlled hostname resolving to the VPS and a trusted
certificate with that DNS SAN instead of the literal IP. Keep DNS/DoH settings as
used in production; inspect retained netlog events separately. Remove the temporary
root certificate afterwards by its thumbprint, never delete unrelated certificates.

`.e2e/browser/*-proof.json` contains PID/exe/flow/source/protocol evidence and the
DNS event summary; `.e2e/tcp-web/` contains simultaneous app evidence. Inspect netlog
for resolver details; default Chromium redaction is retained. Treat these files as
private. Do not claim browser/DNS/IPv6 PASS until the real Windows run succeeds.

Cleanup: `systemctl stop neexitlag-web-test`, remove only its binary and
`/etc/neexitlag/web-test`, and remove exactly the test firewall rules above. The
existing relay, enrollment and proven UDP deployment remain installed.

## 5. Ordinary websites after controlled acceptance

The old controlled-test allowlist permits only the VPS /32, so ordinary websites
will be rejected by the relay and may follow DIRECT failure policy. That is not
a successful MANUAL browser relay test. After the controlled TCP/browser acceptance,
explicitly opt into the relay's **existing authenticated public-only** policy:

```bash
# Existing VPS: create/replace only the non-secret relay env, not identities.
sudo sh -c 'umask 027; cat > /etc/neexitlag/relay/relay.env <<"ENV"
RELAY_LISTEN=0.0.0.0:4433
RELAY_METRICS=127.0.0.1:9090
RELAY_ID=VPS-01
RELAY_DESTINATION_POLICY=public-only
RELAY_CONTROL_PLANE=https://127.0.0.1:8443
RELAY_CONTROL_PLANE_CA_FILE=/etc/neexitlag/relay/ca.pem
ENV'
sudo chown root:neexitlag-relay /etc/neexitlag/relay/relay.env
sudo chmod 0640 /etc/neexitlag/relay/relay.env
sudo python3 /tmp/neexitlag-tcp-update/validate-env.py /etc/neexitlag/relay/relay.env
sudo systemctl restart neexitlag-relay
curl --fail http://127.0.0.1:9090/healthz
```

This requires the updated start wrapper/unit from section 1. No
`RELAY_ALLOW_CIDRS` may be present in public-only mode. Device mTLS, one-use tickets,
audience checks and replay protection remain mandatory. The existing relay policy
blocks private, loopback, multicast, link-local and reserved destinations. No
unauthenticated proxy is enabled. Restore `RELAY_DESTINATION_POLICY=cidrs` and an
explicit limited allowlist to return to controlled-only testing.

Restart the Windows service to reconnect, select the full Chrome/Edge executable
path in Applications, MANUAL -> VPS-01, then restart that browser to create fresh
connections. Other applications without profiles remain DIRECT. Browser DNS and
IPv6 limitations above still apply; confirm TCP/UDP flow route and egress source
rather than assuming the profile alone proves relay routing.
