# Напрямую+ (DIRECT+) — controlled Windows test

DIRECT+ v2 добавляет composable chains, handshake-gated old-sequence fake TLS, bounded QUIC fallback и Discord/YouTube presets. Актуальные возможности/ограничения, real-app tester и точные update/REAL TEST команды: [DIRECT_PLUS_V2.md](DIRECT_PLUS_V2.md). Ниже сохранён v1 controlled acceptance; его строгие проверки не ослаблены.

Experimental, disabled by default. Base UDP E2E previously passed on the user's real Windows/VPS. This change does not repeat or revoke that proof. New local strategies have portable tests/native CI, but no claim of real ISP bypass, Internet speedup, anti-cheat compatibility or external DIRECT+ Windows PASS until these commands produce evidence.

## Install/update and capture architecture

Use the Windows service and GUI artifacts from this PR's successful Verify run. Preserve the existing credentials/ProgramData ACL and use the existing explicit `install.ps1 -Reinstall` workflow documented in WINDOWS_TCP_WEB.md; update service binary only after stopping the service. No changes on VPS are required for DIRECT+ itself. RELAY comparison uses the existing authenticated VPS-01 session and existing controlled target allowlist.

Do **not** run winws/GoodbyeDPI alongside VELIQ. We add no NETWORK handle: current TCP/UDP filters feed local transforms after PID/exe classification. Own-service, unprofiled and unsupported packets remain native DIRECT. GUI stays asInvoker; launching the optional explicit controlled tester opens a separate elevated PowerShell window. No game code injection, memory reads or hooks.

DIRECT means native Windows routing, which can be Happ/VPN. Do not call its observed address a physical ISP address without external proof. Existing physical-adapter VPS host route is only inspected, never edited. Diagnostics include adapter/address/network profile, default/split routes and VPS /32, DNS, WinHTTP proxy (service-account context), DoH configuration presence, heuristic VPN and process/module conflicts. HKCU/browser proxy/DoH, arbitrary anti-cheat drivers and every WinDivert consumer cannot be exhaustively attributed. Inaccessible modules/unknowns are not a clean bill of health. Known conflicts suspend DIRECT+ and new selected decisions fail open; existing TCP sessions remain pinned.

## Three mechanisms

- `tcp-split-1`: two ordered segments at payload offset 1.
- `tcp-split-5`: two ordered segments at offset 5.

The same TCP mechanism accepts data-driven `strategy="tcp-split", split_position=1..512`. The named variants are presets; adding offsets, targets or cutoffs requires config changes, not an engine rewrite.

- `udp-fragment-24`: two fragments of one IPv4 UDP datagram, first fragment body=24 bytes, unchanged UDP payload/checksum. Experimental: deliberately clears DF; middleboxes may drop fragments. No retransmission/reliability/fake payload.

TCP sequence space, encrypted data, endpoint and TLS trust stay unchanged. No CA is installed by DIRECT+. A controlled self-signed HTTPS endpoint may need its existing `-EndpointCA` file for test-client certificate verification, as in the earlier harness; that is not a MITM CA. Normal browser sites use normal browser trust.

Only complete unfragmented IPv4 with a 20-byte IP header and <=1500-byte packet is transformed. TCP SYN/FIN/RST/URG payload, malformed options, TCP-MD5/AO/MPTCP, IP options/fragments, UDP ID=0, IPv6 and oversized/offloaded packets pass through. UDP domain/SNI matching is rejected: use explicit IP/CIDR. No QUIC/STUN payload templates, QUIC decryption, fake packets or global game-port ranges. Fragmented TLS ClientHello/ECH has no domain attribution; domain-only or unknown domain exclusions pass through. Explicit IP scope can work without a visible domain. No IPv6 relay/bypass support is added; prior guard limitations remain.

## Profile model and GUI

«Локальные стратегии» supports enable/disable, finite strategy selection, exact executable path, ports, domain/IP includes and excludes, add/replace/remove, metrics and launching tester. Load before editing; save publishes the full validated snapshot. Select an application under «Приложения» and choose «Напрямую+» explicitly. Games remain unmodified by default; unknown destinations are not learned automatically. «Auto Strategy» sets the selected application to AUTO, which requires scoped successful tester evidence. The TCP tester uses its own ordinary socket application and does not transfer results to Chrome or games.

Authenticated owner-only IPC:

- `local.get`, `local.set`: version 1 config; separate `builtin` (reserved empty) and `user` arrays.
- `local.metrics`: actual inspection/modification counters.
- `local.network`: timestamped read-only context/fingerprint.
- `local.record`, `local.recommend`: scoped measured evidence / finite recommendation. They accept reports from the explicitly invoked controlled tester, not passive claims of browsing success.

Example from an elevated PowerShell in repository root (change target to an existing controlled public endpoint allowed by VPS; do not use documentation addresses for runtime acceptance):

```powershell
. .\tools\windows\common.ps1
$TargetIP = '2.56.177.4' # existing controlled web-test-target on the existing VPS
$Exe = (Resolve-Path .\bin\windows-e2e\tcp-selected.exe).Path
$Rules = @()
foreach ($s in @('tcp-split-1','tcp-split-5')) {
  $Rules += @{id=$s;name=$s;version=1;application=$Exe;protocol='tcp';ports=@(40080,40443);domains=@();ips=@($TargetIP+'/32');exclude_domains=@();exclude_ips=@();strategy=$s;cutoff=2;priority=10;enabled=$true}
}
Invoke-ServiceIPC 'local.set' @{version=1;enabled=$true;builtin=@();user=$Rules}
```

`application` is an exe identity, not an unrestricted glob. A bare exe matches basename; full paths are recommended. Domain syntax: `example.org` exact, `*.example.org` children only. CIDR supports native IPv4/IPv6 set matching, but packet transform support remains IPv4. Exclusions override includes and other rules for the same app/protocol/port. At most 32 profiles / 24KB config, 256 entries per set, 32 ports, cutoff 1–8 initial outbound payload packets. No /0, no remote unsigned updater, no disk I/O or DNS lookup in packet path. Config lives separately in protected ProgramData/local-strategies.json; no secrets belong there.

## Exact controlled Windows rerun

Keep the existing VPS target/token/endpoint CA from WINDOWS_TCP_WEB.md; no new VPS is needed. If using artifact extraction, pass `-Binaries` explicitly to its root or use packaged tools/windows scripts that detect the adjacent executables. Retain all `.e2e` reports privately (they contain metadata, not TLS payload/token).

```powershell
$ErrorActionPreference = 'Stop'
git fetch origin
git switch codex/direct-plus-flowseal
git pull --ff-only origin codex/direct-plus-flowseal
# With Go installed, otherwise download windows-real-e2e-tools from this PR:
.\tools\windows\build-e2e.ps1

# Elevated PowerShell: replace ONLY the installed service executable.
# Existing credentials, service config, local strategies and ACL stay in place.
$replacement = (Resolve-Path .\bin\windows-e2e\neexitlag-service.exe).Path
$svc = Get-CimInstance Win32_Service -Filter "Name='neexitlag'"
if ($null -eq $svc) { throw 'neexitlag service is not installed' }
if ($svc.PathName -match '^"([^"\r\n]+)"') { $installed = $Matches[1] }
elseif ($svc.PathName -match '^(\S+\.exe)(?:\s|$)') { $installed = $Matches[1] }
else { throw 'Cannot safely parse service executable path' }
Stop-Service neexitlag
(Get-Service neexitlag).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
Copy-Item $replacement $installed -Force
Start-Service neexitlag
(Get-Service neexitlag).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))

# Repeat the reported HTTP acceptance (same existing token):
.\tools\windows\acceptance-direct-plus.ps1 -URL 'http://2.56.177.4:40080' -TokenFile '.\.e2e\bundle\windows\echo.token'

# Three ordinary apps at the same external endpoint, simultaneous windows:
.\tools\windows\acceptance-direct-plus.ps1 -URL 'http://2.56.177.4:40080' -TokenFile 'C:\secure\echo.token'
.\tools\windows\acceptance-direct-plus.ps1 -URL 'https://2.56.177.4:40443' -TokenFile 'C:\secure\echo.token' -EndpointCA 'C:\secure\web-ca.pem' -Strategy tcp-split-5
# Separate UDP real fragmentation/reassembly proof (uses current authenticated echo):
.\tools\windows\acceptance-direct-plus-udp.ps1 -Target '2.56.177.4:40000' -TokenFile 'C:\secure\echo.token'
# Same finite UDP comparison through tester entrypoint:
.\tools\windows\strategy-tester.ps1 -UDPTarget '2.56.177.4:40000' -TokenFile 'C:\secure\echo.token'

# Finite TCP DIRECT / both configured strategies / authenticated RELAY comparison:
.\tools\windows\strategy-tester.ps1 -URL 'https://2.56.177.4:40443' -TokenFile 'C:\secure\echo.token' -EndpointCA 'C:\secure\web-ca.pem'
```

A=tcp-plus.exe/udp-plus.exe uses DIRECT_PLUS; B=tcp-control.exe/control-client.exe DIRECT; C=tcp-selected.exe/test-game.exe RELAY. Harness requires real process identity including creation time, exe/destination, selected_route/relay_id, captured/direct/relayed/reply packet+byte counters, actual signed endpoint-observed source, application success and overlapping windows. TCP requires every measured connection successful; UDP retains measured loss and uses existing <=10% acceptance limit (zero replies always FAIL). Warm-up never replaces measured results. Failure keeps report, stdout/stderr, status and capture. Route-table drift fails TCP acceptance rather than silently modifying routes. The tester reports FAIL if no actual transform is observed, even if ordinary HTTP succeeded. Packet loss means failed application probes here, not inferred IP loss or ICMP.

## Chrome / DNS / QUIC

Create an explicit full chrome.exe application profile in DIRECT_PLUS mode; add only intended domains (visible complete Host/SNI) or explicit destination CIDRs/ports under local strategies. Close existing connections and open new ones. Do not import the tester exe's cache into Chrome. No system DNS rewrite: selected browser DoH is ordinary classified traffic; system DNS service stays unchanged. Secure DNS availability and actual browser behavior require browser netlog / prior browser harness, not a guessed DNS success flag.

Test TCP/HTTPS first; optionally use an isolated Chrome launch with `--disable-quic` solely for TCP diagnosis, then run a separate normal QUIC-enabled session. UDP/443 alone is not QUIC proof. For controlled HTTP/3 use the prior browser harness/netlog and actual HTTP/3 response evidence, plus an explicit UDP IP strategy. This MVP does not automate learned browser/QUIC strategy scoring. Do not claim Flowseal fake/STUN compatibility from IPv4 UDP fragment tests. No default-route changes, no full-device strategy, no automatic CA installation.

## Learning / failure / metrics

UDP A/B/C comparison is report-only: different probe exes never share learned cache, and temporary config is restored. TCP tester uses the same exe for every trial and can populate its own cache.

Cache is volatile, bounded to 1024 targets × 8 variants, TTL 15min (AUTO additionally requires quality evidence <=90s old), quarantine after 3 reported failures for 5min. Key includes network fingerprint, config digest/schema, normalized full application, destination:port and protocol. Network observation refreshes every 30s; detected changes invalidate old cache, but there is a detection interval. Test result submission rejects a network fingerprint change. Changed config invalidates prior recommendations. Repeated failed variants are blocked by engine guard for that target/network; unknown runtime HTTPS failures cannot be automatically inferred from encrypted packets. Rerun controlled testing rather than silently treating a sent packet as successful browsing.

Existing optimizer.Score evaluates actual RTT/jitter/loss/failure/stability, with only a 5ms equivalent RELAY cost tie-break. Fresh healthy target DIRECT wins. No scoped evidence -> existing AUTO stays unchanged. Global good echo quality does not prove a specific destination works. AUTO never performs infinite candidate tests on game traffic.

Inspection counts only eligible initial payload packets; successful modified/extra counts commit after injection. Capture `direct_plus_packets/bytes` count only original outbound IP packets/bytes whose transformed outputs were all successfully reinjected (one original counts once, even when split into two). Unchanged SYN/ACK/FIN, unsupported packets and post-cutoff pass-through count in `direct_packets/bytes`, including after a successful transform. `selected_route=DIRECT_PLUS` records actual successful use during the current flow, persists across these native packets or later fail-open, and retains the successful strategy/domain; it does not promise every packet was modified. Before the first completely successful transform, fail-open remains DIRECT with zero modification counters. DIRECT+ never adds relay counters. A new TCP connection, including reuse of the same process/tuple with a new SYN sequence, resets flow evidence but preserves lifetime totals. Flow counters/route/strategy/domain publish atomically. Acceptance still requires DIRECT_PLUS and positive modification packet/byte counters for **every** independent connection, not just positive totals.

The separate engine `local.metrics.bytes_direct_plus` is a flow-usage metric: original outbound bytes from the first successful transform onward while its strategy state remains applied, including unchanged ACK/FIN/cutoff pass-through. It is not the capture modification counter, relay tunnel overhead or response download bytes. `relay_savings_measured=false`; `bytes_relay_avoided` remains 0/unknown without a measured counterfactual. GUI says savings unmeasured. No payload/TLS contents are logged. CPU/performance numbers below are microbenchmarks, not Internet claims.

```sh
go test -race ./core/localstrategy ./platform/windows ./services/client-service
go test ./core/localstrategy -run '^$' -bench . -benchmem -count=3
go test ./core/localstrategy -fuzz FuzzPacketParser -fuzztime 10s
```

Per-packet CPU (ns/op), allocation bytes and allocs/op are emitted as a CI artifact. Throughput=1e9/ns per single CPU benchmark. DIRECT baseline is a minimal local dispatch; RELAY packaging is benchmarked separately, not equated to full QUIC encryption/network/driver overhead. Real comparative CPU/memory/pps and ISP effectiveness need a Windows runtime with the same workload and external target; no claim DIRECT+ beats relay in every workload.

Local preparation benchmark (2026-10-14, Linux amd64, Xeon 8573C, 1000-byte TCP payload; three runs): DIRECT dispatch 1.8–2.4ns/0 allocs, initial DIRECT+ 2.7–3.0µs/1376B/9 allocs, cutoff pass-through 14–16ns/0 allocs; RELAY wire packaging only 0.72–0.79µs/1048B/2 allocs. Initial DIRECT+ is **not** cheaper than packaging alone; the full relay transport/Internet path is outside this benchmark. Two segments/fragments add one packet per transformed input. These are not full Windows capture CPU/RSS/pps measurements. CI publishes fresh benchmark logs per revision.
