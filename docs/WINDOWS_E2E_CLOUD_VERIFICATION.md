# Windows E2E preparation: cloud verification

Linux x64, Go1.25.1, PowerShell7.4.6, actual PostgreSQL17.
No real Windows runtime or operator VPS was available **in cloud**. The operator
has since confirmed manual simultaneous per-process DIRECT/RELAY on Windows;
see [reported evidence and exact rerun](WINDOWS_REAL_E2E.md). The updated automated
suite has not been executed against that Windows/VPS pair here.

| Check | Result / actual scope |
|---|---|
| go build ./... | PASS |
| go test -race -count=1 -timeout 120s ./... | PASS with PostgreSQL URL supplied |
| go vet ./... | PASS |
| Windows amd64 CGO0 build of all Go packages | PASS |
| Windows vet of platform/service packages | PASS |
| Windows discovery/UDP owner test executable | Compiled; not executed on Linux |
| build-e2e.ps1 | PASS, produced five Windows executables and four Linux binaries |
| PowerShell syntax | All published setup/acceptance/service/test scripts PASS |
| Actual PowerShell IPC client | Linux .NET fixture: framed round-trip, bad ID and bounded timeout PASS |
| VPS shell installer | bash -n PASS; not executed against a remote host |
| systemd units | systemd-analyze verify PASS in isolated dependency/executable fixtures |
| Official WinDivert download | Archive and DLL/SYS SHA256 verified; PE signature-table structure inspected |
| Original tools/lab | Actual local UDP/TCP E2E PASS |
| Real Windows A–F | NOT RUN |
| Public-Internet relay/echo | NOT RUN |
| Real CS2 | NOT RUN |

The new integration test actually runs PostgreSQL APIs, private-CA HTTPS device
registration, signed config/ticket issuance, mTLS QUIC relay and authenticated
nonce echo over both DIRECT and relay transports. It then validates persisted LKG
with the HTTP server stopped. It deliberately asserts that this portable transport
alone does not advertise Windows capture as connected.

Other tests cover PID reuse/cache expiry, wildcard/shared-port ownership,
IPv4-mapped/dual-stack ownership parsing, service-PID exclusion and counter-ledger
cleanup, echo authentication/reply rejection/observed source, actual ordinary UDP
client RTT/loss and temporary profile removal without deleting default profiles.
Windows-specific tests use real current-process discovery and actual sockets;
only their compilation was checked here. CI can run those without a driver, but
that still cannot substitute for administrator-run public-Internet acceptance.

A new IPC fixture caught an AsyncWaitHandle ownership error in the PowerShell
client; removing disposal of framework-owned cached handles resolved it, and all
three scenarios subsequently passed. The new service-LKG integration fixture
initially checked an uninitialized helper cache; it now loads and checks the
actual signed cache persisted by the service. These were resolved before the
final regression. No saved report is represented as a Windows runtime PASS.

## Deployment / acceptance reproducibility fixes

The full Go race suite with PostgreSQL17, go vet and Windows amd64 cross-build
passed again after these fixes. Actual build-e2e.ps1, PowerShell parsing and the
existing framed-IPC round-trip/rejection/timeout fixtures passed.

Additional regression checks:

- Python deployment tests: core.autocrlf=true checkout still produces LF shell,
  Python and systemd source; bash -n passes on the exported installer. Password
  generation preserves quotes, backslashes, injection-shaped text and newlines.
- Actual PostgreSQL: execute generated SET/CREATE ROLE/CREATE DATABASE and then
  authenticate with the exact password for five special-character cases.
- Actual loopback UDP socket: retain the same source socket across warm-up and
  measurement; discard late warm-up nonce replies; deliberately lost measured
  packets remain in measured loss.
- PowerShell regression fixtures: reject wrong routes, relay IDs, counters,
  recycled PID creation times, truncated proof and excess/inconsistent loss;
  retry transient startup IPC and require three stable readiness snapshots;
  retain status/capture/report/stdout/stderr for zero-reply failures and client
  artifact paths even when IPC is unavailable; reject nonoverlapping measured
  windows. Staged CRLF source is normalized while binary bytes are unchanged.

These tests exercise the published functions, SQL generator and ordinary socket
client; they do not create a real Windows PASS report. No GUI changes were made.
