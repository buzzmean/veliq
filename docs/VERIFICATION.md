# Phase 3–6 local verification

Environment: Linux x64, Go1.25.1, .NET8.0.425, PostgreSQL17, Docker local daemon,
Chromium + Python Playwright. Original checkpoint and tests retained.

| Check | Result and scope |
|---|---|
| go build ./... | PASS |
| go test -race -timeout 120s ./... | PASS; PostgreSQL test URL supplied, API test actually executed |
| go vet ./... | PASS |
| GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./... | PASS |
| Windows discovery tests cross-compiled | PASS; .exe not executed on Linux |
| Original tools/lab | Real UDP/TCP E2E PASS |
| Short fuzz campaigns | FuzzDecode/FuzzReadOpen/FuzzFrame PASS (5 s, 2 workers); FuzzTicket/FuzzConfig PASS (10,000 inputs each, 1 worker); smoke only |
| Docker Compose backend | Registration, verified config, device-bound ticket, real UDP and TCP through relay PASS |
| WPF .NET8 build | PASS, zero warnings/errors |
| Shared desktop ServiceClient runtime | PASS against real demo: 4 measured routes, 3 profiles, 7 diagnostics |
| Chromium browser smoke | PASS: custom profile, actual relay stop, diagnostics, settings; no JS errors |
| Compose observability config | Validated; example Grafana stack not runtime tested |

Meaningful tests cover scoring examples, threshold/confirmation/freshness,
backup open failure, pinned flows, packet restoration, identity reuse/endpoints,
real nonce echo, overlapping rounds' shared probe budget, cancellation, API
persistence/migrations, scoped heartbeat authorization, crypto tampering/expiry,
rollback/equivocation/LKG outage, ticket binding/replay/revoke/rotation/restart,
local custom profile/settings persistence and IPC version/auth/replay/size bounds.

These results do not verify native WPF rendering, Windows SCM/named-pipe runtime,
WinDivert driver capture, service-crash fail-open, transparent TCP/IPv6, Internet
performance or production scalability/security. GitHub Windows workflow is
configured, but its future result is separate from local cross-build evidence.

One concurrent 5-second extended ticket fuzz run ended with the fuzz coordinator's
`context deadline exceeded`, without a saved crash input. An isolated, iteration-
bounded repeat completed 10,000 ticket and 10,000 config inputs successfully.
Ticket/config harnesses exercise both envelope verification and raw payload parsing.
