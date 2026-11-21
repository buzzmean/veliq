# Relay

`go run ./tools/lab` starts the original ephemeral mTLS UDP/TCP lab.
`docker compose up --build -d` starts the ticket-required development relay.
For a standalone ticket-required relay:

```sh
go run ./services/relay/cmd/relay -cert server.pem -key server.key -ca devices-ca.pem -relay-id FRA-01 -ticket-keys trust.json -replay-cache PRIVATE-STATE/replay.json -control-plane https://YOUR-CP -heartbeat-token-file heartbeat.token
```

`trust.json` maps trusted key IDs to raw-url-base64 Ed25519 public keys, provisioned
out of band. Missing identity/key/replay state errors fail closed for ticket auth.
Optional legacy mTLS-only mode remains compatible with Phase 1 tests; production
should supply ticket flags. Never expose the echo/lab allowlist publicly.

Listener UDP :4433; health/Prometheus 127.0.0.1:9090. Default policy rejects private,
loopback, link-local and special destinations. Use explicit `-allow-cidrs` and
host firewall policy for deployment. Session limit128, flows/session64, bounded
QUIC windows/queues, packet token bucket2000/s and idle cleanup remain in place.
Ticket replay persistence survives restart. Auth lease30min preserves existing
TCP beyond ticket issuance expiry while bounding offline authorization.
Signed config/revocations are refreshed outside forwarding; heartbeat uses an
independent scoped token. The CP is absent from the packet path.

Metrics: active_sessions, active_flows, udp_packets_total, tcp_connections_total,
rx_bytes_total, tx_bytes_total, packet_drops_total, rejected_flows_total,
auth_failures_total, relay_health (running exporter; remote reachability is measured
by client probes). Probe latency/health are exported by the demo on port8099.
Production DDoS infrastructure and Internet performance acceptance remain pending.
