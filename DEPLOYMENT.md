# Development deployment

```sh
docker compose up --build -d
docker compose --profile test run --rm dev-client
docker compose -f compose.yaml -f deploy/compose.observability.yaml up -d
```

Optional Prometheus: http://127.0.0.1:9091; Grafana: http://127.0.0.1:3000.
Provisioning mounts a Prometheus data source and a small relay/CP dashboard.
Grafana uses its initial local default login; change it before exposing anything.
Ports bind loopback; no production publishing is performed. Probe metrics are on
an independently running demo at http://127.0.0.1:8099/metrics and can be added to
Prometheus explicitly when that host is reachable. No fake probe series is seeded.

For a managed environment requiring a custom proxy CA, build with:
`docker compose -f compose.yaml -f deploy/compose.managed.yaml build` and set
`BUILD_PROXY_CA_CERT` to the provided CA file path. BuildKit secret injection verifies
TLS without copying proxy credentials or CA into repository/output. Docker runtime
internal destinations use NO_PROXY. Normal developer builds need no override.

PostgreSQL and signing/device/CA secrets live in scoped named volumes. Preserve
volumes across rebuilds. Relay state includes a private replay cache. These are dev
identities and egress rules; production needs HTTPS, durable protected keys,
PostgreSQL backups, explicit destination policy, metrics access control and signed
Windows driver/application distribution. WFP kernel deployment is not supplied.
