# Control plane MVP

`docker compose up --build -d` is the reproducible development launch.
Standalone binary: `go run ./services/control-plane/cmd/control-plane` with
`DATABASE_URL`, `-signing-key`, `-ca`, `-ca-key`, `-admin-token-file` and optional
`-database-password-file`. Use TLS termination for remote access. See CLI `-help`.
Never put credentials into public command lines or logs.

PostgreSQL 17 (pgx, pool8) stores users, devices, relay nodes, application profiles,
config versions, audit log and auth nonce replay protection. Transactional,
advisory-locked migration is idempotent. No Redis dependency. Default owner and
CS2/Discord/Steam profiles are seeded. This is bootstrap-admin enrollment, not
production multi-tenant user login.

| Endpoint | Authentication / behavior |
|---|---|
| POST /api/v1/auth | Signed device proof → short-lived signed relay ticket |
| GET/POST/DELETE /api/v1/devices | Admin; register certificate or revoke ID |
| GET/POST /api/v1/relays | Read registry; admin writes return a scoped heartbeat token |
| POST /api/v1/relays/heartbeat | Relay-specific token; health/load persisted |
| GET /api/v1/config | Public digitally signed versioned config |
| GET/POST /api/v1/apps | Read profiles; admin writes validated profiles |
| POST /api/v1/telemetry | Admin aggregate ingestion; bounded payload, no packet payload |
| GET /api/v1/version | Supported client/schema version |
| GET /healthz, /metrics | Database health and aggregate Prometheus counters |

Device proofs authenticate by Ed25519 ownership, not bootstrap token. Revoked
devices cannot receive tickets. Registry/profile/revoke operations publish a new
signed config. Heartbeat is normally 30 s; load-driven config publication is
coalesced to >=30 s and config refresh keeps expiry current.
`neexitlag_connected_devices` is explicitly an estimate of non-revoked devices
that authenticated in the last 30 minutes, not live socket inventory. Relay
session/flow metrics describe actual data-plane state.

Test: set VELIQ_TEST_DATABASE_URL to a disposable DB and run
`go test -race ./services/control-plane`. Tests create and drop isolated schemas.
