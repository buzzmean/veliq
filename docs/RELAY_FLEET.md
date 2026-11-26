# Fleet relay admission

The legacy relay path is the default. On an explicitly enrolled client, fleet applies to new implicit RELAY opens already authorized by routing policy. An explicit ID and address, MANUAL, DIRECT, LOCAL and protected routing keep their policy scope. Every service pool consumes the same client budget in fleet mode. The limits are two QUIC sessions, 47 application flows, one probe flow, 16 waiters and 10 relay echo sends per five-second rolling window. Older live resources count against the limit and finish on their original path. The two selected candidates use authenticated relay echo as transport evidence. The acknowledged target OPEN supplies separate destination evidence.

## Isolated reference setup

- Build the reference client, control plane and relay from the same reviewed source. Pin the actual role, commit, byte size and SHA256 of each test binary. Use loopback for the control-plane fixture, local test trust, an isolated PostgreSQL schema and a dedicated authenticated UDP echo target.
- The client service state directory accepts a protected `fleet-opt-in.json` marker. The marker must explicitly contain `{"scope":"application","application_id":"profile-id"}` for a single application canary, or `{"scope":"all"}` for a separately authorized device-wide rollout. Empty, malformed and unknown scopes cannot admit fleet traffic; a malformed enrolled marker leaves implicit opens fail-closed until corrected. Use the private ACL applied to existing service state. The existing service manifest stays unchanged. A separate `fleet-policy.json` stores the authenticated version floor. A scoped canary leaves other applications on their legacy provider and enforces the old/new egress boundary for the selected application. Signed policy and regular authenticated relay probes still apply to the enrolled device. `relay.fleet.status` reports the effective candidate IDs, occupied budget and bounded failure reason.
- The reference control plane reads a scoped operator bearer from the path in `VELIQ_FLEET_REGISTRY_TOKEN_FILE`. Use the service's credential mechanism and its mode-0600 file. Configure a credential distinct from the legacy administrator bearer. The scoped bearer authorizes the fleet registry endpoint and has no other CP role.
- `RELAY_FLEET_ADMISSION=1` is for the one new fleet-only node. Provide its own ticket audience, pinned HTTPS control-plane CA, mTLS leaf and a dedicated heartbeat credential file. Start the fixture in this mode before registration. A verified policy grants new admission for at most 45 seconds. Keep the node in its existing process while advancing phases.
- Legacy relay measurement can be enrolled through the same registry with `legacy=true`, an existing exact relay ID/address, measured limits and phase `active`. A compatible observer uses `RELAY_FLEET_ADMISSION=observe` alongside the legacy admission path. A legacy node without fresh scoped observations remains in legacy discovery but is ineligible for fleet selection. Treat missing telemetry as unknown. A production legacy node upgrade requires its own approval.
- Check the 715 parser on the original signed v1 response and check signed fleet data on the separate endpoint. Keep real club or production credentials outside the fixture.

## Node operation

Use `deploy/vps/relay-fleet-stage.py` with an explicit plan. Read-only validation is the default. The `--execute` option is for an approved fixture or separately authorized host operation. The local plan and durable journal are owner-controlled. Retain the verified journal on storage independent of the relay and club PC. Use the same immutable plan and operation ID when resuming a step.

| Plan field | Required value |
| --- | --- |
| `schema`, `operation_id`, `node_id` | Schema 1, fresh operation ID, exact new relay audience |
| `address`, `probe_target` | Canonical IP and port for the node and the approved UDP echo target |
| `source_commit`, `artifact_sha256`, `artifact_bytes` | Reviewed source and binary identity |
| `probe_device_ref`, `canary_device_ref`, `pilot_devices` | Dedicated probe device, one entitled canary identity and its authorized cohort of up to ten devices |
| `limits` | Sessions, flows, packets/s, payload bits/s and OPEN/s from measured safe limits, within local relay ceilings |
| `cp`, `relay` | Independent host, port, non-root user, absolute single-host `known_hosts` file, independently checked public Ed25519 fingerprint and separate `identity_ref` environment key |

Provision the fixed helper `relay-fleet-agent.py` and its shared module on the isolated hosts as trusted files. Bind each SSH identity to its role-specific fixed command and disable forwarding, interactive shells and privilege escalation. The CP role reads pinned CA material and the scoped bearer reference. The node role checks the reviewed artifact and provenance manifest, public leaf fingerprint, local key and heartbeat credential permissions. It uses the pinned staged-probe executable and its local mode-0600 test manifest. Put only metadata and credential references in the operator plan and audit journal.

1. Run `prepare` against the scoped helper. Verify artifact size, SHA256, exact source and node trust. Fast staging starts once a scoped host and its independent credentials are ready.
2. Run `stage`. Register the node through version CAS. Wait for the new node to acknowledge its signed staged phase. If the receipt is pending, repeat the same plan and phase. A CAS conflict requires review of the intervening mutation before a new operation.
3. Run `probe`. The dedicated identity must prove mTLS, the relay audience and authenticated UDP echo to the designated destination.
4. Run `cohort` and then `canary`. Stage and verify a viable previous pool before enrolling a device. Scope the new node to the approved canary identity. Confirm its actual relay ID and hold a single linked scenario before considering expansion. Each expansion requires its own authorization and a 30–60 minute observation window.
5. Run `active` only after authorized canary acceptance. Limiting an active fleet deployment to the explicitly enrolled identities remains mandatory.
6. Run `drain` to retire the new node. Verify both new handshake and new OPEN denial while a pre-existing flow renews its authorized lease. Allow up to the heartbeat/refresh windows for a phase to reach the node and clients. Report completion after the acknowledged version is observed.
7. Run `rollback` to remove the new node from selection in a newer signed epoch. If this operation enabled the cohort from legacy mode, rollback publishes signed OFF and preserves the old audience for draining leases. With an already enabled cohort, it drains the node and keeps the previous eligible fleet pool. Preserve active flows, replay cache and the database; verify zero sessions and flows before any separately authorized teardown. A drain timeout leaves the node and active flows intact for review.

The relay reports active sessions and flows, QUIC UDP work, payload bits/s and OPEN/s from process samples. These measurements exclude NIC overhead and monthly outbound accounting. Synthetic 10/40/120 fixtures test assignment and admission invariants. Site capacity, provider quota and real application acceptance require separate measurements.
