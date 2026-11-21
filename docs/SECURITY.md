# Threat model and current controls

TLS 1.3 mTLS verifies relay CA/hostname and device keys. Ticket-required deployments
use ALPN neexitlag/2 and a first-stream signed Ed25519 ticket bound to the client
certificate public key and relay audience. Tickets normally expire in 2 minutes;
expiry limits new authentication, not existing TCP lifetimes. Sessions have a
30-minute lease. There is no 0-RTT or control-plane call per application packet.
Relay uses expiry-checked bounded replay IDs and optional persistent atomic private
replay state; production CLI enables it. Persistent capacity 512 fails closed when
full. Device proofs also have time bounds and PostgreSQL nonce replay protection.

Signed config envelopes use Ed25519 with separate ticket/config domain prefixes.
Trust keys are provisioned out of band. The client rejects signature errors,
expiry, rollback and same-version equivocation, stores signed LKG atomically, and
uses only a still-valid LKG during outages. Config expires in 24 h by default.
Revocations reach relays via signed-config polling (30 s); established sessions
check live revoked state. Outages delay new revocations, bounded by session lease.

Rotation: provision new public trust key alongside old key to clients/relays,
switch signer/key_id, wait beyond all old ticket/config/session lifetimes, then
remove old trust key. The signed public_keys field does not automatically expand
trust. Tests exercise overlap, retirement, tampering and persistent replay restart.

Control plane bootstrap administration uses a random >=24-character secret;
relay heartbeat tokens are independent, scoped and stored as SHA256 hashes.
Device private seeds persist only in private local files. Windows installer ACLs
protect service identity, manifest, trust, state and driver files. Loader requires
trusted SHA256 pins and signed SYS Authenticode validation and restricts DLL search.
IPC owner/token authentication, timestamps, replay limits and bounded frames keep
networking privilege out of the GUI. Optional publisher/signature profiles do not
match when verification data is absent.

Destination IP policy prevents special/private egress by default; dev/lab override
is explicit. Flow/session/window/queue/probe limits, rate limits, timeouts and
cancellation bound resources. Logs exclude payloads and secrets. Telemetry endpoint
is admin-authorized MVP ingestion, not a device monitoring pipeline; it accepts
aggregate counters only. API metrics count accepted submissions, not invented data.

Relays see application payload at egress; applications still need end-to-end
crypto. Hostile local administrators, stolen bootstrap/private keys, public DDoS,
production onboarding, signed updater delivery, kernel-driver review and full
security audit remain outside current verified coverage. Use HTTPS and managed
key storage/firewall controls in production. Local Docker CA/HTTP are dev only.
Short fuzz smoke tests are not a security audit.
