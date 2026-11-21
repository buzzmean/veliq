# PostgreSQL control plane

Implemented Go HTTP MVP with persistent device/relay/profile/config/audit state,
Ed25519 device proofs, tickets, signed configs and scoped relay heartbeats.
[API and standalone launch](../../CONTROL_PLANE.md); [Docker dev](../../DEPLOYMENT.md).
The data plane verifies tickets locally and never forwards through this component.
