# Windows networking

ADR-001 remains authoritative: production WFP ALE/callout boundary, temporary
WinDivert v2 integration. Source now implements process discovery, PID reuse
protection, FLOW-to-NETWORK associations, IPv4 UDP interception/reinjection,
SCM service hosting and authenticated owner-scoped named-pipe IPC.

It does not implement transparent TCP/IPv6 or the WFP kernel driver. Unsupported
or unknown traffic stays DIRECT. No global route/adapter changes are made.
Graceful stop drains and reinjects; abrupt service/driver fail-open still needs
real Windows verification. Cross-compilation cannot establish driver safety.

See [backend details](platform/windows/README.md), [IPC](docs/IPC.md),
[install/run](README.md) and [runtime acceptance matrix](docs/BLOCKERS.md).
