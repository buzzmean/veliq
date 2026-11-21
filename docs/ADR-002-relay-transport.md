# ADR-002: Relay transport
Choose QUIC via quic-go: TLS 1.3, persistent authenticated sessions, DATAGRAM
for UDP (no retransmission), one bidirectional stream per TCP flow.

| Option | Benefits | Costs |
|---|---|---|
| QUIC | Audited TLS stack, multiplexing, NAT keepalive, unreliable DATAGRAM | Congestion control and packet overhead; benchmark needed |
| WireGuard | Efficient authenticated L3 | Flow/session control and app classification must be added |
| Custom encrypted UDP | Potential small overhead | Replay, key lifecycle, congestion and NAT risks; not justified initially |
| TCP tunnel | Easy network compatibility | Cross-flow head-of-line blocking harms game UDP |

No custom cryptography. Phase 1 uses mutual TLS device certificates; later
short-lived signed tickets must be bound to device key and relay audience.
No UDP-over-reliable-stream fallback. Congestion and bounded queues can drop datagrams.
