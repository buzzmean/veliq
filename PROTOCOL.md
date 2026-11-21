# Relay protocol v1
QUIC ALPN `neexitlag/1`, TLS 1.3 mutual authentication, no 0-RTT.
One persistent connection multiplexes flows. Device CA and server CA are pinned.

Each flow opens a reliable bidirectional stream with a 24-byte OPEN:
version u8 (1), kind u8 (UDP=1/TCP=2), flow ID u32 BE (nonzero),
IP 16 bytes (IPv4-mapped for IPv4), destination port u16 BE (nonzero).
Relay replies status u8 (0 accepted, 1 rejected). No destination DNS resolution;
client resolves to an IP before opening. Control format is fixed binary because
OPEN has fixed fields; unknown version/type is rejected. QUIC is the session ID.

UDP: stream remains open for lifetime. DATAGRAM contains version u8 + flow ID
u32 BE + original payload (0..1100 bytes). Unknown ID drops. Each relay flow owns
one connected UDP socket, pinning its NAT mapping to one destination. Close the
control stream to close the mapping. Idle expiry is 60 seconds by default.
32-datagram client receive queue drops on overflow. No reliability or reordering
layer; late, lost or out-of-order datagrams retain UDP semantics.

TCP: after status byte the stream carries bytes; stream FIN maps to TCP half-close.
No independent relay migration of existing connections. Relay failure resets flows.

## MTU
UDP data header: 5 bytes, no redundant session ID. Typical QUIC short header:
1 flags + 0..20 destination CID + 1..4 packet number + 16 AEAD tag;
DATAGRAM framing 1..3 bytes. UDP 8 bytes; IPv4 20, IPv6 40.
With CID 8 and packet number 2: overhead IPv4 about 64..66 bytes, IPv6 84..86.
Worst short-header estimate with CID 20/PN 4 and 3-byte framing: 100 bytes IPv6.
An 1100-byte payload fits a 1200-byte path packet with that estimate.
ACK/control coalescing varies: transport may reject or defer a datagram.
quic-go PMTU discovery is enabled; oversized application packets are rejected,
not fragmented by this framing layer. Destination-leg UDP PMTU support is future
work. Client cannot infer end-to-end game PMTU just from client-relay PMTU.

## Ticket-authenticated session v2

ALPN `neexitlag/2` adds one first bidirectional AUTH stream before flows.
AUTH is a four-byte big-endian length (<=8192) followed by a signed ticket JSON
envelope. Relay returns status byte 0 only after validating signature, time,
audience, revocation, certificate key binding and single-use ticket ID.
After successful AUTH, the existing v1 flow OPEN and UDP/TCP framing above is
unchanged. Relay lease is 30 minutes; ticket expiry governs new authentication.
Legacy ALPN v1 remains available only on explicitly mTLS-only configured servers.
See [security](docs/SECURITY.md) for replay persistence and rotation.
