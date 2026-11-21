# Destination-aware quality and adaptive FEC: future contracts

## Destination-aware quality

The v1 sampler proves CLIENT -> selected route -> configured authenticated echo.
A relay's handshake or echo RTT is not CLIENT -> RELAY -> GAME quality. The
`core/quality` contract keys observations by application, real PID/creation time,
protocol, actual existing-flow destination and route ID. Reused/unknown identities
are invalid. Existing WinDivert capture/flow evidence already records bounded
metadata and counters; no packet payload is needed for the groundwork.

Future observers may use only active classified flows, with bounded storage,
expiry, local-drop categories and user-approved retention. Never scan arbitrary
Internet addresses or maintain hardcoded CS2 server IPs. A UDP application's
sent/reply counters are asymmetric; the contract explicitly reports network loss
as unknown. Arbitrary encrypted game payloads do not expose a trustworthy RTT,
packet sequence or acknowledgment scheme. Repeated UDP sends without replies
could be entirely normal and must not imply a failed destination.

A future provider may expose known quality only from a protocol-aware, explicitly
supported sequence/ack signal or an opted-in authenticated destination probe.
Probe candidates need authorization, rate/MTU budgets and active-destination TTL;
passive metadata does not authorize probes. Application/destination scoring must
retain DIRECT comparison and confidence, and apply to new flows. No provider is
wired to AUTO in v1: the default configured echo scope stays visible in the GUI.

## Adaptive FEC

There is no FEC encoder/decoder in v1 and `DisabledFEC()` advertises no capability.
Game payload remains QUIC DATAGRAM. Control/ticket/open handshakes may use streams;
game UDP does not become a reliable stream and is not normally retransmitted.

Future FEC must negotiate an explicit capability/wire version at both ends;
unknown peers remain on the existing DATAGRAM framing. Consider XOR parity for a
small group (e.g. 4 packets + 1 parity, 25% payload overhead), and compare with a
small erasure code for short bursts. A five-packet burst cannot be recovered by
one XOR parity group; capability claims must match actual recoverable erasures.

Design constraints before implementation:

- bounded group/sequence/generation metadata and authenticated parity, replay and
  duplicate protection; no cross-flow recovery;
- respect the existing 1100-byte user payload/QUIC MTU budget, including added
  metadata and parity; no implicit fragmentation;
- maximum extra group wait and recovery deadline budget (initial experiment at
  most 2ms, not a claim that 2ms improves games);
- late parity/recovered realtime payload must expire rather than delaying live
  packets; no ordinary retransmission fallback;
- enable only when measured burst patterns and overhead justify it; hysteresis,
  CPU/queue caps and explicit rollback to no FEC;
- count recovered, unrecoverable, expired, parity-byte, queue and reinjection
  outcomes separately; never hide original loss behind recovery totals;
- require impairment-lab tests and real Windows/VPS game validation comparing
  loss, p95 latency and queue pressure before any opt-in runtime deployment.

None of these designs claim source-IP continuity. FEC would recover erasures
within a pinned path, not make relay-to-relay migration safe or seamless.
