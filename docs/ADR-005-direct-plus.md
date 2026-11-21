# ADR-005: process-scoped DIRECT+ in the existing capture owner

Status: implemented experimental; external Windows validation pending.
Base: codex/windows-tcp-web at 3306fa7d03c292c795a90f63d8547f78ad15430b.

## Decision

Retain one VELIQ WinDivert owner and existing non-overlapping IPv4 UDP/TCP NETWORK filters plus existing FLOW/SOCKET/IPv6 guard. Do not add winws, a second packet backend, TLS termination, process injection, global route/DNS changes or a new tunnel. The classifier yields DIRECT, DIRECT_PLUS, RELAY (and existing BLOCK). Route.Direct() continues to mean native/direct egress including DIRECT_PLUS for compatibility; Route.Type()/Local() distinguish local transformation.

LocalStrategyEngine owns an immutable versioned configuration and small atomic metrics. Existing bounded capture tables own per-flow strategy state. TCP route eligibility is pinned on a new SYN; only an eligible native DIRECT_PLUS flow may transform initial payload. Existing TCP sessions never migrate to relay/local. First complete TCP payload can refine eligibility with HTTP Host / TLS SNI without decrypting TLS application data. Unknown/fragmented/ECH metadata passes through. UDP requires an explicit IP set, not an inferred QUIC domain.

Configuration has separate builtin/user arrays; builtin is reserved/empty in this release. No background remote list download. Reload validates the whole <=24KB / <=32-profile snapshot before publication. Rules require application, protocol, ports, explicit domains/IPs, exclusions, enabled flag, priority and cutoff (1–8 payload packets). Exclusions take precedence. Domains are exact ASCII/punycode or explicit `*.` subdomain rules; IP sets accept IPv4/IPv6 CIDR, but packet transformations are IPv4 only. /0 is forbidden. IPv6 matching is future architecture, not IPv6 runtime support.

Representative strategies: `tcp-split-1`, `tcp-split-5` and `udp-fragment-24`. Generic `tcp-split` accepts a validated `split_position` (1–512), so new TCP profile variants are data driven. TCP creates two in-order segments with unchanged sequence space, options, encrypted bytes and destination; PSH stays on the final segment. UDP creates two IPv4 fragments of one checksummed datagram; it clears DF only under explicit opt-in, requires nonzero original ID, <=1500-byte packet, and does not add retransmissions or reliability. Fragment filtering can make this strategy worse; tester must report that failure. No fake/overlap packets, timers, delayed queues or arbitrary templates.

Fail-safe: unmatched/unsupported/error/saturation -> original DIRECT. A transformation send failure disables further transforms for that flow and attempts the original packet. Partial TCP send does not create a new connection; native TCP sequence deduplication applies. Stop removes capture; no persistent modifications remain. Known concurrent WinDivert users/anti-cheat processes disable local transforms and new selected routing decisions; diagnostics do not terminate them. Process-name/module detection is partial, not a guarantee of anti-cheat compatibility.

## Learning / route quality

Controlled tester records real application-level response RTT, connect/TLS timings, jitter, failed probe ratio and authenticated endpoint source, plus capture identity/route/modification evidence. It tests a finite list, never brute-forces a live game's connections. Cache key includes observed network configuration fingerprint, exact application path, destination:port, protocol, strategy config digest/schema. TTL=15min, capacity=1024 targets with <=8 variants; three failures quarantine a variant for five minutes. Config/network change invalidates old evidence. No payload is persisted. Cache is volatile; restart requires revalidation.

AUTO changes only with fresh, per-target tester evidence. Healthy DIRECT wins. A known-working DIRECT+ may beat degraded/failed DIRECT using existing optimizer.Score; RELAY gets only a bounded 5ms equivalent traffic-cost tie-break. Worse quality is never rescued by zero traffic cost. No evidence -> unchanged existing AUTO selector. Global relay quality is not assumed to describe every website. Existing TCP remains pinned. Network inspection is background-only (30s cadence), so undetected network changes within that interval remain a limitation.

## Metrics / performance / validation

Count inspected payload packets, successfully sent modifications, extra packets, matched local flows and original outbound DIRECT+ bytes. `bytes_relay_avoided=0` is explicitly unknown without an actual RELAY counterfactual, not a savings claim. Cutoff fast path retains no payload and allocates no packet buffers. Initial transforms allocate bounded output packets; the pre-existing identity/evidence path has its own costs.

Portable tests prove transformations, checksums, stream/datagram reconstruction, exclusions, bounds, cache/AUTO and identity delegation; native CI covers Windows compilation/driver lifecycle. Real external Windows A=DIRECT_PLUS/B=DIRECT/C=RELAY and actual ISP bypass/performance require the controlled acceptance command. Until then GUI/docs call strategies experimental, never proven working. See DIRECT_PLUS.md and FLOWSEAL_ZAPRET_ANALYSIS.md.
