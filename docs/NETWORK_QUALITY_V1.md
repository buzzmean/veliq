# Network quality v1

AUTO evaluates the configured authenticated acceptance/probe destination, not
unknown game servers. No real Windows/VPS loss improvement is claimed by this
change. DIRECT/MANUAL routing, IPC v1 and ordinary QUIC DATAGRAM remain supported.

## Rolling evidence

Per-route history is a 60-second window, bounded to 128 rounds and 64 routes.
Production round size remains 5, but AUTO eligibility requires at least 20
sent-network samples and 3 distinct rounds. A switch additionally requires 3 fresh paired
observations of incumbent/challenger, not repeated GUI polling of one result.
With the active 5-second probing interval this typically means tens of seconds
of evidence. At 50–60 probes/minute loss estimates are still coarse: sample count
is visible, and a reported 0% is not proof of a loss-free Internet path.

Actual per-probe send times, authenticated reply RTTs and outcomes are retained
inside the service. Raw per-packet observations are not exported into every IPC
history row. Available summaries include latest successful RTT, median and
nearest-rank p95, mean absolute successive-RTT variation (jitter), unanswered sent
probe fraction, EWMA RTT/jitter/loss, trailing consecutive losses, largest burst,
local failure rate, failure rate, consistency/stability index and counts.
EWMA alpha is 0.25 per round, recomputed from the surviving window; expired evidence
cannot survive indefinitely in EWMA. Legacy aggregate observations have no
per-packet percentile proof: `percentiles_available=false`, and GUI shows no
invented median/p95. Median-of-round means is only a scoring compatibility fallback.

A canceled parent operation is not recorded as a network timeout. Probe timeout
means no valid reply was received end to end: it does not identify the failing
hop, nor prove that an uninstrumented kernel/QUIC queue was loss-free. Known local
errors are separate from sent-network-probe samples. Do not subtract cumulative
queue counters from probe loss: unrelated application traffic shares those queues.

## Score and hysteresis

Equivalent-ms score for eligible routes:

```
0.90 * median RTT + 0.10 * EWMA RTT
+ 0.50 * max(0, p95 RTT - median RTT)
+ 2 * rolling jitter
+ 4000 * rolling probe loss
+ 2000 * failure rate
+ 25 * max(0, largest loss burst - 1)
+ 15 * relay load
+ 20 * (1 - stability)
```

RTT/jitter values in this formula use milliseconds. One percentage point of
sustained probe loss costs 40ms; a five-packet consecutive burst costs another
100ms. This explicitly favors a 55ms/0%/2ms DIRECT path over a 48ms/2%/7ms relay,
and a 58ms/0.1%/3ms relay over an 80ms/1.5%/12ms DIRECT path. Deterministic tests
cover these cases, isolated vs burst losses, 1/3/5% losses, p95 tails and jitter.
These are engineering defaults, not empirically validated game QoE weights.

Stability is a bounded consistency index:
`1 / (1 + 10*loss + jitter/50ms + 0.1*max(0, burst-1))`.
It is not a probability of uptime. The window's observed losses are never hidden.

Existing signed routing parameters remain wire-compatible: default minimum
improvement 5 equivalent ms, minimum route lifetime 30s and confirmation 10s.
Both candidate and incumbent must receive new evidence to advance confirmation.
A single lossy round remains visible but cannot alone establish sustained
loss-driven switching. Median/p95 guards transient latency spikes. Multiple
relays are ranked by the same history; ID is only a deterministic equal-score tie
breaker. Unknown DIRECT history is not evidence that relay is better.

Health bypasses normal switch confirmation for session closure, real probe
open/send/receive failures, 3 consecutive unanswered probes, a 5-packet loss
burst (including round boundaries), or >=10% window loss with >=40 samples and
at least 2 bad rounds. Recovery requires 3 good rounds spanning at least 10s;
late closure of a retired transport generation cannot poison its replacement.
Health notifications and completed rounds are published promptly rather than
waiting for the slowest route in a multi-route round. These thresholds are
covered by deterministic tests and still require real-world validation.

## Existing flows

AUTO selection and Primary/Secondary/Tertiary are for **new flows**. The routing
engine reserves/pins a route; existing UDP/TCP handles never consult AUTO again.
Backup relays may be tried while opening a new flow, before sending application
payload. A deterministic regression changes AUTO while an existing flow is live,
then fails that handle: no second relay is opened for the existing flow.

The Windows capture backend retains its existing fail-open behavior: on actual
relay/session IO failure, policy can drain unsent queued packets onto DIRECT, or
block according to policy. There is no relay-to-relay live migration. DIRECT
fallback changes public source IP and may still break IP-bound game sessions;
it is **not seamless**. Quality degradation alone does not migrate a pinned game
flow. Packets already accepted by QUIC are not retransmitted by this feature.

## Loss classification and availability

| Evidence | Where observable | Interpretation |
|---|---|---|
| `probe_loss` | authenticated probes | unanswered sent probes, hop unknown |
| `capture_processing_drops` | client/relay size or processing validation | local discard |
| `capture_queue_drops` | WinDivert application flow queue | local queue overflow |
| `worker_saturation_drops` | exhausted WinDivert worker with BLOCK policy | actual discarded packets, DIRECT fail-open is not counted as loss |
| `capture_receive_errors` | native WinDivert receive error | events, not an invented packet count |
| `capture_kernel_queue_drops` | WinDivert kernel queue | unavailable through this API; explicitly no data |
| `transport_queue_drops` | client per-flow QUIC reply dispatch queue | actual local queue overflow |
| `quic_decode_drops` / `unknown_flow_drops` | client/relay DATAGRAM dispatch | local protocol/flow discard |
| `relay_socket_send_drops` | QUIC DATAGRAM/socket send errors | local send failure; peer receipt not implied |
| `reply_reinjection_failures` | Windows reply construction/injection | local failure to return reply |
| `policy_drops` | intentional blocking / relay rate limit | policy discard, not network loss |

Each metric exports observed count, attempts, availability and an optional
fraction. No attempts => no percentage. Counts are cumulative within the shown
component/session, while probe loss uses the rolling window; denominators are
not interchangeable. `quality.diagnostics` is an additive owner-authenticated
IPC endpoint. Capture evidence keeps old counters plus `local_drops`; transport
counters are local current-session counters. The remote relay's classified
counters are exported by its existing private `/metrics`; the desktop explicitly
has no remote-server counter values. Unexposed QUIC/kernel internal drops cannot
be declared zero. GUI labels unknown fractions/unsupported counters honestly.

## Destination-aware and FEC groundwork

See [design](design/DESTINATION_QUALITY_AND_FEC.md). Neither destination inference
nor FEC/parity/retransmission is enabled. Captured flow metadata is evidence of
traffic, not automatically game-server RTT or UDP packet loss. No Internet scan
or hardcoded game IP is introduced.

## Validation

Go deterministic quality/health/ranking, internal overflow classification,
flow-pinning, real existing echo/relay integration, race tests, .NET DTO/UI/resource
tests and Windows cross-build are required. Windows CI retains the native EXE
startup/Russian/single-instance smoke and the existing E2E tooling regressions.
Operator-run simultaneous DIRECT/RELAY E2E and destination/game QoE measurements
must be repeated separately; cloud/unit results do not prove improved game loss.

Actual relay UDP open/send failures also notify the generation-guarded health handler immediately. Parent cancellation and local oversized-datagram validation do not classify a relay outage. Sent-probe receive deadlines remain probe loss; send failures are transport/local failures, not unanswered sent probes.
