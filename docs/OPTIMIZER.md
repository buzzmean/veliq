# Route quality and flow semantics

DIRECT is a normal candidate. Lower score is better, in equivalent milliseconds:
`RTT_ms + 2*jitter_ms + 1000*loss + 2000*failure_rate + 15*load + 20*(1-stability)`.
Fractions must be finite in [0,1]. History stability is smoothed and reduced by RTT
variation. Missing, failed or stale measurements cannot win; an unmeasured DIRECT
path does not prove that a relay is better.

Defaults: improvement >=5 score-ms, minimum lifetime 30 s, winner confirmation
10 s, freshness 90 s. A healthy route survives small changes. Unhealthy relays
can fail over immediately; all stale paths return to DIRECT. Rankings include up
to three healthy choices. UDP/TCP handles remain pinned; policy changes apply to
new flows. Failed opens try up to two backups then DIRECT or explicit BLOCK.

Real nonce-echo UDP probes traverse each selected transport, not ICMP. RTT uses
Go's monotonic time. Default active/idle periods are 5/30 s; each round has
700 ms timeout, 5 samples, 100 ms spacing. Global slots bound concurrent probes
and cancellation closes sessions. Limits: 32 probe candidates, <=8 concurrency,
<=20 samples, active interval >=1 s. Measurement and selection history are bounded.
The demo shortens lifetime/confirmation to 4/2 s and intentionally impairs DIRECT.
The configured echo target is not a universal prediction of game server quality.
