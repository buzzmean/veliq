# Passive DIRECT UDP reply diagnostics

The existing inbound WinDivert sniff observer also accounts for ordinary DIRECT
UDP flows. No handle, filter, priority, driver, routing policy or anti-cheat guard
is added or changed. The observer never injects, sends or drops packets and does
not enable GameUDP priming. Active GameUDP and socket/relay worker replies retain
their existing accounting; they are excluded from the new path.

Only an existing live capture flow with the same tuple, PID/birth, native FLOW
endpoint and evidence generation accepts replies. Unknown native ownership,
retired flows and reused endpoints/generations are excluded. FLOW/NETWORK event
delivery ordering still bounds attribution; this is not a kernel ownership proof
independent of the existing association feed.

`capture.diagnostics` and `capture.changes` add `udp_reply_observer`:

- `available`, `reason`, observation `started_at`, optional native Win32 error;
- `kernel_queue_loss_known: false`: no claim of zero driver-queue loss.

Eligible flow evidence adds `direct_udp_reply`, including identity/filter scope,
first-packet coverage and the first/last reply observation timestamps. Existing
`counters.direct_reply_packets`/`direct_reply_bytes` include these replies, in
IPv4 packet bytes rather than payload bytes. No packet content is retained.

States distinguish `OBSERVING`, `PARTIAL` and `UNAVAILABLE`. A late observer or
late ownership binding is partial coverage. Unavailable/failed observation must
never be reported as measured RX=0. A running observer with zero observed replies
also cannot establish network loss: queue loss and parsing/fragment limitations
remain unknown. The unchanged sniff filter excludes loopback, impostors, IPv6
and remote UDP source ports below 1024; those flows explicitly remain outside
the new observation scope. An absent field on an older client is unsupported
diagnostics, not zero replies.

This is transport metadata, not evidence of successful game join, anti-cheat
compatibility, latency, FPS or the cause of a historical connection failure.
Candidate tests run without installing on working client machines; actual field
acceptance requires a separately authorized update and normal owner activity.
