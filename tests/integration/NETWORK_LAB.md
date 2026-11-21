# Network lab
`go test -race -v ./tests/integration -run TestUDPDestinationDelayAndLoss`
runs real client→relay→target UDP with deterministic 50% destination-leg loss
and 5ms target delay. No retransmission layer is added.
This does not emulate impairment of client-relay QUIC packets, Internet jitter,
adapter changes, DNS outages or sleep/resume. tc/netem lab is a future validation.
