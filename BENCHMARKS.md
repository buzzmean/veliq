# Benchmarks
No throughput or latency improvement claims yet. Planned: 64/512/1100-byte UDP,
TCP streams, packets/sec, Gbps, CPU, memory per flow and transport overhead.
Protocol payload limit is 1100 bytes, so 1200-byte forwarding is rejected until
PMTU-aware support is implemented. Run protocol benchmarks with go test -bench . ./core/protocol.

## Initial framing microbenchmark (Linux x64)
Command: `go test ./core/protocol -run '^$' -bench BenchmarkFrame -benchmem -benchtime=100ms`.
Worker CPU: Intel Xeon Platinum 8573C; concurrent compilation affected load.

| Payload | ns/op | allocated bytes/op | allocs/op |
|---|---:|---:|---:|
| 64 | 521.1 | 80 | 1 |
| 512 | 1349 | 576 | 1 |
| 1100 | 2743 | 1152 | 1 |

These measure framing only, not network throughput or per-flow memory. Encode
currently allocates one frame per packet; measure relay bottlenecks before pooling.
