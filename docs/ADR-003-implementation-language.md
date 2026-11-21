# ADR-003: Implementation language
Choose Go 1.25 for relay, core and control plane. Go provides net/http, TLS,
race tooling and quic-go with a straightforward Windows/Linux build.
Rust offers memory safety without GC and tighter allocation control, but adds
implementation and FFI cost for this initial platform. Benchmark Go before
changing language. Kernel WFP code will require WDK-compatible C/C++, isolated
behind the backend contract. PostgreSQL is the planned persistent store;
Redis is not needed yet.
