# Windows networking boundary

`WindowsCaptureBackend` separates service/routing from the native capture backend.
WinDivert v2 joins FLOW/SOCKET identity and exact native ownership tables with
NETWORK IPv4 UDP/TCP capture. UDP keeps its existing datagram path. TCP uses a
separate bounded local stream reflector, with authenticated relay open before
SYN reflection, connection pinning and native DIRECT fallback on opening failure.
Unknown/self and unselected traffic remain DIRECT; TLS is never decrypted. IPv6
relay transport is unsupported; the network guard blocks attributable new relay
IPv6 flows, with explicit existing/unknown-socket fail-open limits.
See [TCP/web architecture, evidence semantics and limitations](../../docs/WINDOWS_TCP_WEB.md).

Absolute-path loader requires trusted DLL/SYS SHA256 pins, validates signed SYS
Authenticode and constrains library search. External signed binaries are not
committed. Missing dependencies fail before capture. WFP is a distinct unavailable
boundary awaiting a signed kernel driver, preserving ADR-001.

The owner reports successful real IPv4 UDP Windows E2E. TCP/web acceptance is
separate; cross-builds, owner-table tests and driver handle tests do not establish
a real external TCP/browser PASS.

Real E2E tools, owner-table fallback (including dual-stack socket ownership),
process cache/cleanup and counter evidence are described in
[Windows real E2E](../../docs/WINDOWS_REAL_E2E.md). Official unsigned DLL is protected
by pinned SHA256; signature validation applies to the signed kernel SYS.
