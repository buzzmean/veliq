# Desktop / service protocol v1

The unprivileged WPF client sends unary requests over `\\.\pipe\neexitlag-v1`.
Each frame is a four-byte big-endian length and <=64 KiB JSON. Requests include
version, random request ID, timestamp, token, method and payload. Responses include
version, request ID, success, error code/message and payload. Token comparison is
constant-time; timestamp and bounded request-ID replay checks precede dispatch.

Methods: status, profiles, processes, profile.set, optimize, settings.set,
diagnostics. demo.fail-relay is available only on the lab's explicit demo hook.
The Windows pipe ACL permits SYSTEM, Administrators and the configured owner SID.
Service state, device identity and driver binaries remain privileged; only the IPC
token is readable by the GUI owner. Requests have deadlines and a 16-worker bound.
The client distinguishes missing/stopped service, bad frames, versions, errors
and timeouts and displays disconnected/unavailable rather than fabricated metrics.

Portable demo uses the same request/response shape over loopback HTTP with a
per-instance token, JSON content-type checks, Host checks and no CORS. WPF demo
URLs must be loopback; redirects are disabled. This is a development transport.
