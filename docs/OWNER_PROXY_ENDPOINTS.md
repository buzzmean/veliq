# Owner proxy endpoint continuity

The protected state file `browser-owner-endpoints.json` retains one primary and
at most one compatible IPv4 loopback address for the installation owner. It is
independent of `browser-owner-proxy.json`, the reversible Windows settings lease.
OFF/uninstall still restores only settings owned by the current lease, using the
existing compare-before-write rules. The endpoint file contains no credentials.

Before stopping an older service, the normal update script runs the candidate
with `-remember-owner-proxy-endpoints -config <installed manifest>`. This elevated,
offline operation imports only the current validated lease. A repair may also
specify `-previous-owner-proxy-lease <verified same-owner backup lease>`; that
address becomes compatible, never primary. There is no arbitrary-port IPC, no
global fixed port and no external forwarding process. A third address is refused
instead of silently discarding a cached client endpoint. An occupied port is not
taken over; a failed compatible bind does not replace or stop the primary.

Startup restores the primary and compatible listeners before slow activation.
Both use the same real socket owner, SID, PID/birth, profile and destination
authorization callbacks. Protected destinations retain their existing policy.
Existing TCP connections can close when the service process is replaced; clients
can reconnect to their cached address without restarting their process.

`browser.native.status.authority_transport.listeners` exposes role, address,
listening/bind error, owner failure counts, lost/truncated and up to four recent
requests per listener (basename/PID/birth/hostname/counters; no URL or credentials).
The legacy `browser.status.listening` field keeps its original meaning.

The updater snapshots the old lease and restores it, with original ACL and hash
verification, before a failed update starts the old binary. Version 730 ignores
the separate endpoint file and can read its unchanged lease schema. The compatible
listener is unavailable after rollback to a version that did not implement it.

The isolated endpoint workflow tests cached clients across controller replacement
with production Windows owner authorization and existing guard/foreign-owner
tests. Full Linux and Windows race/vet/build and pinned WinDivert filter checks
remain required in the normal Verify/Beta workflows. These checks do not prove
real Steam/EA authorization or video playback on an installed machine.
