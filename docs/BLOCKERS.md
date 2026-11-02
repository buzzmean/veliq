# Windows runtime acceptance blockers

> Current beta work, 2026-11-02: draft #56 supersedes the Build618 origin
> blockers with an owner CONNECT transport. See [BROWSER_AUTHORITY_TRANSPORT.md](BROWSER_AUTHORITY_TRANSPORT.md)
> for the implemented contract and [BETA_ACCEPTANCE.md](BETA_ACCEPTANCE.md) for
> exact-SHA CI plus physical PC gates. The historical matrix below is not the
> current candidate's acceptance result. No production state was inferred.


This matrix was written before real Windows runs. Several items are now exercised
by native CI tests or were run on a real PC (see `docs/STATUS.md`), but it has not
been re-reviewed line by line: the owner decides which items are closed. Anything
not re-run after `6b50bd1` on a real Windows machine stays open here.

On a Windows 10/11 x64 test machine with administrator access and an official
signed WinDivert v2 distribution, verify:

1. Process discovery: PID, full path, creation time, exited process and PID reuse.
2. GUI owner without elevation reaches the service; another SID cannot connect;
   bad tokens, replays, incompatible frames and timeouts fail safely.
3. Selected Process A IPv4 UDP traverses relay while unselected Process B stays
   DIRECT; reply IP/port tuple, checksum and payload match the original socket.
4. First packet before FLOW metadata stays DIRECT for that flow. Endpoint-delete
   events cannot delete a reused endpoint/identity. Stop/restart capture repeatedly.
5. Relay failure switches new flows to backups or DIRECT; existing TCP stays
   pinned at core level. Transparent TCP/IPv6/fragment/loopback traffic stays DIRECT.
6. Stop and forcibly kill the service with active traffic. Verify WinDivert handle
   close releases capture and ordinary networking continues without route changes.
   Graceful shutdown drains/reinjects; abrupt crash may lose in-flight captured
   datagrams. The real driver fail-open behavior still requires this acceptance test.
7. Missing, wrong-hash, unsigned or incompatible DLL fails with a clear UI error
   before capture. Check bounded queues/concurrency under traffic, driver reboot,
   NIC change, sleep/resume, AV interaction and multiple adapters.
8. Native WPF six pages, .exe picker, disconnected service, profile persistence,
   launch-on-login preference, actual named-pipe bindings and diagnostics.

Full BLOCK profiles are rejected by the current UDP-only Windows backend.
Optional publisher/signature matching needs independently verified discovery data.
Production WFP needs WDK, a signed kernel driver, security review and acceptance
coverage; the current WFP boundary deliberately reports unavailable.
