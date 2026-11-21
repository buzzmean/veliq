# ADR-001: Windows networking
Decision: WFP ALE classification + signed callout driver for production;
WinDivert as a replaceable MVP candidate behind routing.Backend.

| Approach | Process metadata | UDP/TCP | Costs and deployment |
|---|---|---|---|
| WFP filters alone | ALE app identity | Classification only | Cannot forward packets alone |
| WFP callout | ALE PID/path | Both with distinct redirection paths | Best integration; WDK, signing, kernel testing required |
| WinDivert | FLOW/SOCKET PID joined to NETWORK | Both | Copies and kernel/user transitions; signed vendor driver, correlation races |
| Wintun/TUN | No PID in IP packet | Both with userspace stack | Device-wide capture unless paired with classifier |
| Routing table | No PID | Both | Destination routing, cannot satisfy per-process requirement |
| Local proxy | Only cooperating apps | Both if explicitly supported | Useful lab transport; cannot transparently capture games |

Never use a full-device tunnel as a substitute. PID reuse, process exit,
service crash, packet reinjection, anti-cheat compatibility, IPv6 and adapter
changes must be tested before shipping. Linux cannot verify WFP behavior.
