# Chrome AUTO: incorrect system DNS and bounded recovery

The Windows comparison reported system DNS `web.telegram.org -> 149.154.167.40`,
while independent DoH sources returned `.99`. The `.40` relay TCP OPEN succeeded
but origin TLS returned `INVALID_TLS_RECORD`. This is consistent with an incorrect
DNS address; TCP OPEN and healthy relay RTT do not establish HTTPS availability.
**The public `.99` vs `.40` comparison has not been executed in the development
environment:** it has neither an enrolled client identity nor network access to
VPS/Telegram. No credentials were requested/read, and no VPS/SSH change was made.
No Telegram Internet PASS is claimed.

## Read-only real comparison on Windows

After building/updating the service from this PR (existing identity/paths retained),
run as the existing authorized owner; Chrome does not need to be restarted:

```powershell
.\tools\windows\check-origin-dns.ps1 -HostName web.telegram.org `
  -Candidates '149.154.167.40','149.154.167.99' `
  -ReportFile .\bin\telegram-origin-comparison.json
```

These are explicit diagnostic inputs, **not** configured origin pins. The helper
calls owner-authenticated IPC `browser.origin.check`. It uses the existing secure
relay pool and always pins RELAY_REQUIRED / fail-closed. It accepts at most three
unique public IPv4 addresses on HTTPS/443, a public hostname, and no URL path,
headers, cookie, client key or insecure TLS option. Each candidate gets a fresh
service-origin connection and 1500 ms budget. The method validates SNI/certificate
against the original hostname, negotiates h2/http1.1, issues fixed GET `/`, reads a
bounded body, and reports phase, failure/detail, actual received bytes, status,
ALPN and TLS version. Total method budget is five seconds, below existing IPC
read deadline. It does not modify profiles, Optimize, Windows DNS/PAC, enrollment,
credentials, files on the VPS or relay configuration. It is a transport check,
not Chrome/full-page/login/WebSocket acceptance.

A valid certificate + completed/bounded GET response on `.99` and invalid TLS on
`.40` confirms the wrong-address hypothesis for that test. If `.99` fails too,
inspect the finite phase/detail and HTTP status; do not call this Telegram PASS.
Then run the existing short seven-site Chrome acceptance to check real Chrome.

## Recovery architecture

Normal browsing still starts with system DNS and the existing per-domain policy.
On system lookup failure or failed unknown-origin trials/certificate mismatch,
HTTPS AUTO can perform independent DNS recovery. It does not change the OS
resolver and never uses a query about one domain to classify another.

- DoH wire-format A queries use pinned **resolver bootstrap** endpoints
  `dns.google / 8.8.8.8:443`, then `cloudflare-dns.com / 1.1.1.1:443` as fallback.
  They are carried through the authenticated relay, with normal resolver-hostname
  TLS validation. Origin IPs are never fixed in code. No direct DNS/DoH fallback.
- At most two provider attempts, two candidate TLS/HTTP checks, two simultaneous
  recovery operations and 512 domain/app/network/policy entries. Existing request
  deadline is preserved, with 750 ms reserved for the actual new Chrome tunnel.
  The recovery budget is at most two seconds. Negative/capacity results cool down
  for 30 seconds; duplicate requests share the in-flight result.
- Validate DNS question/type/ID/rcode, CNAME chain (max eight), message/header/body
  bounds and public IPv4 answers. Private, loopback, link-local, metadata, CGNAT,
  multicast, reserved/documentation ranges and private/LAN query names are refused.
  DoH redirects are not followed. Answer TTL includes CNAME minima, HTTP Age and
  conservative Cache-Control limits. Resolver answers alone never mean success.
- Only original-hostname TLS certificate verification plus real origin HTTP 2xx/3xx
  and response bytes can publish `DNS_RELAY_HTTP_VERIFIED`. The result is a required
  relay route on the exact verified destination. It proves origin reachability,
  not the full Chrome application. Certificate checks are never disabled.
- Cache key includes app, exact hostname/port/scheme, network, policy revision and
  relay identity. Positive entries expire at DNS TTL (maximum five minutes);
  TTL=0 permits the current result but creates no reusable positive cache. Re-reading
  poisoned system DNS does not overwrite a still-valid independently verified pin.
  Expired entries and network/policy changes require fresh resolution and proof.
- BLOCK/explicit DIRECT/DIRECT+ rules and the confirmed YouTube baseline are not
  overridden. Protected OpenAI remains RELAY_REQUIRED and never gets a DIRECT
  recovery trial. Existing native system/browser DNS bootstrap behavior remains.
  This is not a new system resolver or native IPv6/HTTP3 support.

An `INVALID_TLS_RECORD` result is no longer eligible for the previous unverified
Chrome-vs-Go fingerprint relay trial. When alternative resolution/proof fails,
there is no false healthy result. Unknown ordinary AUTO retains its existing
best-effort policy; protected origins remain fail-closed. Existing required-origin
fast paths are not proactively HTTP-probed on every connection; this does not
promise transparent correction of every poisoned established/opaque connection.

## Automated evidence

Core integration uses a real one-shot-ticket/mTLS QUIC relay, a wrong-DNS endpoint
returning plaintext to TLS, independent RFC8484 DoH over that relay, and a correct
HTTPS/H2 endpoint with full certificate validation. It covers TTL/network isolation,
malformed/private/wrong-question answers and DoH/origin certificate rejection.
Native Windows acceptance gives Chrome a wrong system-DNS address for the Telegram
fixture, recovers via an independent TLS/DNS fixture over real authenticated relay,
then requires actual browser nonce/HTTP results and the corrected pinned address
alongside unchanged ordinary DIRECT, YouTube modified-packet DIRECT+ and protected
OpenAI relay. No public site or deployed credentials are involved in CI.
