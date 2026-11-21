# Chrome AUTO by origin — PR #8

No extension, MITM, certificate replacement, Windows proxy, default route or DNS
server change is required. Initial activation may gracefully restart Chrome.
Production VPS, credentials, relay tickets and the QUIC/mTLS `/3` lease protocol
are unchanged.

## Confirmed regression and fix

The real ff9585a report had `browser.status.listening=false`, no VK CONNECT row,
and native `BLOCK / POLICY_BLOCK / ECH_OUTER_SNI_ONLY`. AUTO could be published
before Chrome had a working origin transport. Missing usable SNI was then treated
as a failed protected open. Chrome DNS/53 also entered the opaque relay policy,
including requests to a LAN resolver. A stale live-PID FLOW association could
mistake a reused service socket for Chrome and recursively intercept it.

Activation now binds the listener, installs an owned mandatory Chrome policy,
and requires a one-use nonce actually requested by Chrome under that policy.
The service checks TCP owner, executable, creation identity and owner SID, plus
the current owner-SID policy and fresh local strategy/network prerequisites.
Only then does the GUI commit AUTO/capture and restore real user tabs. IPC success,
a listening port, process exit=0 or a false readiness ACK cannot certify AUTO.
Failure preserves a protected-domain guard, restores a safe Chrome profile and
reports an error; domain rules survive in `browser_recovery_rules`. Other apps
are not globally disabled. A legacy AUTO without this activation is rejected.

Opaque native flows retain their explicit authenticated required-relay route;
missing SNI is not itself an upstream failure. ECH is not globally disabled.
DNS/53 bootstrap stays on its existing DIRECT path without granting a 443 bypass.
TCP resolves the actual tuple owner before a cached FLOW association. Only an
internally reserved exact DIRECT+ delegation overrides service self exclusion.
Cleanup retains that reservation even before its first SYN reaches capture;
otherwise a real transform could lose its original CONNECT attribution.

## Stable online and recovery transport

Changing an HKCU value does not prove that an already-running Chrome applied it.
Native Windows tests observed `ERR_PROXY_CONNECTION_FAILED` and no Group Policy
notification even after a queued refresh. Runtime recovery therefore does **not**
depend on `RefreshPolicy`, `gpupdate`, a Chrome policy reload or browser restart.

The mandatory inline PAC has a distinct SHA256-derived `*.localhost` proxy name
for each canonical origin. This partitions Chrome HTTP/2 connection pools even
when origins share an address/certificate. The policy contains:

* OpenAI, YouTube and explicit protected domain rules: **primary CONNECT only**.
* Ordinary/unknown origins: **primary CONNECT; owner-scoped recovery CONNECT**.
* Non-domain non-DIRECT rules conservatively retain primary-only behavior.

There is no bare `; DIRECT` fallback. It would let opaque TLS bypass attribution
and leave Chrome's bad-proxy cache avoiding the healthy planner after restart.
Instead, the GUI supervises a separate standard-user instance of the installed
`neexitlag-service.exe --chrome-recovery`. Its loopback port is persisted. This
mode never reads the service manifest, device key, token, driver or certificates.
Its only configuration channel is the GUI's inherited stdin pipe; EOF stops it.
Each endpoint has the existing 256-connection / 512-record bounds and 16 KiB
header limit. Headers and diagnostics never include HTTPS content or TLS keys.

The recovery endpoint validates the real selected Chrome executable, PID/birth
and owner SID. It never accepts OpenAI/YouTube/custom protected targets, including
when the primary service is healthy. For an ordinary new connection it first
tries the primary origin planner. The primary accepts forwarded metadata only
from the expected installed helper executable under the owner SID, then verifies
the original live Chrome TCP socket independently. Forwarded PID/path assertions
are never trusted. Client-supplied forwarding headers are rejected.

Only failure to connect to the local primary, before sending application bytes,
permits emergency ordinary DIRECT. An HTTP rejection, timeout after connecting,
required-relay failure or established stream error cannot become DIRECT. Existing
TCP streams keep their original upstream and are never replayed/migrated. New
connections use the healthy primary even if Chrome still caches the secondary
proxy. The GUI records suspended/resumed state without replacing the live PAC.

Before each emergency DIRECT open, the helper reads an atomic, bounded (1 MiB)
non-secret `state/browser-recovery-guard.json`. Policy transactions first publish
a deny guard and then the complete resulting profiles. MANUAL/BLOCK, a deleted
profile, a new protected domain, missing/invalid state or an interrupted update
cannot retain an old DIRECT grant. Only SYSTEM/admins write this new file; the
installation owner receives read access to it. Existing credentials/state ACLs
are not broadened. Only the installed executable gains owner RX so the helper
can run without elevation; it remains writable only by SYSTEM/admins.

The helper exports actual DIRECT socket bytes through an owner-SID and random
read-only-token protected loopback metadata endpoint. The private pipe delivers
that token to the GUI; it is not a relay credential. GUI and acceptance merge
these records with primary evidence and distinguish `RECOVERY_DIRECT`. Socket
bytes are not represented as captured WinDivert packets. While the primary is
unavailable the GUI reports it and shows actual recovery records. Keep the GUI
running for the independent recovery transport. If both local processes are
unavailable, proxy traffic is unavailable; protected traffic never bypasses it.

## Automatic per-origin decisions

* `chatgpt.com`, `openai.com`, `oaistatic.com`, `oaiusercontent.com`, `chat.com`,
  including exact subdomain boundaries: **RELAY_REQUIRED VPS-01**. A learned
  DIRECT result or another domain's rule cannot downgrade these origins.
* YouTube/Googlevideo and the existing curated asset domains: the operator's
  network-confirmed **DIRECT+** baseline. Exact delegated upstream tuples use
  Chrome's identity in the existing native engine. The GUI requires real modified
  packet/byte evidence, not strategy intent. Other origins do not inherit it.
* Unknown origins: bounded `GET /` with normal TLS validation, then a domain-scoped
  verified local candidate and authenticated relay on network failures. At most
  three 1.5-second attempts, four workers, 32 pending origins, 500 ms admission,
  512 cached entries. Cache keys include application, exact domain, port/scheme,
  network and policy revision; successes last 15 minutes, failures cool down for
  one minute. A TCP ACK is not success. HTTP/WAF/auth errors are not a page PASS.
  Failed synthetic trials alone cannot force ordinary browsing onto a dead VPS.

Unknown learned AUTO is best-effort, not an offline security rule. Use an
explicit required domain rule for protection during outage. A bounded origin response does
not prove login, media playback, every API path or public ISP availability.

CONNECT exposes the origin hostname without decrypting TLS, including with ECH
and Chrome DoH. Upstream resolution uses the existing system resolver; DNS
privacy/poisoning bypass is not promised. CONNECT carries TCP/HTTPS/WebSocket/H2;
browser HTTP/3 falls back to TCP in this mode. Other apps' UDP and the relay's
QUIC/mTLS transport are unchanged. Native per-origin HTTP/3 and IPv6 DIRECT+ are
not claimed. Foreign/organization proxy policies are refused. The default Chrome
user-data directory is supported; portable/custom directories need an explicit
configuration. Use the GUI as the installation's normal owner user.

## Automated verification

`TestChromeSitesNativeAcceptance` uses real Chrome with its normal sandbox and
actual current-user policy, signed WinDivert, a TLS/H2 target and authenticated
relay. Nine controlled origins share one address/certificate: all seven reported
hostnames plus ordinary/blocked targets. Real browser-returned per-stage nonces,
relay source, ECH/GREASE ClientHellos, per-connection native DIRECT+ counters and
zero protected DIRECT attempts are mandatory. The same Chrome survives Optimize
off/on and a complete controller/backend stop/restart. A real independent helper
runs with Administrator membership/optional privileges removed. Only the helper
TEST BINARY injects controlled DNS; production has no such resolver flag. No
Windows hosts/DNS or production VPS change is made by this fixture.

The target uses actual 1000-byte socket writes to model Internet MTU: loopback's
jumbo MSS would otherwise exceed the engine's existing 1500-byte packet bound.
No TLS feature is disabled and no counters are fabricated. Every phase's evidence
is retained. Regression tests cover pre-SYN alias cleanup, independent flows,
stale tuple owners, policy activation failure, guard transactions/removal,
forged forwarding metadata, protected rejection, no replay/fallback after primary
rejection, and recovery DIRECT byte provenance. Linux Chromium tests also run
real controlled HTTPS/H2. These are controlled-origin tests, not Internet PASS.

Build E2E binaries first, then the native fixture (elevated only for WinDivert):

```powershell
$env:NEEXITLAG_TEST_DRIVER_DIR=(Resolve-Path .e2e/windivert).Path
$env:NEEXITLAG_TEST_BROWSER_RECOVERY=(Resolve-Path bin/windows-e2e/browser-recovery-acceptance.exe).Path
go test -v -timeout 120s ./platform/windows -run '^TestChromeSitesNativeAcceptance$'
```

## Windows update and short public rerun

Close Chrome and the old GUI normally first. In elevated PowerShell at repo root:

```powershell
$ErrorActionPreference='Stop'
git switch codex/direct-plus-flowseal
git pull --ff-only origin codex/direct-plus-flowseal
if ($LASTEXITCODE) { throw 'git pull failed' }
git rev-parse HEAD
.\tools\windows\build-e2e.ps1
.\tools\windows\build-desktop.ps1
.\tools\windows\update-service.ps1
```

The updater keeps a persistent binary/ACL backup, replaces only the executable,
grants owner RX only on it, checks SCM/IPC and rolls back binary/ACL on failure.
It does not reinstall, enroll, read out credentials or change identity/driver/
state ACLs. No SSH/VPS action is performed. Then run the newly built
`bin/release/VELIQ.exe` as the normal owner user. Select Chrome →
**Chrome: AUTO по сайтам**, allow the initial graceful restart and keep the GUI
running. Updating only the service while keeping the old GUI is insufficient.
Disabling/removing Chrome policy retains the protected guard; Chrome restart may
be needed to fully apply an explicit policy removal. No user process is killed.

After activation, one short public check (two 30-second rounds, same diagnostic
Chrome process across local SCM restart, elevated for `-RestartService` only):

```powershell
.\tools\windows\acceptance-chrome-sites.ps1 -RestartService
```

It opens VK, ChatGPT, Twitch, Yandex Music, langame, Telegram Web and YouTube
simultaneously under the real policy, normal sandbox/TLS, with no proxy command
line override. Real document completion, API/script failures, H2, ordinary DIRECT,
protected relay, native YouTube transform, recovery provenance, complete capture
markers and zero capture/saturation drops are checked. Reports are in
`bin/chrome-sites/`; no page text, headers, cookies, metadata token or TLS keys
are saved. WAF/403, an empty/error page or missing evidence is FAIL. This public
helper has not been run against the user's ISP in CI and is not a claim of
logged-in functionality, voice latency, full video playback or Internet gain.


### Origin-probe regression (Telegram report)

The Windows report establishes that authenticated relay OPEN completed and the
subsequent origin TLS handshake failed. `TLS_FAILED` alone cannot establish the
remote alert, certificate, IP, or ALPN cause; it is not evidence of failed QUIC
mTLS. No production VPS or public Telegram endpoint was accessed for this change.

The old probe advertised only HTTP/1.1, issued HEAD, selected only the first DNS
address, and discarded the TLS failure phase. The probe now negotiates h2/http1.1
with the original hostname as SNI/certificate identity, performs an independent
credential-free GET, and reads a bounded body (32 KiB). It never follows redirects,
uses browser cookies, decrypts a browser tunnel, or treats this as full-page PASS.
Certificate validation and TLS 1.2 minimum remain mandatory. No cipher/curve or
browser ECH downgrade is enabled.

At most three distinct DNS addresses share each existing 1500 ms route budget.
The successful address is pinned in the domain/network/revision cache; a DNS
change invalidates that confirmation. Protected OpenAI and explicit rules bypass
unknown-origin learning and keep required-relay fail-closed policy.

Each trial exports destination, phase (`RELAY_OR_TCP_OPEN`, `ORIGIN_TLS`,
`ORIGIN_HTTP`, `ORIGIN_BODY`), finite error detail (deadline/peer close/reset,
certificate verification, invalid TLS record, remote alert), negotiated ALPN and
TLS version. Arbitrary remote error text, request data and credentials are absent.
A failed relay trial is not cached as success. An h2-only origin behind a real
one-shot-ticket/mTLS QUIC relay is covered by integration regression, with DIRECT
unavailable and a completed origin document through RELAY_REQUIRED. Real ISP
Telegram acceptance remains necessary: the public seven-site helper checks
Chrome document completion and script/XHR errors and permits a verified AUTO
relay choice specifically for Telegram instead of incorrectly requiring DIRECT.


Crucially, when local routes failed and relay OPEN succeeded but the independent
origin TLS probe failed, Chrome now gets a **new unverified required-relay trial**
instead of returning to known-failed DIRECT. This is `ORIGIN_TLS_BROWSER_TRIAL_UNVERIFIED`,
not HTTP_SUCCESS, not a healthy cache entry (5 second bounded trial cooldown), and
never a reason to replay an established stream or bypass certificate validation.
Failed relay OPEN and certificate-verification failures do not take this path.
The real Chrome regression uses a controlled origin that rejects local egress and
Go's probe ClientHello but accepts Chrome over authenticated relay. The native
Windows acceptance runs the same case under actual Chrome policy and capture.
This establishes the incorrect probe-veto/fail-open decision independently of the
specific remote Telegram TLS alert, which still requires fresh ISP diagnostics.

Incorrect system-DNS addresses now have a bounded relay-only DoH recovery path,
with independently verified TLS/HTTP and DNS-TTL/network-scoped pins. See
[DNS recovery and read-only candidate comparison](CHROME_DNS_RECOVERY.md).

## Automatic Chrome profile on "Optimize" (clean install)

When the user presses Optimize, VELIQ looks for installed browsers (`BrowserCatalog`).
If Chrome is installed and the service has **no profile for `chrome.exe` at any path and
in any mode**, one is created in the same safe shape as adding Chrome by hand (DIRECT),
and the normal PAC activation then runs (it asks before restarting a running Chrome).
An existing Chrome profile is never modified. A failure here is shown as a notice and does
not stop the rest of the optimization (Telegram, Claude, ChatGPT keep working).

Edge, Firefox, Brave, Yandex Browser, Opera and Vivaldi are detected and listed in a notice
as **not covered**; they stay DIRECT. Reason: a browser needs its own complete lane (policy
key, PAC, recovery listener with that executable, readiness proof). The service holds one
expected PAC and one recovery process, and a generic Edge profile would relay all of Edge's
traffic (`openai-web` preset), so none is created. Adding Edge means a second lane in both
the service and the GUI; it is deliberately not half-done.

## YouTube через relay: флаг `youtube_via_relay`

По умолчанию **выключен**. Застой DIRECT-туннеля к YouTube/googlevideo/ytimg/ggpht считается и виден в
`browser.status` (`direct_stalls_total`), но ни кэш, ни повтор не уводят YouTube в relay: видео — тяжёлый
трафик, лимиты тарифа VPS не подтверждены. Включение: `settings.set` с полным объектом Settings и
`"youtube_via_relay": true` (остальные сайты от флага не зависят).
