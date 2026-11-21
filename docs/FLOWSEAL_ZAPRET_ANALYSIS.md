# Flowseal / upstream implementation review

V2 re-review confirmed both upstream HEADs below on 2026-10-14. The inventory remains current. Statements below about the initial MVP not importing fake techniques describe v1; the independent v2 implementation, curated domain subsets and limits are documented in [DIRECT_PLUS_V2.md](DIRECT_PLUS_V2.md). No upstream fake binary/code is copied.

Reviewed 2026-10-14, pinned source trees:

- [Flowseal](https://github.com/Flowseal/zapret-discord-youtube/tree/eb16c1419057e36b8a36fbe7c959483450e6ac8b), MIT, including all 22 general batch configurations.
- [upstream zapret](https://github.com/bol-van/zapret/tree/c4d0b1990129dce2b28095277173ee0d7702d304), docs/LICENSE.txt MIT (2016–2024 bol-van at this revision).

## Wrapper versus engine

`general.bat` calls service status/update/list/game helpers then starts winws with a broad NETWORK capture filter and ordered `--new` strategy blocks. The wrapper does not itself transform packets or attribute processes. `service.bat` installs/stops/removes its service, extracts arguments from the chosen batch configuration, creates user lists, toggles game/IP filters, updates lists, launches tests and diagnoses Windows configuration. These service/driver lifecycle operations must not be imported into VELIQ.

Upstream `nfq/nfqws.c`, `nfq/desync.c`, `nfq/protocol.c`, `nfq/conntrack.c` implement filter profiles, L7 classification, packet fabrication, split/disorder/overlap, checksum/sequence handling, connection tracking and cutoff. Windows builds use `nfq/windows` WinDivert capture/reinjection. winws is the packet engine, not a remote proxy and not a TLS MITM. Encrypted QUIC Initial can expose initial-handshake metadata to an implementation with QUIC parsing/decryption; that is not equivalent to UDP port 443 proving a domain.

## Config inventory

This table records every checked-in `general*.bat`, not an assertion that any works on the user's ISP. Repeats, fake files, overlaps and split positions also vary between profiles.

| Configuration | Mechanisms | Fooling | Game cutoff |
|---|---|---|---|
| general (ALT).bat | fake, fake,fakedsplit | ts | n3, n4 |
| general (ALT10).bat | fake | ts | n2, n3 |
| general (ALT11).bat | fake, fake,multisplit | ts | n4 |
| general (ALT12).bat | fake, fake,multisplit, hostfakesplit | ts | n4 |
| general (ALT13).bat | fake, fake,hostfakesplit, fake,multisplit, hostfakesplit | ts | n4 |
| general (ALT2).bat | fake, multisplit | — | n2, n3 |
| general (ALT3).bat | fake, fake,hostfakesplit | ts | n4 |
| general (ALT4).bat | fake, fake,multisplit | badseq | n2, n3 |
| general (ALT5).bat | fake, syndata,multidisorder | — | n3, n4 |
| general (ALT6).bat | fake, multisplit | — | n2, n3 |
| general (ALT7).bat | fake, multisplit, syndata | — | n2, n4 |
| general (ALT8).bat | fake | badseq | n2, n3 |
| general (ALT9).bat | fake, hostfakesplit | ts, ts,md5sig | n2, n3 |
| general (EXP).bat | fake, fake,multisplit, hostfakesplit | ts | n4 |
| general (FAKE TLS AUTO ALT).bat | fake, fake,fakedsplit | badseq | n2, n3 |
| general (FAKE TLS AUTO ALT2).bat | fake, fake,multisplit | badseq | n2, n3 |
| general (FAKE TLS AUTO ALT3).bat | fake, fake,multisplit | ts | n3, n4 |
| general (FAKE TLS AUTO).bat | fake, fake,multidisorder | badseq | n2, n4 |
| general (SIMPLE FAKE ALT).bat | fake | badseq | n2, n3 |
| general (SIMPLE FAKE ALT2).bat | fake | ts | n3, n5 |
| general (SIMPLE FAKE).bat | fake, hostfakesplit | ts | n3, n4 |
| general.bat | fake, multisplit | — | n2, n3 |

The base configuration combines TCP multisplit with sequence overlap patterns (568/681 bytes), QUIC fake repeats=6, Discord/STUN fake repeats=6, game TCP cutoff=n3 and UDP cutoff=n2/repeats=12. ALT2/6 use simpler split positions 2/1. ALT5 uses syndata+multidisorder; ALT7 adds sniext-relative splitting. ALT8/10 primarily fake, ALT9/12/13/EXP introduce hostfakesplit. FAKE TLS AUTO variants randomize/duplicate session IDs and modify fake SNI (`rnd,dupsid,sni=...`); AUTO describes fake-template modification, not network route scoring. SIMPLE FAKE configurations simplify TCP fake injection, with ts-based fooling and some hostfakesplit variants. We do not import any of these fake/overlap recipes.

## Filters, lists, game traffic

The ordered UDP/443 hostlist block and subsequent ipset block are separate eligibility paths. TCP includes 80/443, Discord-specific 2053/2083/2087/2096/8443, Google list, general host lists and an ipset fallback. Includes combine built-in `list-general` with `list-general-user`; excludes combine `list-exclude`, `list-exclude-user`, `ipset-exclude` and `ipset-exclude-user`. Domain-list semantics in upstream must not be assumed to equal our exact / explicit `*.` semantics.

`Game Filter` is **not** process-aware. service.bat starts disabled using placeholder port 12; enabled TCP/UDP ranges default to 1024–65535 and can be edited. Game blocks use `dpi-desync-any-protocol=1`, ipset matching, unknown-payload templates and early cutoff. Discord/STUN has its own L7 filter on UDP 19294–19344/50000–50100. Copying these wide ranges into our backend would affect unrelated applications. VELIQ instead requires a valid PID/exe profile AND explicit protocol/port AND destination scope. No unknown-game learning or ipset-any default.

IPSet Filter toggles normal vs empty/sentinel-list operation using a backup. `ipset_update` downloads `.service/ipset-service.txt`; list-update helpers fetch remote data via curl. Existing user lists are separate. Remote HTTPS delivery is not a signed list format. We keep updates manual/validated, and require signed manifests before any future unattended updater.

## Fake files / packet lifecycle

`bin/` contains TLS ClientHello templates (Google, Sferum, Max, 4pda, etc.), QUIC Initial templates, STUN templates and ACTIVE_GAME_UDP/ACTIVE_DISCORD_UDP payloads, plus executable/runtime/driver binaries. They are input data to winws. Fake strategies rely on invalid sequence/checksum/timestamps/TTL or related tricks so the destination should not consume their payload. Repetition and overlap can increase traffic substantially and have middlebox-specific failure modes. No fake payload, list, executable, driver, or substantial upstream packet implementation is copied into VELIQ.

Upstream cutoff modes are `n` original packet count, `d` original data packet count, `s` sequence delta (`desync.c:cutoff_get_limit`). `maybe_cutoff` can end tracking once all relevant operations are done. VELIQ defines a smaller explicit limit: 1–8 initial outbound payload packets, then pass-through; this is not identical to upstream n-counting. No retained TLS buffers or gigabyte-by-gigabyte strategy processing.

## Testing / diagnostics / DNS

`utils/test zapret.ps1` Standard tests / All configs iterates actual batch files, starts/stops configuration processes, probes targets with curl (connect/total timeouts and HTTP status), and reports working configurations. HTTP success on one target is not a universal bypass or UDP proof. Our tester must additionally prove process identity, route, real modification counters, destination-observed source and network scope, retaining failures and stderr.

`service.bat` diagnostics inspect BFE, proxy, timestamps, known conflicting services/processes, driver files, VPN names, DoH registry state, hosts entries and service state. Some actions **mutate** global timestamps and remove an existing WinDivert service. We reuse only the diagnostic questions, never those automatic mutations. Our strategies do not require timestamps.

Flowseal README explicitly asks for Secure DNS. Local DPI transformation does not repair poisoned/system DNS. VELIQ preserves system DNS; browser DoH uses the browser's classified TCP/UDP socket. ECH, fragmented ClientHello and QUIC domain identification remain unsupported in this MVP: use explicit IP scope or pass through, never guess a hostname from a shared CDN IP.

## Reuse / own implementation / licenses

Reuse principles: ordered bounded profiles, include/exclude precedence, initial-flight cutoff, finite controlled testing, measured outcomes, diagnostics. Implement ourselves: process-aware classification, immutable sets, existing one-owner capture integration, payload-preserving packet strategies, scoped cache, existing optimizer score and truthful UI evidence. No persistent second winws, no copied batch library.

Flowseal's license names bol-van 2016–2026 and Flowseal 2024–2026. Upstream's own pinned MIT notice says bol-van 2016–2024. Both notices are retained in `third_party/licenses/`. MIT permits reuse provided copyright/license notices accompany substantial copied portions; binary dependencies retain their own licenses. This change is an independent Go implementation, with no imported fake data or host/IP lists.

WinDivert is dual licensed LGPLv3 or GPLv2, not MIT. Inspect upstream `nfq/windows/windivert/windivert.h` and [WinDivert v2.2.2 source](https://github.com/basil00/WinDivert/tree/v2.2.2). VELIQ dynamically loads the unmodified replaceable DLL; distribution must retain the selected LGPLv3 terms (including applicable GPLv3 text), source/rebuild/replacement information, and preserve the ability to replace/relink the library. Kernel signing/installation remains a separate deployment requirement. The downloader now carries notices and pinned corresponding-source links alongside binaries; do not infer that the Flowseal MIT license relicenses WinDivert or Cygwin. No new Cygwin/winws dependency is shipped. This is an engineering license inventory, not a relicensing of dependencies.
