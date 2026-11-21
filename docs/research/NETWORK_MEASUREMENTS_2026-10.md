# Фаза 0: проверяемые измерения, 25.10.2026

Исходный контекст: `ZAPRET_WIKI_2026-10.md` прочитан целиком; его описания ТСПУ — гипотезы сообщества. Текущая база содержит `07e65b0` поверх `8b7b2e2`; CDN admission/endpoint negatives/exposure IDs не откатывались. VPS/SSH/CA/коды не использовались. Фаза 0 не меняет маршруты, лимиты пула, стратегии, timestamps Windows или протокол.

## M1 — фактический ClientHello

`TestRelayClientHelloObservedOnWire` принимает **настоящий QUIC** на loopback с временным lab CA и обычной проверкой mTLS. Серверный TLS callback декодирует ClientHello клиента с pinned quic-go 0.55.0/Go 1.25.3:

| Параметр | Наблюдение |
|---|---|
| SNI при адресе relay=IP | пустой, расширение server_name не передаётся |
| ALPN Dial | neexitlag/1 |
| ALPN DialWithTicket (путь службы) | neexitlag/3, neexitlag/2, в таком порядке |
| supported_versions | 772 (TLS 1.3) |
| cipher suites | 4865,4866,4867 |
| supported_groups | 4588,29,23,24,25 |
| signature_algorithms | 2052,1027,2055,2053,2054,1283,1539 |
| supported_points | 0 |

Это JA4-подобный **набор доступных параметров**, не JA4 hash: порядок/полный список extensions callback не раскрывает; version/Go/архитектура могут менять набор. В QUIC Initial ClientHello доступен пассивному наблюдателю; это свойство протокола, **не доказательство блокировки**. `remote.go` создаёт tls.Config без ServerName, `DialWithTicket` задаёт ALPN, quic-go для IP не отправляет SNI. Для DNS-адреса поведение иное (имя используется для проверки/SNI); фикстура проверяет именно текущую IP-схему. Не печатались random/keyshare/cert/key/ticket/байты CH.

## M2 — пул

В `relay.pool.diagnostics` добавлен `session_creation`: попытки и успешные сессии за 60 секунд (60 UTC-second buckets), lifetime maxima, concurrent/max concurrent, последние32 событий (initial_bootstrap/capacity/session_replacement/lease_rotation), factory_ms и успешный QUIC_handshake_ms. Factory включает ticket/CP/auth, handshake — только quic.DialAddr; при недоступном handshake -1. Счётчики отдельные на pool/relay и сбрасываются при создании нового pool. Последовательность создания и лимиты 8/48/3с/25мин не менялись. Concurrent=1 не ограничивает частоту последовательных попыток.

Лабораторный bootstrap+закрытие одной сессии+recovery проверяются real mTLS/tickets, fresh identity не переносится. Значения за старт/восстановление **в клубе пока не получены**; изменения cadence/ALPN не обоснованы.

## M3 — слои

`network-check.exe` из build-e2e + `diag-no-vpn.ps1 -Only layers`:
- системный API (не даёт wire AA/RCode); UDP/TCP53 к IP системного DNS и ранее указанным публичным резолверам;
- настоящий DoT handshake+DNS к 1.1.1.1/8.8.8.8/9.9.9.9/94.140.14.14: TCP connect недостаточен; проверка CA и IP SAN сохраняется;
- DoH dns.google/dns-query через pinned 8.8.8.8:443, SNI dns.google, штатная проверка CA/name; без системного DNS для этого запроса;
- AA/AD/TC/RCode/адреса и валидация ID+question; NXDOMAIN+AA не доказывает подмену. Отрицательные обычные ответы против положительного verified encrypted DNS отмечаются как POSSIBLE_INTERFERENCE;
- максимум2 IPv4 кандидата, TCP connect, отдельные TLS real/foreign(example.com) с проверкой сертификата; затем bounded HTTP только для real SNI, без credentials/redirect-follow;
- существующие публичные controls www.youtube.com `/`, discord.com `/`, опционально i.ytimg.com `/vi/aqz-KE-bpKQ/maxresdefault.jpg`; не добавлены новые веб-цели. DNS-IP взяты из задания/существующих настроек;
- budget60с/host, DNS1.5с/exchange, HTTP4с/128KiB. Никаких signed video URLs/POST в origin. DNS DoH использует только credential-free DNS wire POST.

TCP timeout без pcap = TCP_CONNECT_FAILED_NO_SYNACK_PROOF, не «SYN DROP». TLS reset не устанавливает автора RST. Зависший HTTP после16–20KiB — наблюдение, не диагноз ТСПУ. Короткий404/redirect не bulk-success. Клиент проверки — отдельный процесс со своим маршрутом, не доказательство поведения Chrome/Riot. В cloud внешние проверки не выполнялись: нужны данные владельца, прежний NXDOMAIN Youtube — только его замер, не доказанное DNS-падение desktop-приложения.

`-Only browser,youtube` сохраняет пассивные снимки; активные послойные проверки запрашиваются явно через `layers` (полный default run также содержит их). Диагностика .16 уже была занята предыдущей задачей, поэтому версия осталась .16 с явной `measurement revision 2` (первая фаза была revision 1), старые поля не удалены.

## M4/M5 — timestamps и ранние признаки

`browser.local.probes.layer_audit` — census **retained LOCAL records**, не полная lifetime частота: pure-ts plans, отсутствие timestamp в payload, неизвестное/отрицательное SYN-согласование, TIMESTAMP_OPTION_REQUIRED, >=3 ранних client retransmit, remote RST relative<=4096, выбранные STALL/TIMEOUT/RST-отказы после ответа и в диапазоне16–20KiB wire RX (TLS-байты, не HTTP body). Состояние «нет SYN при hot-attach» = UNKNOWN, не нарушение. Пробы с TIMESTAMP_OPTION_REQUIRED считаются отдельно от flow-планов. Непопавшие в retained/не-browser DIRECT+ потоки не реконструируются; отсутствие записи не означает ноль нарушений.

WinDivert ledger теперь сохраняет **только относительные** early sequence признаки и SYN timestamp booleans. Без SYN относительный RST UNKNOWN; raw payload/absolute seq не экспортируются. Retransmits могут быть обычной сетью, малый RST — сервером или middlebox. Это кандидаты раннего failure, **не автоматическое переключение стратегии**. HTTPS redirect/GOAWAY/segment не видим без MITM. Existing TLS после origin byte не replay/migrate.

Ранее pure-ts уже явно пропускается с TIMESTAMP_OPTION_REQUIRED при отсутствии опции. Собственный LOCAL-сокет включает timestamps per-socket; глобальный netsh не нужен. Из владельческих логов известен timestamp_option=True; статистики реально несогласованных/ранних отказов ещё нет. Фаза1 не должна заменять ts или ускорять перебор вслепую.

Локальный M2 bootstrap/recovery: 2 новых сессии, 2 попытки за60с, max concurrent=1; успешные QUIC handshake ≈4.53/2.22мс (пример loopback, не RTT клуба), factory≈5.99/3.27мс. Метрики проверены real authenticated pool integration. Не следует переносить эти длительности/частоту на40ПК или сеть владельца.

## Решения фазы1 — без догадок по данным community

| Пункт | Статус | Решение/основание |
|---|---|---|
| C1 | Сделано | M2/M3 и пассивный M4/M5 оставлены в постоянной read-only диагностике; Go+PS tests, legacy UNINSTRUMENTED, bounded retention. Native PS5.1 ещё требуется. |
| C2 | Отложено; глобальный netsh не нужен | При отсутствии payload timestamps guard уже TIMESTAMP_OPTION_REQUIRED. Нет реального M4-счётчика потока pure-ts с несогласованными timestamps; не заменять ts вслепую. UNKNOWN/hot-attach не повод отбрасывать рабочий план. Получить census; только затем точечный ts,md5sig/md5sig/skip без системных настроек. |
| C3 | Отложено | Новые relative evidence/candidate counters измеряют базу, но частота и выигрыш в клубе неизвестны. Три ретрансмитa и малый RST бывают не DPI. Будущий counter: failures3/60s поnetwork/profile/host/IP/strategy, bounded state, без массового poisoning; max1/cooldown>=3min и endpoint scope сохранить. После origin byte допускается завершить плохой поток и сменить будущие flows, но не replay. HTTPS redirect недоступен без MITM. |
| C4 | Отложено | Подтверждён только owner NXDOMAIN Youtube в браузере, где broker/recovery уже есть. Нет доказанного desktop-приложения, сломанного именно DNS. Если появится: отдельно спроектировать whitelist blocked-name encrypted DoT/IP или authenticated relay-HTTPS DNS, cache TTL/network/profile, normal cert validation; DNS53 обычного трафика остаётся DIRECT. Resolver службы сейчас не менялся. |
| C5 | Сделан только дизайн; код не нужен по текущим замерам | `../RELAY_TRANSPORT_EVOLUTION.md`: дополнительная версия ALPN, SNI под своим SAN, TCP+TLS fallback, flags OFF, compatibility matrix, backup/rollback. Ни одного признака фильтрации действующего relay пока не измерено; протокол и сервер не менять. |
| C6/П6 | Сделано | В diag только известные googlevideo назначения в указанных AS20485 префиксах помечены COMMUNITY_GGC_RANGE_UNVERIFIED. Метка справочная, не доказанная принадлежность/деградация; маршруты/QUIC fallback не меняются. |
| C6/П5 | Отложено | Два IP меняют VPS и egress/маршрутизацию; нужны решение владельца и доказанное приложение с проблемой exit-IP. Не покупать/добавлять IP и не менять server config. |
| C6/П8 | Сделано, справочные данные | Steam/Valve порты и Battlefield6 network reference в bundled catalog; источники community/unverified помечены. Не создают profile/filter/relay route. Для BF6 не придуман exe: это справочная запись, не новая runnable карточка. Default DIRECT существующих10 игр, guards/Riot/UDP scope неизменны. |

Повторные внешние endpoint-проверки/реальные ISP результаты не подменяются loopback. Следующий шаг — владелец присылает M2/M3/M4/M5 snapshot; только доказанный отдельный дефект открывает поведенческую правку.
