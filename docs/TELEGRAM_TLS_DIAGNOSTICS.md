# Telegram Web: TLS-диагностика без изменения VPS

## Что установлено по коду

`RELAY_FIRST` закрепляет TCP-поток за authenticated relay. PAC принимает CONNECT,
затем передаёт исходные байты через native handoff (если включён) в QUIC stream;
relay копирует их в TCP origin. На этом пути нет TLS termination, изменения SNI,
ALPN, ECH/GREASE или ограничения ClientHello до MTU. QUIC пакеты и TCP сегменты
могут дробиться, но приложение получает упорядоченный поток байтов.
`ReadDeferredHello` возвращает исходные накопленные байты даже при неполном SNI;
после начального write продолжается обычное копирование. `DIRECT+` transform к
`RELAY_REQUIRED` Telegram не применяется.

Проверены участки `core/browserproxy/proxy.go`, `services/client-service/browser_native_pac.go`,
`platform/windows/{deferred_tcp.go,tcp_capture_windows.go}`, `core/transport/client.go`
и `services/relay/server.go`. Локальный regression использует настоящий QUIC+mTLS,
большой ML-KEM ClientHello и проверенный TLS/HTTP, а также непрозрачный большой
поток с ECH/GREASE-подобными байтами. Это не реальный Chrome ECH-тест.
Подтверждённой ошибки перекодирования/обрезки ClientHello в этих проверках нет.

Отдельный диагностический пробел: `openKnownBrowserGroup` запускает DNS recovery
при destination TCP OPEN rejection, но успешный OPEN с последующим TLS-отказом
не запускает recovery. Это может объяснять выбор ошибочного адреса, но пока не
доказывает причину отказа `.40`. В этой итерации DNS/policy не меняются:
нельзя воспроизводить уже отправленный браузерный handshake на другом egress
или объявлять произвольную альтернативу правильной без TLS/HTTP-подтверждения.

## Один read-only запуск с ПК владельца

Из корня обновлённого репозитория, обычный PowerShell (при UAC-off допустимо
текущее окно), пароль вводится только в штатный SSH prompt:

```powershell
Get-Content -Raw .\deploy\vps\diagnose-telegram-tls.py | ssh -T -p 22 root@2.56.177.4 'python3 - --confirm-read-only'
if ($LASTEXITCODE -ne 0) { throw 'Read-only TLS diagnostic failed; see structured output' }
```

При первом соединении проверить fingerprint SSH host key известным владельцу
способом; скрипт не отключает проверку host key и не сохраняет пароль. Root не
требуется самим проверкам: можно заменить SSH user на обычного пользователя.
Если SSH недоступен, этот же Python-файл можно выполнить в консоли VPS:
`python3 diagnose-telegram-tls.py --confirm-read-only`.

Скрипт **сам не подключается по SSH**, ничего не ставит, не читает `/etc/neexitlag`,
ключи или identity, не меняет службы, firewall, DNS, доверенные CA и конфигурации.
Он делает только ограниченные исходящие подключения к публичным кандидатам
`149.154.167.40` и `149.154.167.99`, всегда с SNI/Host `web.telegram.org`.
Это диагностические кандидаты из наблюдения владельца, не постоянные IP pins.
Можно явно задать максимум три публичных IPv4 через `--candidates IP1 IP2`.
Публичный GET `/` отправляется без browser cookies, авторизации и redirects.
Ожидаемая длительность до примерно 100 секунд; каждый subprocess ограничен
10 секундами и 256 КиБ вывода. Требуются уже имеющиеся Python 3, OpenSSL и curl;
при отсутствии скрипт ничего не устанавливает.

На каждом IP выполняются:

1. OpenSSL с обычным X25519/P-256, проверкой цепочки и hostname, ALPN HTTP/1.1.
2. TLS 1.3 с `X25519MLKEM768:X25519`, проверкой сертификата и тем же GET.
   На старом OpenSSL — честный `SKIP_UNSUPPORTED_GROUP`. Измеренный размер
   ClientHello указан явно; это не точная копия Chrome fingerprint/ECH.
3. Большой ClientHello с 400 пустыми неизвестными extensions (`-serverinfo`):
   OpenSSL сам формирует transcript и проверяет сертификат. Это проверка размера
   на старом OpenSSL без ML-KEM, не копия Chrome ECH/GREASE. В локальном захвате
   OpenSSL 3 генерирует record payload 1953 байта; фактический размер на VPS
   указан в отчёте. Редактирования исходных TLS-байтов после генерации нет.
4. curl GET HTTP/1.1 и HTTP/2 с системными доверенными CA и pinned destination
   только для этого подключения (`--resolve`). Если curl без HTTP/2 — SKIP; `http_version` показывает реально
   согласованную версию (сам `--http2` не доказывает выбор h2).
   `verified_get=true` требует успешного завершения, ненулевого body, HTTP 2xx/3xx
   и проверки сертификата. Лимит body 128 КиБ может дать `BODY_LIMIT`, а не полный
   GET PASS. Ответы 4xx/5xx и сертификат/TLS failure не считаются PASS.

Вывод — JSON lines с фиксированными полями. OpenSSL trace/HTTP body/headers и
произвольные ошибки наружу не печатаются и на диск не записываются. Завершение
скрипта с кодом 0 означает, что проверки выполнены, **не** что Telegram работает.

## Что смотреть в Windows diagnostics

После обновления службы открыть `web.telegram.org` в Chrome и Edge, затем:

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

Версия скрипта `2026-10-20.1`. Для свежих соединений появляются строки `TLS`:

- `browser.PAC` / `edge.PAC`: байты, принятые upstream Write PAC-прокси,
  и ответы upstream **до доставки браузеру**.
- `native.actual_upstream`: байты, принятые записью в фактический relay flow,
  и прочитанные из него. `PAC_NATIVE_UPSTREAM` — тот же application flow,
  а не ещё одно независимое соединение.
- `hello_bytes`: длина первого ClientHello handshake по его заголовку, включая
  четыре байта handshake header; `records`: тип, payload length и complete
  первых восьми TLS records. Это не размеры TCP/QUIC пакетов.
- `TLS_HEADER_ONLY` при 5 байтах означает, что тело записи **не пришло**.
  Даже `type=21,len=2` без двух байтов тела не подтверждает конкретный alert.
- `TLS_PLAINTEXT_ALERT_COMPLETE`: получены оба байта plaintext alert;
  `alert_level` и `alert_description` — числовые значения. TLS 1.3 encrypted
  alerts непрозрачны и таким способом не классифицируются.
- `NON_TLS_OR_INVALID_HEADER`: первые байты не соответствуют TLS framing;
  неизвестный/открытый текст не hex-дампится, чтобы исключить вывод секретов.
- `first16_masked`: максимум 16 байт, `xx` скрывает payload; открыты только
  проверенный TLS record header и полный двухбайтовый plaintext alert.
  ClientHello random, session ID, ECH, сертификаты и application data не хранятся.

Оба наблюдения не доказывают доставку байтов origin: успешный Write означает
приём transport API. Если PAC передал ~2 КиБ, а actual upstream меньше — искать
native handoff. Если оба передали одинаковые record sizes, а upstream получил
ровно 5 байт — сравнить VPS direct proof. Несовпадение только полученных байтов
может означать local delivery failure, а не потерю в relay. Нельзя суммировать
два входа или приравнивать `BIDIRECTIONAL_EXCHANGE` к TLS/page PASS.
Старые записи не восстанавливаются; статус bounded/truncated/lost остаётся явным.

## Следующий шаг по результату

- `.40` не проходит verified TLS/GET и напрямую с VPS, `.99` проходит:
  проверять ошибочный DNS/destination и bounded DNS recovery для **новых**
  соединений, сохраняя TTL/network/profile scope и RELAY_REQUIRED. Не hardcode IP.
- Обычный OpenSSL проходит, ML-KEM не проходит на том же IP: исследовать
  origin/fingerprint/большой handshake. Это само по себе не доказывает баг VELIQ.
- Оба OpenSSL проходят, Chrome не проходит: сопоставить новые PAC/actual framing,
  alert и origin IP; OpenSSL не воспроизводит Chrome ECH/fingerprint полностью.
- Передача оригинальных байтов нарушена только в VELIQ: исправлять конкретный
  участок с байтовой регрессией; не отключать TLS validation, ECH или fail-closed.

Production VPS из среды разработки не проверялся. Owner-run результат скрипта
уже получен и учтён в следующем разделе; повторять VPS-диагностику не требуется.
Для нового кода нужна свежая Windows TLS-диагностика; Telegram Internet PASS
не заявляется. Игры, PAC guard, protected policy и сертификаты не менялись.

## Восстановление relay-first по IP (после owner proof 042869d)

Владелец проверил с VPS: исходный DNS endpoint не проходит TLS/GET, независимый
кандидат с тем же SNI проходит проверку сертификата и возвращает HTTP 200.
IP не зашит в routing. Новая логика применяется к TLS relay-first: известным
Telegram/Anthropic, protected OpenAI и остальным публичным доменам, уже выбранным
`RELAY_REQUIRED` (включая YouTube relay-first). DIRECT и DIRECT+ не меняются.

- До первого ответа допускается повтор **только полного ClientHello + dummy CCS**,
  максимум 64 КиБ. Application/early-data TLS records запрещают повтор.
  Gate сериализует replay с concurrent Write; первый origin byte необратимо
  выключает повтор. Existing TLS/HTTP/TCP data flow не меняет egress/route.
- Тишина после первого flight: 900 мс на адрес; максимум три application OPEN,
  включая исходный. Общий бюджет с первого client flight — 4 с, включая DNS,
  новые OPEN и replay. Каждый retry OPEN ограничен 900 мс; DoH — 750 мс.
  Первоначальный OPEN имеет прежний отдельный бюджет до 3 с.
- Отрицательный кэш: 60 с по (network, profile/revision, domain, port, relay, IP).
  1024 записи; истечение TTL разрешает очередную реальную попытку, постоянного
  успешного IP pin нет. При неизвестном network fingerprint кэш между flows
  не используется; общий лимит двух DNS workers сохраняется. При насыщении кэша новые записи не добавляются, а попытки
  всё равно ограничены. Неисправность IP не портит route health целого VPS.
- Origin alert или partial reply/EOF: IP идёт в negative cache, **текущий поток
  не повторяется**. После хотя бы одного байта нельзя безопасно скрыть отказ
  повтором, согласно требованию владельца. Новый браузерный connection сможет
  выбрать другой IP; первая страница при раннем alert может завершиться ошибкой.
  Неполные 1–5 байт не дают бесконечного ожидания: без полного ServerHello handshake
  flow закрывается по общему четырёхсекундному бюджету, без replay.
- Auth/session errors не считаются нездоровым origin IP. При native PAC handoff
  детектор стоит у **фактического QUIC stream**, до превращения ошибки в EOF
  виртуального TCP сокета; его report передаётся в PAC отдельно. Серверный
  protocol `/3`, tickets/mTLS и lease не меняются.
- Сохраняются все DNS-кандидаты в ограниченном ответе (до 64), вместо первых трёх;
  пробовать все подряд нельзя: после трёх попыток flow fail-closed. Обычные AUTO
  probes сохраняют прежний бюджет трёх адресов. Альтернативный DNS — HTTPS DoH
  через authenticated VPS egress, объединение Google и Cloudflare. Это **не**
  вызов ОС resolver на VPS: `/3` OPEN передаёт только IP. Без deployment существующий
  relay уже поддерживает такой путь; DNS/53 и DNS остальных программ не меняются.
- DoH answers: singleflight по scope, две одновременные resolution, 256 cache
  entries, DNS TTL максимум 5 мин и короткий error cooldown. TLS/hostname DoH
  проверяются. Ответ DNS не становится доказательством доступности origin.
- Альтернативный адрес проверяется против BLOCK/IP rules исходного policy snapshot;
  нельзя сменить required route на DIRECT/другой relay. Реальный OPEN сохраняет
  текущие owner SID/process/network/enabled проверки. HTTP/TLS proof прежнего IP
  снимается при retarget; TLS/certificate проверяет сам браузер, без MITM.

Диагностика `2026-10-20.2`: `origin IP recovery`, `addresses_tried`, `selected`,
`negative_skips`, `dns`, `attempts` с фиксированными причинами,
`replayed_client_hello_bytes`, `state`. PAC и native report относятся к одному flow;
их нельзя складывать. Replayed bytes учтены отдельно от application-write TLS
metadata. `ORIGIN_BYTES_NO_REPLAY` — транспортное наблюдение, не TLS/page PASS.
Новые интеграционные тесты проверяют настоящий ticket-authenticated QUIC+mTLS,
ML-KEM ClientHello, origin certificate и два HTTP GET на одном TLS соединении.
Результат на Windows/ISP владельца после изменения ещё не проверен.
