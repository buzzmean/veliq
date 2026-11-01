# QUIC LOCAL: собственная ограниченная HTTP/3-проба

01.11.2026. Блок R1: пакетный план, собственный connected UDP socket,
пассивное наблюдение ClientHello и фоновая HTTP/3-проба службы по свежему
заблокированному Chrome/Edge UDP443. **Автоматический QUIC LOCAL браузера
пока не включён.** Classifier добавляет только callback постановки отдельной
пробы; BLOCK/ICMP и исходные маршруты сохраняются. Новых IPC, конфигурационных
переключателей и зависимостей нет.

Native Chrome/Edge по-прежнему получают UDP443→ICMP→TCP fallback, где действует
существующая origin policy. Поддержка QUIC relay transport не равна поддержке
браузерного HTTP/3 LOCAL. Скрытый QUIC origin нельзя устанавливать только по
DNS/IP или результату TCP/HTTP80-проверки: это может ослабить protected routing.

## Пакетный контракт

`localstrategy.QUICInitialPlan` принимает полный нераздробленный IPv4/UDP443
пакет без IP options, не более 1500 bytes, с внешним заголовком QUIC v1 Initial
и UDP payload не меньше 1200 bytes. Это проверка формы заголовка, не проверка
подлинности входного QUIC. Входной трафик не расшифровывается. Version2,
short-header первого пакета, невалидные lengths/CIDs, другой порт, фрагменты
и GSO/пакеты сверх лимита отклоняются без плана.

План содержит K дополнительных Initial (1≤K≤16), затем ровно один исходный
пакет. Все исходные bytes сохранены. Дополнительный payload ровно1200bytes;
каждый IPv4/UDP пакет1228bytes, с тем же tuple и корректными checksums. Пакеты
имеют независимое хранилище; исходный payload не сохраняется после Send.

ClientHello создаётся стандартным `crypto/tls` для собственного фиксированного
моделя `www.google.com`/ALPN h3/X25519. CRYPTO offset0 и PADDING защищаются
AES128-GCM и header protection с общедоступным QUIC v1 Initial derivation из
RFC9001. Это защита нашего decoy, не расшифровка или MITM пользовательского TLS.
DCID/SCID случайные и отдельные от обоих исходных CID и друг от друга; collision
или ошибка entropy запрещают весь план. Дополнительный handshake не получает
серверные ответы, не завершается и не отправляет application data. Настоящие
серверы могут отвечать на него или временно выделять состояние; эффект на DPI,
сервер и экономию трафика в публичной сети здесь не проверен.

Нет скачивания upstream `.bin`, внешнего winws, добавления dependencies или
изменения WinDivert pin. Существующий игровой random QUIC-shaped decoy не менялся.

## Каталог и отправитель

`Catalog.QUICProbePlans` отделён от действующего `Catalog.Compile`/TCP picker.
В pinned каталоге43 Flowseal QUIC rules дают packet plans с6/11 repeats;
оставшееся zapret2 правило и любые неизвестные/многозначные параметры отклонены.
Разрешены только udp443/fake/известный model и ограниченный repeats. Hostlist
references сохраняются как metadata; файлы не читаются, фильтры не превращаются
в разрешение для всех хостов. `PacketPlanAvailable=true` сопровождается
`BrowserRuntimeEnabled=false`. Существующая runtime capability QUIC остаётся
unsupported. Это собственная ограниченная адаптация, не binary equivalence.

`windowsplatform.QUICProbeWriter` привязан к browser executable/PID/birth,
точному source/destination IPv4:443, network/profile/revision. Destination
должен быть публичным, owner и source заданы. Это scope собственной service-пробы,
не доказательство origin и не проверка SID/ACL. Caller обязан предоставить
проверку живого процесса и актуальной политики; она вызывается перед каждым
send и чтением результата. Отозванный witness не восстанавливается при возврате
политики: нужен новый writer для новой пробы. Capture не создаёт writer для браузерного сокета; отдельный worker службы создаёт его для своего connected UDP socket.

На writer допускается одна fake flight. Последующие datagrams сохраняются без
добавлений. Отказ любой отправки или изменение scope терминальны: нет retry,
redial, relay fallback или повторной отправки исходной датаграммы при
неопределённом результате send. `Committed` появляется только после успешной
отправки всех K дополнительных пакетов и оригинала с актуальным scope.
Ошибка сбрасывает его; partial counters сохраняются. Это send witness, не
QUIC handshake, HTTP/3, доступность сайта или основание для LOCAL promotion.

## Собственный сокет и HTTP/3

`OpenQUICProbeSocket` проверяет живой Windows PID/birth через `IsCurrent`
и caller-owned network/profile/revision guard. В runtime дополнительный guard
проверяет PID/birth/image/SID через один process handle, как описано ниже. Source tuple выбирает ОС для
нового connected UDP socket; переданный извне source запрещён. Writer проверяет
этот tuple перед каждым send. Callback должен быть быстрым и потокобезопасным;
проверять только PID недостаточно. Изменение scope и отмена закрывают пробу.

Дополнительные Initial — обычные UDP payloads без специальных TTL/checksum
трюков. Поэтому сокет службы отправляет их напрямую, через `QUICProbeWriter`;
захват или делегирование service UDP в WinDivert не нужны. Полные IPv4/UDP
пакеты существуют только внутри packet plan; в socket передаются их payloads,
реальные заголовки/checksums создаёт ОС. Исключение собственного и relay-трафика
из capture сохраняется. Это не raw WinDivert injection браузерных datagrams.

`browserproxy.HTTP3ProbeManager` допускает одну пробу на manager, без очереди,
retry, TTL cache или записи в действующий TLS/CDN picker. Служба создаёт один
manager на controller; отдельный runtime ниже управляет общим budget, cooldown
и свежими triggers. Сам manager не запускает запросы по таймеру.

Caller задаёт reviewed DPI hostname, pinned public IPv4:443, browser PID/birth/
executable и network/profile/revision. Protected, relay-first и ordinary names,
private IP, IPv6 и другие порты отклоняются до открытия сокета. Manager сверяет
scope созданного сокета до первого datagram; имя независимо проверяется TLS.
Это подтверждает имя **собственной** пробы, а не origin зашифрованного браузерного
потока к тому же IP. Само наличие имени/IP в DNS не разрешает browser LOCAL.

Один QUIC v1 `Dial`, TLS1.3 с проверкой цепочки и hostname, ALPN h3, затем один
HTTP/3 `ClientConn.RoundTrip`: GET `/`, без query, тела, Cookie, Authorization,
client certificate, session cache или 0-RTT. RootCAs по умолчанию системные;
произвольный tls.Config или отключение verification не принимаются. Нет HTTP
redirect, повторного Dial/запроса, TCP/relay fallback или переключения peer.
Внутренняя QUIC recovery/retransmission разрешена в пределах того же соединения
и бюджета; это не повторный application request или replay браузерных bytes.

Ограничения одной пробы:

- общий deadline6s, QUIC handshake/idle timeout2s; смена scope проверяется перед
  send/открытием/запросом/публикацией и каждые50ms при зависшем чтении;
- до256KiB/256 принятых datagrams и64KiB/128 original отправленных datagrams;
  zero-length тоже расходует packet budget; concurrent writes сериализованы;
- fake flight отдельно: максимум16×1200=19200 UDP payload bytes, один раз;
- один request stream; входящие bidi запрещены, uni≤3; receive windows
  64KiB stream/128KiB connection; response headers≤8192bytes;
- требуется HTTP200, identity encoding и прочитанные32769bytes body. Redirect,
  короткое тело, reset до порога, неверный сертификат или scope не дают успеха.

Byte counters считают обработанные UDP payloads, не NIC wire traffic/IP headers;
входящий flood или очередь ОС не превращаются в измеренную экономию. После
32769bytes тело и соединение закрываются: полный ответ, страница и playback
не проверяются. Ошибка после этой выборки тоже неизвестна. Успех
`HTTP3_AUTHENTICATED_SAMPLE` требует одновременно verified TLS, актуального
scope и committed witness именно своего сокета. Результат не авторизует
браузерный flow, не создаёт LOCAL proof и не меняет established egress.

## Пассивное наблюдение origin в захвате

`localstrategy.QUICOriginObserver` читает только ClientHello нового QUIC v1
Initial. QUIC Initial packet protection снимается по публичным salt/DCID из
RFC9001: это не TLS session keys, TLS/application decryption, MITM или ECH
inner-name extraction. Поля SNI/h3 описывают намерение клиента, а не проверенный
сертификат сервера. Initial protection публична и не удостоверяет отправителя;
PID/birth/tuple привязывает Windows capture, не AEAD Initial.

На один разбор: UDP payload1200..1472bytes, до16datagrams и8192bytes CRYPTO,
deadline2s; новый flight начинается с PN0, рассматриваются только PN<64,
DCID8..20/SCID<=20, token пустой, все Initial имеют те же CIDs. Поддержаны
PADDING/PING/CRYPTO и совпадающие повторные/переставленные CRYPTO chunks;
конфликт overlap терминален. Весь coalesced datagram проверяется до публикации.
Retry/token, v2/version negotiation, short header, Handshake/0-RTT, reserved bits,
неизвестные frames, bad AEAD/lengths и превышение лимита не дают имени.

ClientHello должен иметь один валидный SNI, TLS1.3/h3 и QUIC transport parameter
initial_source_connection_id, совпадающий с SCID. Дубли extensions/parameters,
дополнительные handshake bytes, PSK/early_data отвергаются. Любой ECH extension,
включая GREASE, возвращает `QUIC_ORIGIN_ECH` без домена; inner name не угадывается.
Раскрытый CRYPTO buffer очищается после завершения, отказа или таймера.

В `processUDP` наблюдатель работает только для уже выбранного
`browser_native_quic_tcp_fallback` у текущего Chrome/Edge PID/birth/path,
точного tuple и непустых network/profile/revision. На backend не более32
незавершённых разборов и64 новых попыток в секунду, без очереди; state изменения
терминальны. Pending buffers очищаются таймером через2s даже без новых пакетов
и при Stop. Capacity/rate failure прекращает только наблюдение.

Результат идёт в существующую bounded ingress ring (24records) как
`QUIC_ORIGIN_OBSERVATION`/`quic_origin`, вместе с network/policy_revision и
имеющимися PID/birth/tuple/profile. Один historical incomplete и один terminal
sample на flow; истечение таймера без следующих datagrams может оставить лишь
исторический incomplete sample. Payload, CID, ClientHello и TLS secrets не
выводятся. Snapshot копирует metadata, не предоставляет mutable alias.

Оригиналы не удерживаются, не пересылаются и не воспроизводятся. Первый
заблокированный datagram по-прежнему сразу вызывает один ICMP port-unreachable;
последующие остаются blocked. Поэтому весь fragmented ClientHello не всегда
успеет попасть в capture до TCP fallback. Отсутствие имени в диагностике —
ожидаемый ограниченный результат, не основание задерживать fallback.

Даже видимое protected SNI остаётся BLOCK. Наблюдение не записывает
Decision.OriginDomain и DNS/CDN/route cache. Historical sample не запускает
пробу: нужен отдельный свежий одноразовый trigger текущего capture.

## Фоновый runtime службы

`quicFlowLedger` фиксирует kernel FLOW endpoint, PID/birth/path, точный tuple
и QPC timestamp. Первый UDP443 packet расходует разрешение до выбора политики,
в том числе при UDP-port owner fallback. FLOW должен предшествовать первому
пакету не более чем на2s; packet timestamp также должен быть свежим. После
полного видимого ClientHello trigger можно получить и расходовать ровно один
раз, не позднее2s от первого packet. Late/duplicate FLOW, cache expiry, смена
endpoint/owner и повторные packets не восстанавливают разрешение. Ledger
ограничен1024tuples; при переполнении временная граница не позволяет позднему
FLOW превратить ранее неучтённый packet в свежий. Неизвестный tuple запрещён.

Callback в packet loop только проверяет metadata, лимиты и Claim. Системные
identity calls, TLS и сеть выполняются worker. `CurrentQUICProcessOwner`
проверяет birth, полный image path, SID владельца установки и отсутствие exit
через **один OpenProcess handle**; повторно использованный PID не наследует
проверку. Token/SID/handle не попадают в диагностику. Worker перепроверяет
current owner, AUTO/native profile, network/revision, LOCAL enabled, capture
ready, отсутствие VPN/conflicts, static DPI floor и действующую origin policy.
Protected/ordinary и явные UDP flow rules не запускают пробу.

Один manager на controller, максимум одна QUIC-проба и один слот из общего
browser probe budget4, без очереди. Между попытками не менее30s; после sample
новый trigger того же key ограничен5min, после отказа3min. Cooldown map<=128,
история<=16. Изменение scope/отмена нейтральны, без negative route cache.
Повтор требует нового свежего FLOW и ClientHello; timer сам ничего не запускает.
Runtime использует6 дополнительных Initial; все прочие HTTP3 byte/time limits
сохранены. Нет relay fallback, DNS dial, credentials, replay браузерных bytes.

После Claim исходный browser socket может закрыться из-за ICMP: разрешена
только отдельно созданная bounded проба, уже не привязанная к его lifetime.
Capture restart и опубликованное изменение policy epoch отзывают trigger
навсегда; возвращение прежней конфигурации его не оживляет. Guard проверяется
перед каждым send, на завершении и watcher каждые50ms. Controller.Close
отменяет manager и ждёт освобождения worker/shared slot.

`browser.native.status.quic_probe` содержит ограниченную историческую сводку
attempts/observed/canceled и host/outcome/body_bytes. Это не readiness, не
LOCAL proof/cache и не правило маршрутизации. В частности authenticated sample
не доказывает допустимость следующих зашифрованных браузерных packets.

## Проверки

- Fresh FLOW, stale/future timestamps, late attribution, endpoint reuse/delete,
  duplicate/parallel Claim, overflow, capture/policy generations: разрешение
  одноразовое; после закрытия source socket оно относится лишь к owned probe.
- Native process handle: реальные SID/birth/image тестового chrome.exe,
  несовпадение SID/path/birth и завершение процесса запрещают пробу.
- Native controller guard: классификация BLOCK+callback, отказ пустого trigger,
  OFF/network/profile/revision/VPN/capture/owner/protected revocations.
- Runtime shared-budget saturation, no queue, close/cancel, neutral stale scope,
  global rate limit, exact-key cooldown, bounded history и snapshot isolation.

- Независимый quic-go client с гибридным key share и настоящим UDP loopback:
  fragmented ClientHello разбирается в scope; deadline/capacity/rate/epoch bounds.
- Native Windows `processUDP`: настоящий test chrome.exe PID/birth/path,
  видимые youtube/protected имена, исходные bytes неизменны, ровно1ICMP и0
  forwarded originals. Classifier/association и финальная запись WinDivert —
  seams; это не настоящее наблюдение Chrome/SOCKET событий или ISP-приёмка.
- Malformed/ECH/PSK/0RTT/Retry/v2/CID/overlap отрицательные сценарии и два bounded
  fuzz targets для Initial/ClientHello, по10000iterations.
- RFC9001 A.1 known-answer для key/IV/header-protection key.
- Раскрытие только сгенерированного нами Initial в тесте и обработка его
  ClientHello настоящим TLS parser: фиксированные SNI/ALPN, CRYPTO и padding.
- Byte identity, checksums, packet/repeat bounds, malformed/version/entropy/CID
  failures, отдельные runtime/catalog capabilities и bounded fuzzing.
- Ошибка на каждом из K+1 send, отмена на каждой границе и после оригинала,
  запрет повторного Send после ошибки, exact tuple и browser/process scope.
- Настоящий QUIC v1+mTLS на loopback,112KiB application body с проверкой SHA256,
  только одно принятое соединение, K=6, все исходные datagrams без изменений.
  С неверным server certificate пакетный план committed, но handshake отвергнут
  и application exchange отсутствует; проверки TLS не ослаблены.

- Настоящий HTTP/3 server и connected socket: authenticated sample32769bytes,
  wrong CA/name, redirect без follow,403, short/reset, compression/headers bounds,
  отсутствие witness, scope revoke, cancellation/deadline и чужой socket owner.
  На один вызов приходится ровно один socket open и максимум один HTTP request.
- Manager busy/Close, отмена до open, запрет protected/ordinary/private/IPv6,
  RX/TX byte/packet budgets, zero-length flood и concurrent writer bounds.

На Linux owner identity подставная; на Windows это PID/birth/path отдельного
тестового exe с именем chrome.exe. DNS/IP mapping —
loopback seam. HTTP/3 использует production socket helper, без подмены Send;
ранний raw QUIC+mTLS тест имеет отдельный packet send seam. Не запускался
Chrome или драйвер в QUIC-сценариях; SID проверен через native process token,
но не проверены cross-user installation ACL, реальные FLOW/SOCKET события,
WinDivert injection для QUIC, ISP, playback,
поведение браузера после отказа QUIC и экономия VPS. Full Linux/Windows Go
race/vet/build и pinned DLL compiler проверяются CI отдельно от этих сценариев.

## Решение о browser admission

[ADR-006](ADR-006-browser-quic-admission.md) фиксирует browser QUIC LOCAL как
unsupported в текущей архитектуре. Свежий owner/FLOW, видимый SNI и успех своей
пробы достаточны только для описанного диагностического пути. Отслеживание
смены CID и запрет миграции не обеспечивают origin каждого HTTP/3-запроса.

Для пересмотра нужен проверяемый механизм допуска до отправки каждого запроса,
включая повторное использование соединения разными origins. Дополнительный
parser/fuzz/ISP PASS этого условия не заменяет. R1 остаётся частично выполненным;
реальная Windows/ISP-приёмка отложена. Следующая фоновая проверка границы origin
для существующего HTTP/2 пути описана в ADR; QUIC-диагностика её не доказывает.
