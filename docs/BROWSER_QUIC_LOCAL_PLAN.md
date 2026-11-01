# QUIC LOCAL: собственная ограниченная HTTP/3-проба

01.11.2026. Блок R1 для QUIC: пакетный план, собственный connected UDP socket
и ограниченный менеджер authenticated HTTP/3-пробы службы. **Автоматический QUIC LOCAL
браузера пока не включён.** Нет нового IPC, конфигурационного переключателя,
автоматического запуска проб службой, изменения Classify, UDP443 capture или игровой политики.

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
политики: нужен новый writer для новой пробы. Production capture не создаёт этот writer.

На writer допускается одна fake flight. Последующие datagrams сохраняются без
добавлений. Отказ любой отправки или изменение scope терминальны: нет retry,
redial, relay fallback или повторной отправки исходной датаграммы при
неопределённом результате send. `Committed` появляется только после успешной
отправки всех K дополнительных пакетов и оригинала с актуальным scope.
Ошибка сбрасывает его; partial counters сохраняются. Это send witness, не
QUIC handshake, HTTP/3, доступность сайта или основание для LOCAL promotion.

## Собственный сокет и HTTP/3

`OpenQUICProbeSocket` проверяет реальный Windows PID/birth/path через `IsCurrent`
и caller-owned network/profile/revision guard. Source tuple выбирает ОС для
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
retry, TTL cache или записи в действующий TLS/CDN picker. Новый запрос требует
отдельного явного вызова; служба пока не создаёт manager. Перед будущим runtime
подключением нужен один manager на controller и общий бюджет с другими пробами.

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

## Проверки

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
Chrome или драйвер; не проверены SID/ACL, WinDivert injection, ISP, playback,
поведение браузера после отказа QUIC и экономия VPS. Full Linux/Windows Go
race/vet/build и pinned DLL compiler проверяются CI отдельно от этих сценариев.

## Следующая граница R1

Перед подключением к runtime нужны общий бюджет вместе с другими пробами,
проверенная привязка origin к новому QUIC flow и current process/SID/profile/network,
ограниченные positive/negative TTL и отдельный admission для browser flow.
Собственная HTTP/3-проба и её socket witness этих условий не заменяют. Отмена не должна публиковать старый proof.
QUIC v2, Retry, connection migration и short headers не получают разрешения
по старому tuple или чужому CID. Protected/ambiguous остаются на существующем
TCP fallback. Established flow не переводится на другой egress, application
bytes не воспроизводятся повторно. После изолированных регрессий потребуется
отдельная WinDivert/ISP-приёмка; она пока отложена владельцем.
