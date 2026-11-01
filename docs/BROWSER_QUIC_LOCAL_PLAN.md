# QUIC LOCAL: пакетный план для отдельной пробы

01.11.2026. Первый блок R1 для QUIC — подготовка ограниченного пакетного плана
и отправителя для будущей собственной пробы службы. **Автоматический QUIC LOCAL
браузера пока не включён.** Нет нового IPC, конфигурационного переключателя,
фонового worker, изменения Classify, UDP443 capture или игровой политики.

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
должен быть публичным, owner и source заданы. Это scope будущей service-пробы,
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

На Linux owner identity подставная; на Windows это PID/birth/path отдельного
тестового exe с именем chrome.exe. DNS/IP mapping и packet capture/injection —
seams, payload передаётся настоящим UDP socket. Не запускался Chrome, драйвер
или HTTP/3 сервер; не проверены SID/ACL, WinDivert injection, ISP, playback,
поведение браузера после отказа QUIC и экономия VPS. Full Linux/Windows Go
race/vet/build и pinned DLL compiler проверяются CI отдельно от этих сценариев.

## Следующая граница R1

Перед подключением к runtime нужны общий bounded probe budget/deadline,
проверенная привязка origin к новому QUIC flow и current process/SID/profile/network,
commit witness именно его socket, независимая authenticated HTTP/3-проверка
и ограниченные positive/negative TTL. Отмена не должна публиковать старый proof.
QUIC v2, Retry, connection migration и short headers не получают разрешения
по старому tuple или чужому CID. Protected/ambiguous остаются на существующем
TCP fallback. Established flow не переводится на другой egress, application
bytes не воспроизводятся повторно. После изолированных регрессий потребуется
отдельная WinDivert/ISP-приёмка; она пока отложена владельцем.
