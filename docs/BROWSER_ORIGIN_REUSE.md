# R1: HTTP/2 authority reuse

Проверка границы маршрутизации после открытия TLS-соединения. Один TLS
ClientHello/SNI не определяет authority всех последующих HTTP/2-запросов:
[RFC 9113 §9.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1)
допускает reuse для нескольких origin, в том числе через CONNECT.
Это отдельный gate R1; QUIC admission рассматривается в draft
[PR #53](https://github.com/buzzmean/veliq/pull/53).

## Изолированный сценарий

- Реальный Chromium, отдельный пустой профиль, один тестовый TLS endpoint,
  общий IP/port и короткоживущий SAN-сертификат для `www.youtube.com`,
  `youtube.com`, `chatgpt.com`. Эти имена перенаправлены только на фикстуру;
  к публичным сайтам, production или пользовательским данным обращений нет.
  Test-only allowlist отклоняет фоновые CONNECT до planner и native browser
  destinations кроме контролируемого TCP endpoint. Для изучаемого endpoint
  вызываются исходные classifier/planner службы; per-request фильтра не добавлено.
- Уникальный root добавляется в отдельный NSS store дочернего Linux-процесса
  либо временно в machine root store disposable Windows Actions VM. User-root import
  может требовать диалога Windows; machine store не используется вне этой VM. Проверка
  сертификатов включена; SPKI exception / ignore-certificate-errors не применяются.
  Root удаляется после теста, ключи и сертификаты не публикуются в evidence.
- ECH/GREASE отключён только в этом дочернем браузере; сервер проверяет отсутствие
  расширения `0xfe0d`. Проверяется reuse после явно видимого SNI, отдельно от
  известной native opaque-origin границы. QUIC отключён, чтобы измерять HTTP/2.
- Одна top-level страница последовательно получает четыре body: локальный
  DPI host, его sibling, REQUIRED host, повторный REQUIRED. Один network
  isolation key, fetch без credentials/cache. Сервер записывает connection ID,
  HTTP authority, исходный SNI, HTTP version, egress source и размер body.
  Браузер проверяет nonce каждого полностью прочитанного ответа.
- Контроль без VELIQ обязан показать coalescing всех authority на одном H2
  соединении. Если условие не достигнуто, это ошибка предусловия, не PASS изоляции.
- PAC использует настоящую `ChromeArguments`/per-authority proxy identity и
  controller owner/SID, planner/open callbacks. Native использует обычный signed
  WinDivert capture/filter, реальный owner и native opener. Установка службы,
  policy/recovery UI, реальные ISP и пользовательский браузер здесь не проверяются.
- В службе явно разрешён DIRECT для тестовых DPI hosts. Это моделирует уже
  допущенный локальный путь и не подменяет доказательство DPI transform или
  автоматического LOCAL learning. REQUIRED floor для `chatgpt.com` неизменён.
- Локальный egress — `127.0.0.1`; authenticated QUIC+mTLS relay с одноразовыми
  билетами — `127.0.0.2`. Учитываются реальные origin requests и relay bytes.
  Никакой TLS расшифровки/подмены между браузером и целевым сервером нет.
- Native проверяется в двух порядках: REQUIRED bootstrap → LOCAL fetch → REQUIRED
  fetch, затем отдельным процессом LOCAL bootstrap → LOCAL fetch → REQUIRED fetch.
  Egress bootstrap учитывается отдельно: правильный первый REQUIRED relay не
  доказывает маршрут позднейшего запроса после открытия локального соединения.
  Существующие соединения не мигрируют, запросы не повторяются службой.
- Те же два порядка отдельно проверяются с PAC и native AUTO. CONNECT authority
  передаётся существующему `PAC_NATIVE_UPSTREAM`; требуются реальные capture,
  owner PID/birth/profile, байты каждого authority, нулевой native-only ingress,
  DIRECT для обоих локальных имён и RELAY для REQUIRED независимо от порядка.
  Test-only wrapper меняет на TEST-NET только адрес зарезервированного службой
  сокета перехвата: Windows loopback не проходит обычный NETWORK filter.
  Неизменённый controller callback открывает настоящий loopback origin/relay;
  owner, пакеты, OPEN и счётчики не подменяются. Это проверка транспорта,
  не доказательство установки или подхвата PAC в пользовательском браузере.
  `CaptureIngress.Lost` — вытеснение metadata samples из кольца на 24 записи,
  не потеря пакетов: проверяются его lifetime atomic totals и число реальных
  reflected accepts. Отдельные native/PAC журналы соединений обязаны оставаться
  полными, с owner/policy и двусторонними байтами для каждого authority.
- Два live-policy сценария запускают Chromium без proxy flags и включают native
  capture только после первого полностью прочитанного LOCAL fetch. В одном owned
  HKCU PAC уже существует до запуска, в другом настоящий journal/writer службы
  устанавливает его после прогрева DIRECT H2. Сверяются неизменные PID/birth,
  серверные connection IDs и реальные CONNECT. После первого REQUIRED измеряется
  штатное удаление owned policy через native maintenance (existing-policy случай)
  либо повторный REQUIRED через 30 секунд (live install). Нет browser restart,
  reload, дополнительного RefreshPolicy или смены транспорта через CDP.
  Readiness enforcement/SCM/recovery provisioning здесь не сертифицируются.
  Повторный DIRECT доказывает pinned reuse только при том же connection ID/SNI;
  новый loopback DIRECT не считается доказательством native interception.
- Fresh-withdrawal сценарий после той же последовательности обращается к новому
  REQUIRED authority `api.openai.com`. Он включён только в тестовый SAN, заранее
  mapped на TEST-NET и ещё не встречался в ledger. Старые имена остаются на
  loopback; browser process/transport не меняется. Для двух новых ответов нужны
  новые серверные connection IDs, relay source, новые owner-bound capture records
  с REQUIRED floor и приращения capture/reflected/relay counters. Фактический
  `NATIVE_TCP` либо `PAC_NATIVE_UPSTREAM` учитывается отдельно: удалённая registry
  policy сама по себе не доказывает отказ браузера от cached PAC.

Сервер учитывает запрос до ответа: даже ответ 421/403 не отменяет факт
получения REQUIRED authority на неверном egress. `ORIGIN_ISOLATION_VIOLATION`
должен завершать routing gate ошибкой; нет continue-on-error или ожидаемого
успеха при утечке. Успешные full race/build checks сами по себе не закрывают gate.

## Проверено

01.11.2026, Linux Chromium `154.0.8037.57`: контроль без VELIQ воспроизвёл
все четыре HTTP/2-запроса на одном соединении, с SNI `www.youtube.com`,
включая оба `chatgpt.com` authority. Проверка с Go race PASS. Это доказательство
работоспособности сценария, не утверждение о маршрутизации VELIQ/публичных сайтов.

02.11.2026 MSK (01.11 UTC), Windows Chrome `156.0.8078.48`, code SHA
`a654618fab522de195281d4cfd58b385eaafa4e0`:
[run 41352232776, browser job 124984733487](https://github.com/buzzmean/veliq/actions/runs/41352232776/job/124984733487).
Baseline coalescing PASS, pinned DLL filters PASS. Artifact
`browser-origin-reuse-evidence`, ID `13101499474`, digest
`sha256:13e47ca1fb29e45d33859e4f94a9a07b165d274f5a67ce5620806d317e32fadd`
содержит только журналы контролируемого сценария, без ключей/сертификатов.

| Сценарий | Первый запрос | Последующие REQUIRED requests | Relay TCP / RX counter | Gate |
|---|---|---|---|---|
| PAC | LOCAL, source 127.0.0.1 | Оба на connection 5, SNI chatgpt.com, source 127.0.0.2 | 1 / 2499 | PASS, 0 DIRECT |
| PAC + native LOCAL first | LOCAL, connection 1, source 127.0.0.1 | Оба на connection 4, SNI chatgpt.com, source 127.0.0.2 | 1 / 2497 | PASS, 0 DIRECT |
| PAC + native REQUIRED → LOCAL | REQUIRED, connection 3, source 127.0.0.2 | Оба на connection 6, SNI chatgpt.com, source 127.0.0.2 | 4 / 8604 | PASS, 0 DIRECT |
| Native REQUIRED → LOCAL | REQUIRED, connection 1, SNI chatgpt.com, source 127.0.0.2 | Оба на connection 2, SNI www.youtube.com, source 127.0.0.1 | 1 / 2653 | FAIL, 2 DIRECT |
| Native LOCAL first | LOCAL, connection 1, source 127.0.0.1 | Оба на connection 2, SNI www.youtube.com, source 127.0.0.1 | 0 / 0 | FAIL, 2 DIRECT |

Connection IDs локальны для каждого запуска. В обоих hybrid сценариях локальный
и sibling fetch остались DIRECT: connections 2/3 либо 4/5 соответственно,
с собственными SNI и source `127.0.0.1`. REQUIRED bodies 41 и 47 bytes полностью
прочитаны браузером через relay. Первый REQUIRED bootstrap — отдельные 78 bytes.
Реальные delegated/connected/reflected/PAC opened/PAC exchanges составили 4/4/4/4/4
и 6/6/6/6/6; native-only accepted = 0 в обоих. Полные native/PAC connection ledgers
подтвердили три authority, правильные owner PID/birth/profile, policy и байты.

`relay_rx` — счётчик `relay.Metrics.RXBytes`, не размер HTTP body. Browser
preconnect и bootstrap могут создавать дополнительные tunnels: число relay TCP
не равно числу fetch и само по себе не доказывает маршрут. Серверный учёт каждого
запроса остаётся главным свидетельством egress. Capture metadata ring вытеснил
8/19 старых samples; его atomic totals и отдельные полные connection ledgers
сохранены; семантика счётчика определена в `platform/windows/capture_ingress.go`.

В обоих native-only сценариях connection 2 обслужил все четыре fetch с исходным
SNI `www.youtube.com` и source `127.0.0.1`. Новый REQUIRED open для поздних authority
отсутствует. Ненулевой relay counter первого native сценария относится только к
начальному соединению; в LOCAL-first relay bytes нет. Все соединения созданы после
включения controller/capture, это не только исключение pre-activation TCP.

Это **воспроизведённое нарушение изоляции origin у native DIRECT-пути** в
заданных условиях общего SAN/IP/port. Не установлен факт общей SAN-связи
публичных YouTube/OpenAI; не доказана утечка их реального трафика. DIRECT+
transform, автоматическое LOCAL learning, ECH, Edge, policy uptake/recovery,
IPv6, пользовательские сети и произвольные будущие версии браузера этим
сценарием не приняты. Продуктовый код не изменён, R1 остаётся частично готовым.

Полные Go race/vet/build CODE a654618:
[Windows job 124984733288](https://github.com/buzzmean/veliq/actions/runs/41352232776/job/124984733288)
PASS;
[Linux + PostgreSQL 17, job 124984733368](https://github.com/buzzmean/veliq/actions/runs/41352232773/job/124984733368)
PASS. C# 218 PASS в Edge workflow. Общий CI сохраняет прежние failures:
Python rollback (99/100), WPF `Empty visual: actual-RelayChoice`,
Edge `Edge AUTO requires verified Edge CONNECT/PAC`.
[Chrome policy/actual-driver](https://github.com/buzzmean/veliq/actions/runs/41352232798)
PASS. Два native-only origin FAIL остаются открыты: успешные сборки и три
PAC/hybrid PASS не закрывают весь routing gate.

## Работающий Chromium и owned policy

02.11.2026 MSK (01.11 UTC), Chrome `156.0.8078.80`, code
`079e73142d3890e35631387538403fd686f3dd67`:
[run 41355656822/job 124995009467](https://github.com/buzzmean/veliq/actions/runs/41355656822/job/124995009467).
Artifact `13102064835`, `browser-origin-reuse-evidence`, digest
`sha256:0acdcc59c629d3153ce221014e0ca32a96294d661144eb5e847d8e1e97d9e795`.
Baseline coalescing и pinned DLL filters PASS. Вся матрица: PAC/hybrid/owned-before
4 PASS, live-install и два native-only сценария 3 FAIL. FAIL не подавлены.

| Сценарий | Наблюдение | Вывод |
|---|---|---|
| Owned PAC до запуска Chromium; native включён после LOCAL fetch | LOCAL connection 2 и sibling 3 DIRECT, REQUIRED connection 4 RELAY; 2 hybrid exchanges, 2 connected/reflected, relay TCP 1/RX 2497 | PASS для данного перехода; PID/birth не изменились |
| Штатный native maintenance после первого REQUIRED | Registry policy удалена, listener сохранён; через 3048 ms после активации повторный REQUIRED остался на том же relay connection 4 | Уже открытый tunnel сохранился; будущие новые соединения после удаления ещё не приняты |
| Owned PAC записана в уже работающий Chromium после LOCAL fetch | Registry active; через 30031 ms CONNECT/hybrid/relay counters всё ещё 0, `POLICY_PENDING_BROWSER_REFRESH` | Live uptake не доказан в этом окне; нельзя обещать мгновенное включение или конечный срок |

В live-install LOCAL был на connection 3/SNI `www.youtube.com`; sibling и оба
REQUIRED — на **новом** connection 4/SNI `youtube.com`, source `127.0.0.1`.
Следовательно, `pre_activation_reuse=0`, `fresh_loopback_unproven=2`.
Это достоверное отсутствие PAC ingress и два DIRECT-запроса к фикстуре, но не
новое доказательство обхода native capture: Windows loopback исключён NETWORK
filter. Gate сообщает `LIVE_POLICY_UPTAKE_NOT_PROVEN` и
`LIVE_POLICY_REQUIRED_ROUTE_NOT_PROVEN`; не приписывает этому случаю нарушение
pre-activation pinning. Ранее подтверждённые native-only нарушения используют
TEST-NET и остаются отдельными actual-capture FAIL.

Проверены реальные journal/writer, `nativeBrowserCompatibility` и один явный вызов
`RetrySilentBrowserPolicies` в заданной фазе. Полный `Controller.Start`, SCM,
readiness enforcement и recovery не запускаются. Live-install оставляет policy
на всё окно наблюдения; обычный native maintenance мог бы удалить её раньше.
Поэтому этот опыт не сертифицирует весь продуктовый startup/lifecycle.
В частности, используется исходный guarded PAC. При включённом readiness
enforcement `reapplySilentLocked` преобразует его через `AvailabilityPAC`,
добавляющий DIRECT в browser proxy fallback при недоступности proxy infrastructure.
Это отказ от proxy, а не доказанный DIRECT egress: маршрут ещё зависит от native
capture. Успех healthy
guarded-PAC сценария не доказывает fail-closed этого режима при потере listener
или capture; следующий outage gate должен учитывать обе фактические формы PAC.
Фактическое удаление согласуется с текущим кодом, но расходится с историческим
обещанием постоянного PAC guard: [уточнение области старого варианта A](BROWSER_SILENT_POLICY.md).
После удаления `POLICY_OR_LISTENER_UNAVAILABLE` означает недоступную registry
policy, хотя сохранённый listener и старый relay tunnel продолжают работать.

Полные Go race/vet/build этого code SHA:
[Windows 124995009381](https://github.com/buzzmean/veliq/actions/runs/41355656822/job/124995009381)
и [Linux + PG17 124995008859](https://github.com/buzzmean/veliq/actions/runs/41355656769/job/124995008859)
PASS. Chrome policy/actual-driver, Game UDP и isolated upgrade PASS; C# 218 PASS.
Общий CI сохраняет прежние Python rollback (99/100), WPF `actual-RelayChoice`
и Edge `verified CONNECT/PAC` failures. Эти результаты не закрывают три
отрицательных browser gate и не являются приёмкой на ПК/ISP.

## Свежий REQUIRED после удаления policy

02.11.2026 MSK (01.11 UTC), Chrome `156.0.8078.48`, code
`17f627350676e1455269fb8d90457309baad530e`:
[run 41357412180/job 125000355256](https://github.com/buzzmean/veliq/actions/runs/41357412180/job/125000355256).
Artifact `13103528800`, `browser-origin-reuse-evidence`, digest
`sha256:be68e991e054f3ce83e1dbe9f474efc6a4d9c251558c57cd4811d2f0350a1e7d`.
Baseline coalescing и pinned DLL filters PASS. Новый
`FreshRequiredAfterPACWithdrawal` PASS; вся browser matrix — 5 PASS, 3 FAIL
(live-install pending и два ранее подтверждённых native-only нарушения).

После настоящего удаления owned registry value и повторного запроса по старому
relay tunnel тот же browser process впервые запросил `api.openai.com`.
До этого authority отсутствовал в native ledger. Его mapping на TEST-NET задан
до запуска; ни proxy flags, ни DNS/transport mutation через CDP не добавлены.

| Проверка | Фактический результат |
|---|---|
| Server connection / initial SNI | Новый connection 5 / api.openai.com; прежние connections не использованы |
| Egress и полные body | Оба ответа source 127.0.0.2, HTTP/2, 47 и 53 bytes, browser nonce проверен |
| Owner и policy | Новая owner-bound запись с PID/birth/profile, RELAY_REQUIRED + Required fallback |
| Ingress | PAC_NATIVE_UPSTREAM: 1 exchange; NATIVE_TCP: 0 новых exchange для этого authority |
| Новые capture/relay данные | TCP packets +42, reflected accepts +1, relay TCP +1, relay RX +2511 |
| Registry | Owned policy отсутствует до и после fresh phase |

Удаление registry value **не перевело этот браузер в native-only**: он продолжил
пользоваться cached PAC и compatibility listener даже для нового authority.
Это проверка свежего relay open с реальным capture, а не только старого pinned
туннеля. Длительность сохранения cached PAC, произвольные будущие версии Chrome,
отказ listener/capture/relay и режим AvailabilityPAC этим PASS не приняты.
Счётчик relay RX не равен размеру HTTP body; metadata ring и полные application
ledgers по-прежнему учитываются раздельно.

Полные Go race/vet/build code 17f6273:
[Windows 125000354999](https://github.com/buzzmean/veliq/actions/runs/41357412180/job/125000354999)
и [Linux + PG17 125000354876](https://github.com/buzzmean/veliq/actions/runs/41357412150/job/125000354876)
PASS; C# 218, Game UDP и isolated upgrade PASS. Общий CI красный: сохраняются
Python rollback (99/100), WPF `actual-RelayChoice`, Edge `verified CONNECT/PAC`.
Chrome policy PASS, но [отдельный actual-driver job 125000355273](https://github.com/buzzmean/veliq/actions/runs/41357412172/job/125000355273)
снова завершился assertion `route leak` с пустой policy в
`browser_native_windows_test.go:249`. Причина этого ранее наблюдавшегося сбоя
не установлена; новый fresh-origin PASS его не исправляет.

## Граница readiness: следующий контракт

Текущие статусы отвечают на разные вопросы. Их нельзя объединять в одну
гарантию изоляции каждого запроса:

| Наблюдение в текущем коде | Что подтверждает | Чего не подтверждает |
|---|---|---|
| `NATIVE_READY_NEW_CONNECTIONS` | Capture готов, relay доступен | Был ли реальный browser exchange; authority позднейших H2 requests |
| `NATIVE_ONLY_OBSERVED` | Реальные native-only двусторонние байты | Совпадение каждого authority с исходным SNI |
| `PAC_NATIVE_UPSTREAM` exchange | Конкретный owner-validated CONNECT прошёл native worker | Подхват policy всеми работающими контекстами браузера |
| `OWNED_PAC_PRESERVED` / запись registry | Сохранена принадлежащая службе конфигурация | Применение policy браузером, закрытие старых direct sockets |
| Успех данного origin gate | В указанной версии/профиле разделены проверенные authority | Универсальная гарантия для Edge, будущих версий, ECH, IPv6 или старых connections |

Источники: `browser_native_readiness.go`, `browser_policy_readiness.go`,
`browser_native_compat.go`, `browser_native_pac.go` в `services/client-service/`.
В частности, `browserPolicyHealth` для native profile использует `NativeOnly`,
а не `PACUpstream`: успешный hybrid тест не должен искусственно повышать этот
счётчик или превращаться в ложное native-only подтверждение.

Перед реализацией отдельной strict-origin capability нужны следующие условия
приёмки; это предлагаемый контракт, не новые поля API или уже включённый режим:

1. Разделить capture readiness, наблюдённый ingress и изоляцию authority.
   Ограничить доказательство конкретными browser/profile, живыми owner PID/birth/SID,
   network/policy epoch, listener и per-authority proxy identity. Не выводить его
   из одного успешного nonce, TLS handshake или исторического счётчика.
2. В disposable Windows VM проверить сохранённую owned policy с браузером,
   запущенным до активации. Сопоставить реальные CONNECT, capture и server egress
   обоих порядков authority, сохранив PID/birth. Отдельно проверить отсутствие
   policy, чужую/устаревшую policy и отсутствие uptake. Не заменять эти случаи
   новым процессом с `--proxy-pac-url`, диалогом или принудительным reload.
3. При потере relay/listener/capture либо смене owner/network/policy отозвать
   соответствующее доказательство; REQUIRED не разрешать через DIRECT fallback.
   Повторный READY требует нового наблюдения в актуальном контексте. Проверить
   отзыв и восстановление фактическим egress, а не только строкой статуса.
4. Явно учитывать старые pinned H2 connections: новый PAC не переписывает их
   маршрут. Без доказательства их завершения/исключения нельзя обещать защиту
   всех requests работающего браузера. Не разрывать их и не replay/migrate TLS.
   Сохранить DIRECT/LOCAL для допустимого трафика и отдельный REQUIRED floor.

## Матрица одиночных отказов после withdrawal

Новые `Listener/Capture/RelayOutage{Guarded,Availability}` выполняют исходную
owned-policy последовательность, удаляют registry policy штатным maintenance,
затем реально останавливают ровно один компонент. Listener закрывает свои
соединения и возвращается на тот же port; capture выполняет Stop/Start;
relay закрывает server и pool, после восстановления использует новые mTLS sessions
и одноразовые tickets. Это управляемые lifecycle callbacks, не полный SCM/recovery.
Availability-вариант использует точный `AvailabilityPAC` script; readiness enforcement
не включается и его полный lifecycle этим не принимается.

Браузер остаётся тем же, без reload/reset proxy state. По одному новому REQUIRED
и ordinary authority запрашиваются во время отказа и после восстановления.
TEST-NET адреса различаются, чтобы исключить coalescing со старым соединением.
Исключение — capture outage: его две fault-authority заранее mapped на доступный
loopback origin. При выключенном capture TEST-NET blackhole мог бы скрыть DIRECT
fallback; reachable endpoint делает такое ложное доказательство невозможным.
Recovery-authority опять требуют actual capture. Старые flows закрываются только
как реальное следствие остановки компонента, специально для свежего запроса их
не разрывают. Восстановление нового authority не доказывает очистку bad-proxy
cache уже неудачного authority.

Fetch имеет 6s deadline; исход браузера, серверные запросы до ответа, actual ingress,
owner/floor, native/PAC ledgers и приращения relay/capture проверяются отдельно.
Ожидаемый барьер: REQUIRED не достигает DIRECT; разрешённый DIRECT не отправляется
в relay. Availability при потерянном listener проверяет native fallback; недоступность
ordinary при остановленном capture/guarded listener учитывается явно. Ни error
браузера, ни пустой серверный ledger по отдельности не дают PASS. Одновременная
потеря listener+capture, crash guard, долгий lifecycle и повтор неудачного authority
остаются отдельными gates.

02.11.2026 MSK (01.11 UTC), Chrome `156.0.8078.80`, code
`d7ecc28b0515bd0a909244d8c2e9267ecf1c5dff`:
[run 41358865000/job 125004701506](https://github.com/buzzmean/veliq/actions/runs/41358865000/job/125004701506).
Все **6 новых сценариев PASS**; вся матрица **11 PASS / 3 FAIL**. Baseline coalescing
и actual pinned DLL filters PASS. Artifact `browser-origin-reuse-evidence`,
ID `13104102853`, digest
`sha256:a4ac8e29465bf745a25706df210898f60556710d04562f0af4cb542c38767d58`.

| Отказ | PAC | REQUIRED во время отказа | Ordinary во время отказа | Новые authority после восстановления |
|---|---|---|---|---|
| Listener | guarded | FetchError, серверных запросов 0 | FetchError, запросов 0 | REQUIRED RELAY, ordinary DIRECT |
| Listener | Availability | RELAY через NATIVE_TCP | DIRECT через NATIVE_TCP | REQUIRED RELAY, ordinary DIRECT |
| Capture | guarded | CONNECT open failed, запросов 0 | CONNECT open failed, запросов 0 | REQUIRED RELAY, ordinary DIRECT |
| Capture | Availability | CONNECT open failed, запросов 0 | CONNECT open failed, запросов 0 | REQUIRED RELAY, ordinary DIRECT |
| Relay + его pool | guarded | OPEN_IO_FAILED, запросов 0 | DIRECT через PAC_NATIVE_UPSTREAM | REQUIRED RELAY, ordinary DIRECT |
| Relay + его pool | Availability | OPEN_IO_FAILED, запросов 0 | DIRECT через PAC_NATIVE_UPSTREAM | REQUIRED RELAY, ordinary DIRECT |

У listener Availability REQUIRED действительно дошёл до origin с source
`127.0.0.2`: connection 7/SNI outage.openai.com, body 48 bytes. Ordinary на
connection 8/source `127.0.0.1`, body 46 bytes. Native records показали
`NATIVE_TCP`, RELAY_REQUIRED/Required и DIRECT; relay TCP/RX приросли на 1/2409.
Таким образом, browser proxy fallback DIRECT в этом случае не стал DIRECT egress
для REQUIRED: работающий capture открыл relay по новому SNI. Это не разрешает
переносить вывод на поздние authority внутри уже открытого H2.

При capture outage listener оставался доступен, capture readiness был false.
Оба PAC получили `UPSTREAM_OPEN_FAILED` за 2–4 ms без обращения к доступному
loopback origin. Не было DIRECT retry после отказа CONNECT в этом браузере;
при этом ordinary тоже недоступен. При relay outage REQUIRED получил
`OPEN_IO_FAILED` за 6–8 ms, ordinary сохранил DIRECT, relay TCP/RX delta = 0.
Это быстрый явный отказ закрытого pool/server, не silent blackhole/standby acceptance.

Во всех шести recovery новые REQUIRED/ordinary authority дали полные HTTP/2 body
50/48 bytes, разные новые server connection IDs, правильные source и owner-bound
`PAC_NATIVE_UPSTREAM` records. Каждый recovery добавил 1 relay TCP и 2413–2415 RX
bytes; capture/reflected increments и полнота application ledgers проверены
assertions. Browser PID/birth не менялись, registry policy оставалась удалённой.
Listener возвращался на прежний port. Нет доказательства, что bad-proxy cache
у неудачного старого authority очистился: после recovery использовались другие имена.

Прежние три failures сохранились: live-install за 30s pending/CONNECT=0 и два
native-only случая с 2/2 REQUIRED DIRECT. Fresh-after-withdrawal снова PASS через
PAC_NATIVE_UPSTREAM (native-only=0, capture TCP +40/reflected +1, relay +1/+2512).
Runtime не менялся; эта матрица не исправляет native origin isolation и не закрывает R1.

Полный Linux Go race/vet/build + PostgreSQL17 PASS:
[job 125004701385](https://github.com/buzzmean/veliq/actions/runs/41358865009/job/125004701385).
Затем прежний Python rollback #35 (99/100). Полный Windows Go race/vet/build
[job125004701705](https://github.com/buzzmean/veliq/actions/runs/41358865000/job/125004701705)
на 01.11 23:10 UTC всё ещё `in_progress` в общем шаге; завершённый журнал пока
недоступен. Это **PENDING**, не PASS и не подтверждённый timeout. Целевой browser
job и DLL filters уже завершены отдельно. Повторный общий прогон не запускался;
перед дальнейшими Go-изменениями проверить результат именно этого job.
C#218 PASS. Общий CI сохраняет
WPF actual-RelayChoice #36/job125004701218 и Edge verified CONNECT/PAC
#37/job125004700877. Chrome policy/actual-driver run41358864943, Game UDP
run41358864935, isolated upgrade run41358864932 (оба варианта) PASS. Chrome
actual-driver PASS в этом запуске не объясняет предыдущий intermittent empty-policy
failure на17f6273; он не исправлен этой тестовой правкой.


## Продолжение R1

1. Разделение proxy identity по authority подтверждено для PAC и существующего
   `PAC_NATIVE_UPSTREAM` с native AUTO и фактическим capture/owner/egress accounting.
   Переход с owned PAC, существующей до браузера, теперь проверен; live-install
   остаётся pending в измеренном 30-секундном окне. Свежий authority после policy
   withdrawal прошёл через cached PAC + native upstream; шесть одиночных
   outage/recovery сценариев выше также PASS. Следующий gate — одновременная
   потеря listener и capture при физически доступном DIRECT endpoint, отдельно
   guarded/AvailabilityPAC и без ложного PASS по TEST-NET blackhole. Это измерение
   границы crash guard, не обещание его наличия. Затем — повтор уже неудачного
   authority/bad-proxy cache и полный startup/recovery/strict readiness. Не заменять
   эти проверки повтором уже принятого здорового fresh-flow сценария.
2. Явно разделить гарантии: native наблюдение SNI привязано к соединению;
   строгая изоляция каждого запроса требует подтверждённого браузерного
   transport-контекста. Нельзя объявлять gate закрытым по корректному первому
   REQUIRED open, TLS успеху, SYN count или ещё одному SNI/IP cache.
3. Сохранить existing-flow pinning/no replay, известный REQUIRED floor и
   экономию DIRECT/LOCAL. Не вводить скрыто полный RELAY браузера, MITM,
   извлечение ключей, расширение или принудительный restart/policy reload.
   Независимый WFP guard сам не раскрывает HTTP/2 authority:
   [действующая архитектурная граница](BROWSER_NATIVE_GUARD.md#отдельное-ограничение-имя-сайта-не-всегда-доступно).
4. Сохранить `ORIGIN_ISOLATION_VIOLATION` как failure до реального исправления
   или явно принятого другого контракта. Это draft с воспроизведением,
   не готовое исправление и не разрешение на merge/rollout.

## Запуск

Linux baseline (нужны Chromium и NSS certutil):

```sh
NEEXITLAG_TEST_ORIGIN_REUSE=1 go test -race -v ./internal/browserfixture -run '^TestChromiumOriginReuseBaseline$' -count=1 -timeout=70s
```

Полный Windows сценарий — workflow `Browser HTTP2 origin reuse`, на отдельной
Actions VM с pinned DLL и app-scoped firewall rule. Trust/capture opt-in
преднамеренно не поддерживает запуск на установленном пользовательском ПК.
Workflow также проверяет полный Windows Go race/vet/build и все WinDivert
filters; Linux Go race/vet/build с PostgreSQL — `relay-release.yml` того же SHA.
