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

## Продолжение R1

1. Разделение proxy identity по authority подтверждено для PAC и существующего
   `PAC_NATIVE_UPSTREAM` с native AUTO и фактическим capture/owner/egress accounting.
   Следующий шаг — проверить условия readiness выше: незаметный подхват owned policy
   уже работающим браузером, потерю/восстановление transport и старые pinned flows.
   Нынешние сценарии используют явно заданный PAC нового test process; их PASS
   не доказывает установку policy или её подхват пользовательским браузером.
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
