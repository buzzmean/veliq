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

Сервер учитывает запрос до ответа: даже ответ 421/403 не отменяет факт
получения REQUIRED authority на неверном egress. `ORIGIN_ISOLATION_VIOLATION`
должен завершать routing gate ошибкой; нет continue-on-error или ожидаемого
успеха при утечке. Успешные full race/build checks сами по себе не закрывают gate.

## Проверено

01.11.2026, Linux Chromium `154.0.8037.57`: контроль без VELIQ воспроизвёл
все четыре HTTP/2-запроса на одном соединении, с SNI `www.youtube.com`,
включая оба `chatgpt.com` authority. Проверка с Go race PASS. Это доказательство
работоспособности сценария, не утверждение о маршрутизации VELIQ/публичных сайтов.

Windows Chrome `156.0.8078.48`, code SHA
`b7152cda63265316a0a48a3f1dc05dcf8f426ecd`:
[run 41349924470, browser job 124977693377](https://github.com/buzzmean/veliq/actions/runs/41349924470/job/124977693377).
Baseline coalescing PASS, pinned DLL filters PASS. Artifact
`browser-origin-reuse-evidence`, ID `13101050932` содержит только журналы
контролируемого сценария, без ключей/сертификатов/пользовательских данных.

| Сценарий | Первый запрос | Последующие REQUIRED requests | Relay TCP / RX counter | Gate |
|---|---|---|---|---|
| PAC | LOCAL, source 127.0.0.1 | Оба на отдельном connection 5, SNI chatgpt.com, source 127.0.0.2 | 1 / 2497 | PASS, 0 DIRECT |
| Native REQUIRED → LOCAL | REQUIRED bootstrap на connection 1, SNI chatgpt.com, source 127.0.0.2, body 78 bytes | Оба на connection 2, SNI www.youtube.com, source 127.0.0.1 | 1 / 2654 | FAIL, 2 DIRECT |
| Native LOCAL first | LOCAL bootstrap на connection 1, source 127.0.0.1 | Оба на connection 2, SNI www.youtube.com, source 127.0.0.1 | 0 / 0 | FAIL, 2 DIRECT |

Connection IDs локальны для каждого запуска. В обоих native сценариях
connection 2 обслужил `www.youtube.com`, `youtube.com`, затем оба запроса
`chatgpt.com`. Сервер получил authority REQUIRED, браузер полностью прочитал
ответы 41 и 47 bytes. `relay_rx` — счётчик `relay.Metrics.RXBytes`, не размер
HTTP body. Ненулевой relay counter первого сценария native относится к
первоначальному соединению и не доказывает маршрут позднейших запросов.

Native record с SNI `www.youtube.com` остаётся DIRECT; новый REQUIRED open для
последующих authority отсутствует. В LOCAL-first вообще нет relay bytes.
Все эти соединения созданы после включения контроллера и capture: это не только
исключение для сокетов, существовавших до активации. Свежий REQUIRED bootstrap
действительно идёт через relay, что отдельно подтверждено серверным source.

Это **воспроизведённое нарушение изоляции origin у native DIRECT-пути** в
заданных условиях общего SAN/IP/port. Не установлен факт общей SAN-связи
публичных YouTube/OpenAI; не доказана утечка их реального трафика. DIRECT+
transform, автоматическое LOCAL learning, ECH, Edge, policy uptake/recovery,
IPv6, пользовательские сети и произвольные будущие версии браузера этим
сценарием не приняты. Продуктовый код не изменён, R1 остаётся частично готовым.

Полные Go race/vet/build CODE b7152cd:
[Windows job 124977693452](https://github.com/buzzmean/veliq/actions/runs/41349924470/job/124977693452)
PASS;
[Linux + PostgreSQL 17, job 124977693256](https://github.com/buzzmean/veliq/actions/runs/41349924467/job/124977693256)
PASS. Linux workflow далее падает на прежнем Python rollback-тесте; общий Verify
также сохраняет WPF `Empty visual: actual-RelayChoice`, Edge acceptance —
`Edge AUTO requires verified Edge CONNECT/PAC`. Общий CI не зелёный.
Chrome policy/actual-driver, Game UDP и isolated upgrade того же SHA прошли.
Эти результаты отделены от красного origin routing gate: прохождение сборки
не означает устранения нарушения.

## Продолжение R1

1. Для строгой per-request изоляции использовать уже имеющееся разделение
   proxy identity по authority, подтверждённое PAC-сценарием. Следующий шаг —
   проверить этот же gate для `PAC_NATIVE_UPSTREAM` с native AUTO profile и
   фактическим capture/owner/LOCAL/RELAY accounting; отдельно проверить readiness
   и незаметный подхват существующей owned policy. Текущий тест PAC не утверждает
   её установку или подхват работающим пользовательским браузером.
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
