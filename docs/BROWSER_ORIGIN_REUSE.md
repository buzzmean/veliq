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

Windows PAC/native и полный CI будут зафиксированы после фактического прогона.

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
