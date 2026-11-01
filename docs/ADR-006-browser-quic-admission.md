# ADR-006: граница допуска браузерного QUIC LOCAL

Дата: 01.11.2026. Статус: принято для текущей архитектуры; browser QUIC LOCAL
остаётся unsupported. Решение сохраняет существующее поведение и не закрывает R1.
Проверенный код: `0d815512465e3d65cf76482291bcf7a42dafcf22`, draft
[PR #53](https://github.com/buzzmean/veliq/pull/53), база `main` = `17bae34`.

## Решение

Не добавлять переход от видимого Initial SNI, свежего FLOW, совпадающего CID или
успеха собственной HTTP/3-пробы к пересылке браузерных QUIC datagrams. Для
активного выбранного native AUTO Chrome/Edge UDP443 сохраняется BLOCK с одним
ICMP port-unreachable на flow и возможностью браузера открыть новый TCP-поток.

Собственный HTTP3 runtime остаётся ограниченной диагностикой. Его успешная
выборка не записывает browser LOCAL proof и сама по себе не экономит VPS-трафик.
Истечение cooldown разрешает рассмотреть новый trigger, но не выдаёт маршрут.
Поведение OFF, DIRECT/MANUAL, других приложений, игр и QUIC relay transport
этим решением не меняется.

Узкий режим «только QUIC v1, без ECH/0-RTT/Retry, фиксированный tuple/CID»
не принят как безопасный browser admission. Проблема остаётся даже при полностью
неподвижном соединении: VELIQ не получает проверяемый origin каждого запроса.
Это ограничение имеющихся наблюдений, а не обещание устранить его ещё одним
парсером или увеличением числа успешных сетевых проб.

## Что установлено по спецификациям

- CID служит идентификатором соединения. Уже первый server Initial может задать
  новый destination CID для клиента; последующие CID выдаются через
  NEW_CONNECTION_ID. Short header не несёт явной длины CID. Поэтому начальный
  DCID нельзя закрепить как постоянный идентификатор всего сеанса
  ([RFC 9000, §5.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1),
  [§7.2–7.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-7.2)).
- Initial protection использует публично выводимые ключи; для остальных уровней
  нужны TLS traffic secrets. Серверные transport parameters передаются в
  EncryptedExtensions, а их подлинность устанавливается завершённым handshake
  ([RFC 9001, §5](https://www.rfc-editor.org/rfc/rfc9001.html#section-5),
  [§8.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-8.2)).
- HTTP/3 допускает повторное использование соединения для другого URI authority,
  если клиент проверил сертификат сервера для нового origin. Новый ClientHello
  для каждого запроса не требуется
  ([RFC 9114, §3.3](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.3)).
  HTTPS authority определяется проверкой сертификата, а не одним IP
  ([RFC 9110, §4.3.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.3.3)).
- Запрет active migration относится к получателю соответствующего transport
  parameter. Он не является запретом смены HTTP origin; NAT rebinding также
  отличается от намеренной миграции
  ([RFC 9000, §9.3](https://www.rfc-editor.org/rfc/rfc9000.html#section-9.3),
  [§18.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2)).

Инженерный вывод для VELIQ: текущий capture видит транспортные признаки и
начальное имя, но не проверяет браузерный handshake, зашифрованные
NEW_CONNECTION_ID/PATH_CHALLENGE или HTTP `:authority`. Собственный TLS endpoint
службы располагает ключами только своей пробы. Его результат нельзя перенести
на другое соединение браузера, даже если совпадают hostname и destination IP.

## Контрпример условию «тот же owner + tuple + CID + успешная проба»

Рассмотрим два условных origin: `dpi.example` разрешён для LOCAL, а
`required.example` должен использовать RELAY. Предположим, сервер и сертификат
допускают оба имени, а браузер выполнил необходимые проверки authority.

1. Браузер открывает HTTP/3 с видимым SNI `dpi.example`.
2. Собственная проба VELIQ к `dpi.example` успешно получает свой sample.
3. Гипотетический admission разрешает browser datagrams по owner/tuple/CID.
4. Браузер использует тот же сеанс для запроса к `required.example`.

На четвёртом шаге owner, адреса и выбранный CID могут остаться прежними.
Значение `:authority` находится в защищённом трафике. Предлагаемое условие не
содержит признака, по которому VELIQ смог бы отказать до отправки такого запроса.
Отбрасывание только нового CID или изменившегося tuple этого случая не решает.

Это логический контрпример достаточности admission. Фактическое объединение
YouTube и конкретного protected-сайта, общий сертификат этих сервисов или утечка
в текущем Chrome не установлены. Текущий QUIC BLOCK такой путь не открывает.

Не путать два значения coalescing: несколько QUIC packets в одном UDP datagram
и несколько HTTP origins в одном соединении. Проверка всего coalesced Initial
datagram в `QUICOriginObserver` относится только к первому случаю.

## Проверяемая граница в существующем коде

| Свидетельство / событие | Что разрешено сейчас | Чего оно не разрешает |
|---|---|---|
| Fresh kernel FLOW, QPC, PID/birth/image/SID | Однократный trigger отдельной service-пробы | Browser LOCAL и перенос разрешения на новый endpoint |
| Полный видимый ClientHello без ECH/PSK | Scoped metadata; reviewed DPI может запустить пробу | Сертификат браузерного сеанса и все будущие HTTP origins |
| HTTP200,32769bytes, verified TLS и send witness | Исторический результат собственного GET | Route promotion, page/playback PASS и измеренная экономия VPS |
| Browser Handshake/short header/Retry/v2/неподдержанный flight | Существующий UDP443 BLOCK | Достраивание доверенной CID-цепочки по совпадению bytes |
| Закрытие browser source после Claim | Уже начатая bounded own probe может завершиться | Повторное использование Claim новым браузерным flow |
| Capture restart / опубликованный policy epoch | Отзыв trigger; новая попытка требует свежих условий | Восстановление старого разрешения после возврата настроек |

Код, обеспечивающий эту границу:

- `services/client-service/browser_policy.go`: `browserFlow` выбирает
  `browser_native_quic_tcp_fallback` до domain routing для selected native UDP443.
- `platform/windows/capture_windows.go`: `processUDP` записывает observation,
  вызывает probe callback и сохраняет BLOCK; browser originals не пересылаются.
- `platform/windows/quic_flow.go`: `Claim` одноразовый, `Current` проверяет
  capture/policy generation; это capability только для owned probe.
- `services/client-service/browser_quic.go`: manager/budget/cooldown/history,
  current owner/policy checks; route/cache promotion отсутствует.
- `core/browserproxy/http3_probe.go`: TLS и GET выполняются на собственном
  socket; `Observed` сопровождается ограничением sample, а не browser admission.
- `core/localstrategy/quic_catalog.go`: `BrowserRuntimeEnabled` остаётся false.

Все пороги, разрешённые frames и правила очистки приведены в
[BROWSER_QUIC_LOCAL_PLAN.md](BROWSER_QUIC_LOCAL_PLAN.md).

## Что потребуется для пересмотра решения

Нужен доверенный и поддерживаемый механизм, который **до отправки** связывает
каждый запрос с разрешённым origin и не позволяет обойти проверку повторным
использованием соединения. Вместе с ним должны быть определены owner/SID,
network/profile generation, отказ канала контроля и connection lifecycle.
Обычный туннель до IP, DNS association, публичный Initial или observational CDP
log такого контракта сами по себе не предоставляют. В текущем коде этого
механизма нет. TLS interception, экспорт browser session keys, инъекция в
процессы и молчаливое ослабление protected policy не являются принятым решением.

До изменения этого условия новые unit/fuzz/loopback successes не закрывают
архитектурный gate. Реальные Windows/ISP-тесты могут проверить доставку, задержки
и совместимость; они не доказывают отсутствующее правило допуска.

## Продолжение R1

QUIC LOCAL остаётся незакрытой частью цели экономии. Статус R1 — «Частично»;
критерии roadmap не сокращаются этим ADR. Приоритет полезного LOCAL трафика
сохраняется на уже реализованном HTTPS/CDN пути; HTTP80 подготовлен отдельно в
[draft #52](https://github.com/buzzmean/veliq/pull/52), cold/resume/post-reply CDN —
в [draft #51](https://github.com/buzzmean/veliq/pull/51). Эти ветки не включены в #53.
Повторная приёмка нового кода на Windows/ISP и Discord voice LOCAL остаются
отложенными, без объявления R1 завершённым.

Есть отдельная граница для следующей фоновой проверки: HTTP/2 тоже допускает
connection reuse между authority, включая CONNECT tunnel
([RFC 9113, §9.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1)).
Поэтому TCP fallback не доказывает изоляцию каждого HTTP origin. Нужно проверить
фактическое поведение Chromium на контролируемом сервере с общим сертификатом
и разными policy classes: реальные запросы, использованное соединение и egress.
До такого воспроизведения не объявлять найденную эксплуатационную утечку и не
менять существующие TCP guards вслепую. Эта проверка может выполняться в
изолированном CI без production, пользовательских браузеров и их данных.
