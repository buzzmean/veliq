# Каталог локального обхода: данные и пределы движка

23.10.2026. Принцип — снимать трафик с VPS подтверждённым локальным обходом,
а не считать любой TCP ACK доказательством работы сайта.

## Происхождение

`core/localstrategy/catalog.json`: все22 general*.bat Flowseal1.10.4,
commit176f56dc3f11ce5915c26abcdde903f93d835b64. Всего119 параметрических rules,
включая основные концепции blockcheck zapret/zapret2 и zapretgui. Для каждого —
источник, revision, путь, TCP80/TCP443/QUIC443, исходные параметры. MIT подтверждены;
у zapretgui лицензия найдена в docs/LICENSE. Notices в third_party/licenses/.

Обновление инвентаря выполняет offline `tools/catalog/import-strategies.py` из
проверенных исходных checkout, без исполнения BAT/shell/Lua/Python upstream.
Бинарники winws, fake-файлы и чужой packet-processing код не копируются.

## Что исполняется собственным движком

С24.10 все64 TCP443 rules Flowseal имеют собственный исполняемый native recipe;
всего44 дедуплицированных плана из70 совместимых rules (119 всего). Остальные49,
включая HTTP/QUIC и неподдержанные правила других источников, явно unsupported.
Проверка инвентаря не считается рабочим обходом: каждый новый plan проходит
пакетный тест, а LOCAL требует отдельной transport/service проверки на этой сети.

Типизированные modes: fake, multisplit/multidisorder, fakedsplit/fakeddisorder,
hostfakesplit/altorder, SYN-data; markers/repeats/fooling/list order/seqovl.
Fake TLS/STUN payload собственный, не upstream binary; параметры адаптированы,
побитовая эквивалентность winws не заявляется. Native TS/MD5 не подменяются badseq;
при чистом TS необходимы реально согласованные timestamps. Свой LOCAL socket
запрашивает их перед connect; global TCP/browser настройки не меняются.

Native TCP443: max64 output packets/first logical flight, repeats≤16, cutoff1,
полностью планируется перед send. Legacy catalog≤20/input, fake≤16 и всегда
old-sequence; обычный DIRECT+≤5. Игры/античит/iSCSI scope неизменны.
LSO Hello делится по MTU с точными original TLS bytes; raw WinDivertSend,
а не одна лишь сегментация socket Write. Подробности/ограничения — LOCAL_ENGINE_AUDIT.md.
QUIC fake не реализован: сохраняется разрешённый QUIC→TCP fallback, затем тот же
DIRECT/LOCAL/RELAY selector. Catalog availability не является LOCAL PASS.

## Проверено

Race tests: каталог/ограничения/случайный own TLS/повторы/cutoff/TTL/MD5/timestamp,
segmented1955B ClientHello и точное восстановление исходного TCP stream. Новые
fake проверены независимым WinDivertHelperCalcChecksums pinned DLL;70вариантов
всех service filters и30 private iSCSI evaluator cases PASS под Wine. Это не
WinDivertOpen/kernel/Windows/ISP proof. Фильтры, driver/pins не менялись.
Два Python inventory tests: все general/provenance и CRLF/caret/no execution PASS.

## Нерешённая граница фоновой проверки CDN

Корень googlevideo обычно403/404 и даёт меньше64KiB. Это не доказательство обхода
заморозки16–20KiB. Native capture без MITM не видит HTTP path и подписанный video
URL; заново открытый TLS имеет другие ключи и не может воспроизвести ciphertext
прикладного запроса. Поэтому строго фоновая передача >64KiB на том же CDN требует
подходящего тестового URL; короткий root не должен подтверждать LOCAL. Решение владельца: ограниченная проба реального нового LOCAL потока с живым
RELAY-соседом, max1 глобально, >=3мин/подгруппу;3успеха >64KiB до LOCAL. С24.10
допуск пробы — committed transform того же scoped плана на любом YouTube-хосте,
даже если public body не прошёл порог. Не означает успешный CDN.
Без любого origin byte можно безопасно повторить только полный ClientHello;
после первого ответа существующий TLS остаётся pinned, replay запрещён.

## Подписанное обновление данных с control plane

Отдельный `GET /api/v1/local/catalog` возвращает Ed25519 envelope с domain
`local-catalog`, монотонной версией данных, generated_at/expires_at и каталогом.
Старый strict `/api/v1/config` не расширяется; лимит revocations1MiB не меняется.
Каталог сохраняет собственный предел64KiB signed document. Источник обновления
проходит прежний HTTPS CA pin/trust, signature/domain/TTL/rollback/equivocation
проверки; файл клиента атомарный, отвергнутые документы его не меняют.

Клиент проверяет данные при подключении, затем раз в час, не блокируя relay,
захват или GUI. 404 старого CP оставляет reviewed bundled catalog; ошибка видна
только в диагностике. Метаданные составляют примерно49KiB/проверку: до~47MiB/сутки
на40ПК при почасовом polling. Это control-plane, не video payload; экономия
YouTube от одной доставки каталога пока **не доказана**, планы теперь участвуют в фоне, но их работоспособность подтверждается отдельно. `local.catalog` сообщает available data, не bypass PASS.

На новом CP встроенные данные доступны сразу. Для публикации обновлений без
пересборки установщика предусмотрен `-local-catalog-file <writable-state-file>` и
admin-only `PUT /api/v1/local/catalog` с `{version,catalog}`. Версия строго растёт,
сначала валидация/проверка signed size, затем fsync+atomic rename. Без настроенного
постоянного файла PUT отвергается. Публичный GET не выдаёт admin token/ключи.
Каталог не выполняет SQL, миграции, enroll/revoke и не меняет activation/CA.

Код CP подготовлен, но на боевом CP endpoint ещё не установлен. Повторный deploy
для клиентских исправлений1a–1c или bundled каталога не нужен. Подписанное remote
обновление требует отдельного будущего согласованного обновления CP; здесь оно
не выполняется. Общая club learning/статистика по сетям — пункт4, ещё не сделан.

## Исторический аудит границы пункта3 (исправлен 24.10.2026)

Точная причина общего cache verdict: youtubeScope использует cacheHost, который
вызывает DirectTimeoutHost; тот сводит ВСЕ youtube-media, включая accounts и
googlevideo, к youtube.com. Локальный подбор должен получить отдельный subgroup
key; менять этот общий DIRECT timeout key глобально нельзя без отдельной проверки.
В старом фоне после полного sweep Retry ставится в Until; при TTL cache удаляется
и выбор опять начинается с первого кандидата. Нужны продолжающийся exponential
backoff, статистика кандидатов и независимость accounts/web/images/CDN.

Текущий ProbeOriginDetailed читает максимум32769B body. Для критерия >64KiB нужна
отдельная transfer-probe с большим лимитом и проверкой полного/достаточного HTTP
body, applied transform, TLS и отсутствия freeze. Короткий CDN root этого не даёт.
Новая политика пункта3 ещё НЕ включена: старая foreground/provisional ladder
пока остаётся прежней. Этот этап данных не является исправлением CDN выбора.

Пункт3 теперь разделяет subgroups, использует отдельный transfer GET >64KiB,
продолжает подбор с bounded backoff и допускает CDN только по решению владельца:
scoped transform на любом YouTube host, один trial при live RELAY sibling,3success/cooldown.
Аудит выше описывает прежний дефект, не текущий route contract.
