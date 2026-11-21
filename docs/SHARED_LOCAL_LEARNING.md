# Общий подбор LOCAL в клубе

24.10.2026. Это advisory learning, не новая маршрутизация и не доказательство
работы обхода на провайдере. На production control plane endpoint пока не установлен.

## Координация

`POST /api/v1/local/learning`: существующий подписанный device proof, свежий nonce
и отдельная audience `local-learning:SHA256(command)`. Метод/подгруппа/режим hints/
candidate/report bytes/flows привязаны к подписи. Проверяются device/revocation,
Ed25519 и прежний PostgreSQL ConsumeProof; nonce нельзя повторить, даже после
ошибки записи learning state. Ticket/renewal audience не принимается.

CP вычисляет cohort как HMAC от IPv4 /24 или IPv6 /48 фактического peer. Не верит
X-Forwarded-For и не принимает hardware ID/SSID/MAC/имя пользователя от клиента.
Ключ HMAC — отдельный domain с seed существующей signing identity; CA не меняется.
В learning state/документе только непрозрачный cohort, известная подгруппа,
кандидат и сроки; owner — fingerprint ключа внутри root-only state, не выдаётся
peer-клиентам. Общий SID образа клуба не участвует. Если CP за недоверенным
reverse proxy с private peer, запрос отклоняется, а не объединяет всех клиентов.

Один picker на cohort+subgroup+hint-mode, lease90s. Lease продлевается при observe,
после исчезновения picker следующий получает право подбора. Кандидат живёт10мин;
для googlevideo публикуется после3 sustained real-flow successes и фактической
LOCAL трансформации, для public origin — после verified body >64KiB. Неподтверждённые
счётчики/short403/404 не публикуются как результат. Сообщение клиента остаётся
недоверенной подсказкой: peer проверяет оба public origins и проходит ту же bounded
CDN trial процедуру на своём ПК. Поэтому удалённый клиент не может разрешить
DIRECT для protected или заставить исполнять неподдержанный packet plan.

Peers не перебирают весь каталог, пока picker жив; проверяют только присланный
кандидат. Локальная неудача блокирует его на этом ПК; один плохой peer не может
стереть общий результат. Picker может отозвать результат при своей деградации.
Никакое established TCP не переносится. Foreground не ждёт CP/подбор.

## Хранение и совместимость

Для будущего согласованного обновления CP требуется явный
`-local-learning-file <root-service-state>/local-learning.json`. Пустой параметр
отвечает503 без обращения к identity/БД. Файл0600, atomic fsync+rename, max256KiB,
512cohort/subgroup records, TTL очистки24ч. Ошибка диска не коммитит lease в памяти.
Новых SQL таблиц/миграций/activation/CA изменений нет. Nonce/revocation остаются в
прежней БД и никогда не откатываются вместе с learning file.

Клиент проверяет отдельную подпись/TTL/scope/версию. При legacy404, отключённом
endpoint или outage показывает `CP_UNAVAILABLE_LOCAL_FALLBACK` и продолжает
ограниченный подбор на каждом ПК. В этом режиме **один picker на40ПК не гарантирован**.
Не требуется повторный deploy Hostkey relay; новый CP endpoint требует отдельного
разрешения на обновление CP; здесь он не запускается. За работой сохраняется pinned
TLS, mTLS/tickets, revocations и основной подписанный config без новых полей.

Polling: picker30s, peer без результата2мин, подтверждённый кандидат5мин; max16
scopes за проход, не чаще1HTTP запроса/2s/ПК. Это фоновый трафик, лимиты CP auth не
ослабляются. При40ПК верхняя равномерная частота около20req/s плюс штатные запросы;
реальная нагрузка/метаданные на production ещё не измерены. Если CP rate-limit
отказал, это деградация координации, не доказательство плохой LOCAL стратегии.

## Проверки и границы

40concurrent members→ровно1picker, restart persistence, re-election, candidateTTL,
strict command proof binding, nonce replay, revoked device, no added SQL schema,
failed persistence→no partial memory state, signature/domain/scope/TTL, legacyCP
fallback и no automatic LOCAL authorization тестируются в изоляции. Диагностика
`browser.native.status.youtube_local_ladder.shared_learning` выводит состояние,
группу/кандидата/picker без proof, device key и аппаратных данных.

Реальные40ПК/freeze/Windows/провайдер/productionCP не проверены. Выдача одному picker
права подбора в unit-тесте не является клубной приёмкой обхода.
