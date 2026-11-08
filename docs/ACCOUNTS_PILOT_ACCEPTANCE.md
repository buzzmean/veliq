# Изолированная приёмка аккаунтов и подписок — 01.11.2026

Историческая приёмка прежней account-ветки. Текущий основной сценарий без ручных
кодов: [ACCOUNT_ONBOARDING.md](ACCOUNT_ONBOARDING.md); общая сборка и новые проверки:
[BETA_ACCOUNTS_2026-11-02.md](BETA_ACCOUNTS_2026-11-02.md). Старые counts/schema ниже
описывают прежний source и не являются результатом новой сборки.

База: `f1a29df362d434533a230c1407abf5435d9a8257`, ветка `accounts-subscriptions`, PR #32.
Это проверка тестовых моделей и локальных сервисов, не подтверждение production или живого клуба.
Production VPS, рабочие данные, сертификаты и реальные платежи не использовались.
Флаг `enforce-subscription` ни у одной запущенной службы не включался.

## Результаты

| Область | Результат и границы доказательства |
|---|---|
| STARTTLS → код → HTTPS → сессия → logout | PASS: новый `TestPilotSTARTTLSHTTPSLoginLogout`, настоящее TLS-соединение к локальному SMTP с AUTH и DATA; настоящий HTTPS с доверенным тестовым сертификатом и cookie jar. Secure/HttpOnly/SameSite/Path проверены; старый cookie и использованный код отклонены. Не реальный почтовый провайдер. |
| Миграция 004 | PASS: `TestPilotMigration004PreservesSchema3IdentityAndCertificate` начинает с SQL 001–003, создаёт активное и отозванное устройства, отключённый слот, nonce, signed config и salt. После двух Migrate снимки прежних записей совпадают, schema=4, тестовый сертификат не изменён и проверяется тем же CA, прежнее устройство получает авторизацию. |
| Подписка, grace, восстановление | PASS: `TestPilotSubscriptionExpiryGraceAndRecoveryWithoutEnforcement` проверяет 24/72/96 часов, синтетическое зачисление и сохранность ключа/identity. Default mode не блокирует просроченный entitlement. Блокировка/возобновление клиента — отдельно существующие portable `TestEndedSubscriptionSuspendsReversiblyAndResumes` и `TestSubscriptionNetworkFailureIsNotExpiry`. Это не живой Windows. |
| Недоступность БД | PASS: `TestPilotDatabaseUnavailableDoesNotAcknowledgeAndRecovers` закрывает весь клиентский pool: login/logout/create возвращают 503, cookie не теряется; новый pool видит прежнюю сессию, повторный logout проходит. Физический restart/partition PostgreSQL не имитируется этим тестом. |
| SMTP failure, commit failure, отмена | PASS: существующие `TestAccountSMTPFailureRollsBackAndRetryReallySends`, `TestAccountLoginDatabaseFailuresCannotAcknowledgeDelivery`, `TestAccountCanceledSMTPReleasesReservation`; предыдущий код/attempts сохраняются, ложного успешного ответа нет, повтор отправляется. |
| Resend/20 подписок/нагрузка | PASS: `accounts_concurrency_test.go` проверяет конкурентные запросы, два экземпляра API, атомарный лимит 20 при READ COMMITTED и REPEATABLE READ, rollback, ограничение SMTP capacity. Это не нагрузка 40 реальных ПК и не throughput benchmark. |
| Места, freeze, выпуск/отзыв кода | PASS: существующие `TestSubscriptionLifecyclePaymentSeatsAndEnforcement`, `TestCodeFiftyFreezeReplacementsOneSeatAtomicRevokeAndLimit`, `TestPublicCodeCSRHTTPSNoAdminAndSafeFailures`: лимит, повторная активация, смена device identity на том же hardware slot, сохранность места при перевыпуске кода, release/revocation, отказ чужому аккаунту. Все identity и CA синтетические. |
| Platega | PASS только локального контракта: существующие `platega_test.go` проверяют создание, секрет/merchant, payload/сумму/валюту, чужую подписку, повторы/порядок уведомлений и запрет неподдерживаемого auto-renew. Новый `TestPilotConcurrentPlategaWebhookCreditsOnce`: 32 одновременных CONFIRMED → один audit credit и один период. API — только loopback mock. |
| Совместимость старой установки | PASS сохранности schema3-фикстуры. NOT TESTED: матрица произвольных production-бинарников, установленная Windows-служба, её ACL/реестр/драйвер и сохранность рабочих файлов. Предыдущие CI legacy/fresh-credential относятся к тестовым layout, а не ко всем выпускам. |

Новые пять сценариев выполнены по 10 раз с race detector. После добавления отозванной identity миграционный сценарий повторён ещё 10 раз.
Полный `go test -race -count=1 ./...` выполняется с настоящим изолированным PostgreSQL17, не с mock SQL.
Python deployment: 103/103. C# portable: 223/223. Актуальные результаты оставшихся проверок и CI — в `CONTINUATION.md`.

## Что не считать PASS

- Доставляемость в настоящий inbox, SPF/DKIM/DMARC, spam/rate limits SMTP-провайдера и задержки интернета.
- Реальные Platega credentials, подпись договора, реальные оплаты/возвраты, публичная доставка webhook.
  Текущий код не отзывает ранее зачисленный период при DISPUTED/CHARGEBACKED и игнорирует PARTIALLY_REFUNDED.
  Тесты подтверждают эту семантику, но не её соответствие будущей политике возвратов.
- SMTP может принять письмо, а commit БД — завершиться ошибкой. API вернёт 503; доставленный код может быть недействителен. Нужен новый запрос.
- Проверка expiry в portable-модели не доказывает работу GUI, сохранность ручного OFF при billing-suspension или восстановление реальных TCP-потоков.
- `POLICY_PENDING_BROWSER_REFRESH` с `requests=0` не доказывает применение PAC без перезапуска.
- Ни один результат здесь не разрешает включать enforcement, менять CA или переносить production.

## Воспроизведение без production

Нужны Go1.25, Python3 и отдельная временная PostgreSQL17 с пустой тестовой БД и правами создания/удаления временных схем.
`NEEXITLAG_TEST_DATABASE_URL` должен указывать только на эту фикстуру, не на рабочую БД или tunnel к VPS.
Без переменной тесты БД пропускаются: такой прогон не является приёмкой.

```sh
go test -race ./services/control-plane -run '^TestPilot' -count=10 -v -timeout=90s
go test -race -count=1 -timeout=180s ./...
go vet ./...
go build ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...
python3 -m unittest discover -s tests/deployment -v
dotnet test tests/desktop/NeExitLag.Client.Tests.csproj --nologo
```

## Следующий живой пилот — отдельная среда, без enforcement

1. Выделить **новый тестовый сервер и чистую Windows-VM/ПК**. Записать тестовые адреса CP/relay/echo,
   отдельные CA и БД; подтвердить отсутствие production identity и данных. Нужны отдельное разрешение на staging deployment,
   его backup/rollback и проверенный способ удаления фикстуры. Этот документ deployment не выполняет.
2. На staging настроить HTTPS кабинета и `/api/`, тестовые планы, `account-origin` и специальный SMTP mailbox.
   Пароли только в защищённых файлах/secret storage. Оставить `enforce-subscription` выключенным;
   реальные Platega credentials не добавлять. Проверить, что API сообщает `enforced=false`.
3. В настоящем браузере открыть staging `account.html`: запросить письмо, проверить inbox и задержку;
   войти, повторить использованный код (401), logout, повторить запрос со старой сессией (401), снова войти.
   Код и cookie не вставлять в чат/логи.
4. Создать клубную подписку на **2 тестовых места**, получить код один раз. На двух чистых Windows-VM
   установить клиент с **явным staging ControlPlaneUrl и staging trust**, активировать. Третья identity должна получить ACTIVATION_LIMIT.
   Не запускать production bootstrap/setup с его адресами по умолчанию. Готовой команды установки до получения staging URL/CA/echo нет.
5. Перезагрузить одну тестовую VM с откатом состояния: та же hardware identity должна занять прежнее место.
   Перевыпустить код: старое значение не активирует новый ПК, уже активированные ПК сохраняют доступ.
   Освободить одно место: прежнее устройство отвергается; новый тестовый ПК занимает освобождённый слот.
   Из второго тестового аккаунта доступ к чужой подписке/release/code должен возвращать 404.
6. Старить `paid_until` **только тестовой записи staging**, проверить preview/cutoff; при enforcement=false
   доступ не должен выключаться. Восстановить период синтетическим staging-зачислением и проверить тот же ключ/identity.
   Реальное принудительное отключение/возобновление требует отдельного разрешения и отдельной Windows-приёмки;
   в этой задаче enforcement не включать.
7. Отдельно выполнить управляемую остановку только staging PostgreSQL и сбой staging SMTP:
   ожидать 503 без ложного успеха; после восстановления login/logout повторяются успешно.
   Проверить время удержания запросов и отсутствие idle-in-transaction/deadlock.
8. До коммерческого включения отдельно согласовать возвраты/chargeback/auto-renew, подтвердить provider sandbox и провести
   Windows-приёмку ручного OFF, просрочки, повторной оплаты, обновления/удаления/повторной установки.
   После испытаний удалить только staging-коды, identity и фикстуру. PR #32/#34 не мержить автоматически.
