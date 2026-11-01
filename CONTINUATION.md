# Контрольная точка изолированной приёмки аккаунтов

Ветка: `accounts-subscriptions`. Проверенная база: `f1a29df362d434533a230c1407abf5435d9a8257`.
PR: https://github.com/buzzmean/veliq/pull/32. Merge и deploy не разрешены.

## Границы

- Production VPS, реальные БД, сертификаты, платежи и SMTP не использовались и не менялись.
- `main`, PR #34 и Issue #33 не затрагивать. `enforce-subscription` не включать.
- Platega проверяется только с loopback mock API, синтетическими заголовками и webhook.
- В публичные файлы не добавлять секреты, коды, PEM или персональные данные.

## Состояние и выполненные проверки

- На базе f1a29df завершены успешно все девять CI-запусков; ссылки и результаты относятся именно к базе.
- Добавлены пять тестов `TestPilot*` в `services/control-plane/accounts_pilot_test.go`:
  STARTTLS → HTTPS → secure cookie → logout/replay;
  настоящая schema3 → migration004 дважды с сохранением устройств/слотов/nonce/config/salt и тестового сертификата;
  отказ всего пула БД и восстановление сессии;
  32 конкурентных mock webhook с одним зачислением;
  границы grace/expiry и восстановление entitlement без включения enforcement.
- SMTP-фикстура использует фактический адрес listener, поэтому работает на случайном порту.
- Первый прогон подтвердил SMTP/HTTPS, миграцию и webhook; обнаружена ошибка только нового DB-outage теста:
  он передавал лишние поля строгому JSON-декодеру. Тест исправлен, production-код не менялся.
- После перезапуска среды повторный прогон всех пяти TestPilot завершён: по 10 раз с race, PASS.
  Миграционный тест дополнен реально отозванным устройством/disabled slot и отдельно повторён 10 раз, PASS.
- Полный `go test -race -count=1 -timeout=180s ./...` с локальным PostgreSQL17: PASS.
- vet Linux/Windows и build Linux/Windows: PASS. Python deployment 103/103, C# portable 223/223.
- PostgreSQL17: deadlocks=0, idle_in_transaction=0 после проверок. SMTP ephemeral-port итоговый прогон PASS.
- Production-код не изменялся. Новые тесты и отчёт: `docs/ACCOUNTS_PILOT_ACCEPTANCE.md`.
- CI коммита с этим файлом нужно сверить по HEAD ветки PR #32; прежние девять PASS относятся к базе f1a29df.

## Следующие шаги

1. Проверить новый HEAD и CI PR #32: Verify Linux/Windows, Isolated upgrade legacy/fresh-credential,
   Edge/Chrome acceptance, Relay release, Game UDP. Не переносить прежний PASS на новый SHA.
2. Если новые TestPilot упали, получить точный лог и исправить только доказанную причину.
3. Не менять production: для живого пилота сначала нужны выделенный staging URL/CA/echo, отдельная БД и SMTP mailbox.
   Точная последовательность действий — в продуктовом отчёте; готовых production-команд он не содержит.
4. При повторении тестов создать новую локальную фикстуру PostgreSQL17; прошлый контейнер после испытаний удаляется.
5. Отдельный незакрытый gate перед enforcement: ручной OFF во время billing-suspension/после восстановления,
   настоящий Windows UI, physical DB outage/restart, доставка почты и политика возвратов/chargeback.

## Остаточные ограничения

- SMTP accepted + DB commit failure может оставить доставленный, но недействительный код: API возвращает 503, требуется новый запрос.
- Сбой БД моделируется закрытием клиентского пула; физический restart/partition сервера — отдельная проверка.
- Произвольные старые бинарники, реальный SMTP/inbox, Windows UI и 40 ПК не подтверждаются portable-тестами.
- Expiry/grace проверяются в тестовой модели; флаги запущенных служб не меняются.
- Silent PAC pending (`requests=0`) не доказывает uptake; не подменять им native/browser acceptance.
