# Activation deployment: leaf renewal и безопасный повтор после schema 2

## Сначала только read-only (на ПК владельца)

PowerShell из корня клона `main`. SSH проверяет host key; пароль вводится
интерактивно. Команда не устанавливает, не мигрирует, не отзывает устройства,
не запускает таймеры, не меняет файлы/бинарники/сертификаты и не перезапускает VPS:

```powershell
$ErrorActionPreference='Stop'
git pull --ff-only origin main
if($LASTEXITCODE){throw 'GIT_PULL_FAILED'}
& .\tools\windows\verify-activation-vps.ps1
```

Перед повторным deployment владелец проверяет вывод:

- `binary`: installed/running SHA256 и commit (без изменений это старый 2c06089).
- `database.schema_version`, `activation_tables`, `activation_row_counts`:
  схема 2 и 3 таблицы допустимы для повторного запуска; коды/их хеши/соль не выдаются.
- `database.temporary_probes`: только публичный device ID, revoked и даты,
  WHERE name='CA rotation health probe'. Это кандидаты на служебные записи,
  имя само по себе не криптографическое доказательство происхождения.
  Ключи устройств, nonce и документы конфигурации не выводятся.
- `database.recent_config_publications`: последние 25 version/generated_at/expires_at;
  это помогает сопоставить публикации с журналом операций, но не восстанавливает
  причинность всех 19 версий по одному снимку.
- `units`: LoadState, active, последнее Result/ExecMainStatus, start time;
  oneshot renewal после удачного запуска обычно inactive, Result=success/exit=0.
- `timers`, `backups`: нет pending операций/активных rollback timer. Старые
  rolled-back/aborted бэкапы сохраняются; их наличие не означает текущий сбой.
- `certificates`: leaf/CA not_after, секунды до истечения, копии control/relay
  совпадают, установлен ли renewal service и активен ли daily timer.

При `PENDING_RECOVERY_REQUIRES_REVIEW`, неподдерживаемой схеме или несовпадении
running/installed binaries **не выполнять повторный deployment**. Сначала
передать санированный read-only вывод владельцу разработки. Не удалять бэкапы,
не запускать pg_restore/DROP и не править production вручную.

## Подтверждённая причина

В 5bbf629 `renew-server-cert.py` после установки leaf вызывает helper с journal
`/var/backups/neexitlag-certificates/<UTC>-<8hex>/probe.id`. Helper разрешал
ТОЛЬКО `/etc/neexitlag.bak-<UTC>-<12hex>/probe.id`. Поэтому локальная проба
возвращала `UPGRADE_PROBE_JOURNAL_REQUIRED` **до создания journal/identity**,
leaf откатывался, а внешний deployment затем откатывал binary transaction.
Текст превращался в `SAFE_OPERATION_FAILED`: helper-команда давала mixed-case
`COMMAND_FAILED_veliq-fresh-helper`, старый CLI оставлял лишь uppercase-code;
родитель запускал python с унаследованными stdout/stderr и создавал новый
LEAF_RENEWAL_FAILED без сохранения этих потоков.

Новая проверка `probe-journal-check` не обращается к VPS/БД и проверяется до
первого backup/изменения. Разрешены только два точных формата journal,
остальные пути/обходы директорий отклоняются. Во время реальной пробы прежние
root/host/owner/ACL/mTLS/replay проверки остаются. Обе части используют один helper.

## Что произошло с БД

`002_activation_codes.sql` добавляет `activation_codes`, `activation_slots`,
`activation_policy`, строку version=2. Migrate дополнительно создаёт singleton
hardware_salt, если его нет. Старые колонки/таблицы не удаляются и не переименовываются.
Бинарник 2c06089 выполняет только идемпотентную 001 и не отвергает version=2:
обслуживание старых устройств/relay совместимо, **API кодов активации в нём нет**.
Это проверяется PostgreSQL-тестом: migrate v2 → повтор SQL baseline 001 → migrate
v2; соль, отзыв устройства и три таблицы сохраняются.

+1 device/+1 revoked согласуется с успешным binary local proof: helper Register
создаёт отдельную временную identity; defer/cleanup отзывает её и публикует config.
Эта запись не удаляется: её отзыв нужен, пока сертификат/билет может быть действителен.
Leaf probe с прежним journal отказал до Register. Увеличение config_version включает
публикации проб, cleanup, запуск/heartbeat control-plane/relay и другие запросы.
Из одних чисел нельзя доказать, что именно создало все +19; снимок ДО/аудит нужны
для точной атрибуции. Удалять лишние versions/nonce/устройства небезопасно.

## Атомарность: честная граница

Выбран безопасный путь: **подготовить доведение deployment вперёд из schema 2**,
а не возвращать production БД к schema 1. На VPS при этом ничего не выполняется.
Полная byte-for-byte атомарность живой БД и сохранение новых security-записей
несовместимы. Пока открытые API принимают билеты/отзывы, восстановление pg_dump
может воскресить отозванные устройства и разрешить повтор nonce/билетов.

Реализован security-monotonic rollback: бинарники/units/конфигурация/leaf
восстанавливаются, **аддитивная schema и новые nonce/отзывы/публикации остаются**.
Это намеренная граница, не обещание полной ACID-транзакции всей машины. Drop новых
таблиц также не делается: в них уже могут быть activation slots/соль/коды.
`database_policy=SECURITY_MONOTONIC_NO_PG_RESTORE`, `database_before` в backup и
финальный read-only снимок явно показывают результат. Бэкап БД остаётся аварийной
копией, не автоматическим способом стирания новых security-записей.

Если владелец требует буквально полный возврат БД, это **отдельный блокирующий
архитектурный этап**: закрыть приём всех публичных записей на время операции,
согласовать rollback security epoch/идентичностей/билетов. Этот режим здесь не
реализован и не включён. Текущий код не заявляет абсолютный baseline rollback.

## Диагностика, повтор и сертификаты

Каждый child deployment/leaf даёт `ACTIVATION_SUBPROCESS`: имя программы,
exit code, отдельно stdout/stderr (размер, безопасная категория и только
allowlisted operational codes). Свободный текст, аргументы, ключи/PEM/пароли/коды
активации не печатаются. Пустое исключение получает SAFE_OPERATION_FAILED и
file/line trace. Для binary engine такой же observer включён внутри activation.

`ACTIVATION_FINAL_STATE` после apply/rollback перечисляет binaries, DB, сервисы,
таймеры и сертификаты. Parent читает финальный файл результата; при kill/timeout
до снимка сообщает `UNVERIFIED / CHILD_DID_NOT_PRODUCE_FINAL_SNAPSHOT`, а не
голый UNKNOWN и не ложное «ничего не изменено». Если сам снимок не удался,
есть FINAL_SNAPSHOT_FAILED с безопасной причиной. Наличие снимка не доказывает
отсутствие исторических записей. При неудаче restore independent guard остаётся
страховкой; при подтверждённом commit/rollback таймер останавливается.

Повторный запуск принимает schema 1 и 2; unknown schema/неизвестные units/CA layout
по-прежнему требуют разбора. Schema 2 с сохранёнными отзывами отражается как
`COMPATIBLE_ADDITIVE_SCHEMA2_SECURITY_STATE_PRESERVED`, не как чистый baseline.
Повтор не обнуляет hardware salt, устройства, ключ CA, credentials и коды.

После отдельного разрешения владельца на **изменение VPS** используется штатный
update-activation-vps.ps1 с точным новым HEAD и ConfirmDeployment. Здесь сначала
требуется только read-only команда выше; повторять старые неудачные деплои нельзя.

Шаг deployment проверяет helper до изменений, принудительно обновляет leaf с тем
же CA/SAN, выполняет настоящие TLS health + authenticated TCP/UDP /3 и revoke
probe, затем запускает реальный renewal.service (due=false) до outer commit.
StateDirectory создаёт нужный private каталог при работе systemd sandbox.
Daily timer persistent, OnBootSec=30s, jitter до 15 минут, threshold 10 дней.
Старый leaf истекает **19.11.2026 16:05:54 МСК / 13:05:54 UTC**; исправленный
renewal должен быть реально установлен владельцем до этого срока. Код/CI не
означают, что он уже установлен на VPS. CA ротация не выполняется.

## Проверки и ограничения

Python unit-тесты, Go race/native Windows helper contracts, Windows PS5.1
transport fixture, PostgreSQL compatibility test. Подготовлен сценарий для disposable systemd VM с
root-only CA: реальный leaf replace → failed proof → rollback, затем полный
activation apply с новой leaf-пробой, проверка /3 TCP/UDP и отзыва временных
identity, реальный renewal.service в sandbox, отсутствие активных rollback timers.
Используется только local interface/loopback fixture, не Интернет/VPS; production
IP в этом тесте назначается исключительно loopback disposable GitHub VM.

Общий Verify может падать на GitHub artifact quota — отдельно от тестов.
Полное восстановление БД/новый security epoch, гарантии при зависании kernel/
systemd/БД, точная историческая атрибуция +19 и реальный production deployment
не подтверждены этим изменением.


Результаты этого изменения: локально 81 Python-тест PASS, Go race/vet и Windows
cross-build helper PASS; PostgreSQL 17 с реальной БД — `tools/fresh-pc` и
`services/control-plane` race PASS, включая baseline/schema2/retry. Новый GitHub
CI f01012f завершился до любых тестовых шагов (steps=[], логи 404); причину
инфраструктуры не удалось получить. Поэтому новый systemd/Windows acceptance
**не подтверждён**, а повтор mutating deployment до успешного CI не рекомендуется.
Это отдельный ранний отказ, не доказанный artifact quota. Никаких команд на
production VPS не выполнялось.
