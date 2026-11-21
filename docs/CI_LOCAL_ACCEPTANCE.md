# Ранний отказ CI и локальная проверка deployment

21.10.2026 владелец предоставил аннотацию GitHub:
> The job was not started because recent account payments have failed or your spending limit needs to be increased. Please check the 'Billing & plans' section in your settings

Это account billing gate до выдачи runner. Аннотация не различает платёж и
spending limit. Исправление — Settings → Billing & plans владельцем аккаунта;
код/permissions/YAML не могут исправить оплату. Артефакты ещё не загружались.
`fresh-credential` был cancelled из-за matrix fail-fast; теперь он отключён,
чтобы после разблокировки оба layout давали независимый результат. Paths и
concurrency сокращают лишние прогоны, не обходят платёжный лимит.

## Linux: тот же реальный systemd/PostgreSQL сценарий локально

Тестовая Linux-машина с Go версии из go.mod, Git, Docker/BuildKit и доступом
к локальному Docker socket. Не запускать на VPS или машине с /etc/neexitlag.
Docker privileged нужен для systemd namespaces; использовать доверенный чистый
checkout на отдельной тестовой машине. Production credentials не требуются.

```bash
bash tests/deployment/run-local-systemd.sh fresh-credential
```

Второй layout:
```bash
bash tests/deployment/run-local-systemd.sh legacy
```

Runner собирает Debian 13 image с systemd/PostgreSQL/Python/OpenSSL, затем
release binaries из чистого checkout. Это тестовые инструменты, не новые
зависимости продукта. Только build image обращается к пакетным репозиториям;
runtime полностью offline (`--network none`), только loopback. Нет host network,
host cgroup bind, bind mounts репозитория/секретов/Docker socket/host /etc.
Root mutations выполняются исключительно внутри disposable filesystem.
Внутренний tmpfs `/run` получает shared propagation для systemd LoadCredential;
это не host /run и не host mount propagation. D-Bus установлен для systemd-run.
Права CA root:600 сохраняются; отсутствие этих механизмов даёт ранний отказ.
Production IP назначается только lo внутри нового namespace; реальных обращений
к VPS нет. Guard требует systemd PID1, root-owned marker, отсутствие других
интерфейсов и default route. GitHub flags не подделываются.

Git archive исключает незакоммиченные файлы, .e2e и credentials. PKI создаётся
заново только для loopback теста, не используется CA пользователя. Cleanup удаляет
конкретный собственный контейнер и временную PKI даже при ошибке; не делает prune
и не останавливает чужие контейнеры. Для разработчика допускается
`VELIQ_LOCAL_KEEP_FAILED=1`: при отказе остаётся только собственный контейнер с
тестовой PKI, его имя выводится явно; после диагностики его нужно удалить.
Приватные журналы и ключи не экспортируются. Публичный отчёт:
`.e2e/local-systemd-fresh-credential.json` / `.e2e/local-systemd-legacy.json`.
Не коммитить отчёты/PKI/private logs. Общий exit=0 обязателен; наличие JSON само
по себе PASS не доказывает. Отчёт содержит commit, systemd/PG версии, units,
schema/revocations, факт отзыва probe, rollback injection, без keys/codes/dumps.

Проверяется исходный isolated-upgrade.sh и, для fresh-credential,
isolated-activation.py: root-only CA/LoadCredential, реальные TLS/QUIC /3
TCP/UDP/renewal, 5000 отзывов, восстановление dump в отдельную БД, ошибочный
binary и rollback, замена leaf/failure/rollback, внешний failure после renewal,
успешный повтор schema 2, реальный renewal.service в sandbox и отсутствие активных
rollback timers. Это лаборатория, не Internet/VPS acceptance.

## Windows: локальный native эквивалент activation job

В обычном Windows PowerShell 5.1 из корня клона, с Git/Go/.NET8/Python:
```powershell
& .\tools\windows\test-activation-local.ps1
```

Перед тестами проверяет официальный nuget.org через SDK и добавляет его в
пользовательскую NuGet-конфигурацию, если URL отсутствует. Другие источники не
меняются; уже включённый URL распознаётся независимо от имени. Явно отключённый
источник или конфликт имени диагностируется, без перезаписи настройки. Затем
запускает isolated NuGet-config regression, native activation/helper tests,
C# tests/WPF build и fake-SSH fixture.
Не устанавливает службу, не вызывает bootstrap/enroll, не подключается к VPS.
Linux cross-build не заменяет эту проверку. Если Windows runtime недоступен,
результат остаётся неподтверждённым до этого прогона или разблокировки GitHub.

## Результаты 21.10.2026

Чистые offline прогоны исходного кода `5adc8e52b0e50ec84281ece204a2f1d5810f96cb`:

| Проверка | Результат |
|---|---|
| fresh-credential, полный deployment/leaf/rollback/retry | PASS, exit 0 |
| legacy, binary transaction/real relay/rollback | PASS, exit 0 |
| systemd / PostgreSQL | 257.13 / 17.11, Debian 13 |
| 5000 revoked IDs, signed publication >64 KiB | PASS, оба layout |
| fresh leaf failure injection + outer failure после renewal | PASS, сертификаты восстановлены, security records сохранены |
| fresh успешный повтор schema 2 | PASS, CA unchanged, renewal service Result=success/ExecMainStatus=0, renewal timer active |
| временные probe identities | active=0; fresh revoked=5004 (включая четыре тестовых probe), legacy revoked=5000 |
| deployment Python | 90 PASS |
| Linux activation Go race с отдельной PostgreSQL 17 | PASS: core/enrollment, control-plane, client-service, tools/fresh-pc |
| Go build/vet ./... | PASS |
| Windows amd64 cross-build service/fresh-pc/codes | PASS, не runtime test |
| C# desktop-core | 145 PASS на Linux |
| WPF Windows targeting build | PASS на Linux, 4 существующих nullable warning, 0 errors |
| PowerShell parsing/quoting fixture | PASS на PS7/Linux; Windows redirected ssh.exe не выполнялся |
| native Windows / GitHub CI | НЕ ПОДТВЕРЖДЕНО: billing gate до первого шага |

Не выдавать legacy PASS за проверку renewal.service: полный activation/leaf
сценарий выполняется только в fresh-credential, соответствующем нынешнему VPS.
Оба контейнера и временная тестовая PKI удалены; production не контактировался.
Публичные JSON остаются локально в `.e2e`, не в git. После этого SHA изменены
только docs, полнота workflow paths и дополнительные parse-проверки
локального Windows runner; production код не менялся.

Найден и исправлен реальный дефект первого запуска: installer держал оба flock,
`systemctl enable --now` ждал recovery, а recovery ждал те же flock. Теперь
recovery при живом installer возвращает `live-transaction-owner`, как основной
production updater; watchdog rollback всё ещё ждёт lock. Регрессии проверяют
настоящий flock и CLI. Engine apply сохраняет оригинальную ошибку после rollback,
не подменяет её общим UpgradeError. Ошибки тестовой fixture (relay_health до
wait_health, /tmp staging, D-Bus, mount propagation) также устранены.

Последние проверенные через API GitHub результаты исходного кода:
[Activation Linux/Windows](https://github.com/buzzmean/neexitlag/actions/runs/39585387093)
и [systemd matrix](https://github.com/buzzmean/neexitlag/actions/runs/39585387157):
failure, нет steps/logs. Устранить billing gate может только владелец аккаунта.
После исправления Billing & plans повторить эти проверки; менять permissions,
runner labels или удалять artifacts для этого отказа не требуется.

Полный допуск к production НЕ объявлен: Windows native transport fixture и
внешний VPS ещё не проверены на этих изменениях. Сначала на ПК владельца из
корня клона — только read-only VPS snapshot:
```powershell
git pull --ff-only origin main
& .\tools\windows\verify-activation-vps.ps1 -VpsIP 2.56.177.4 -SSHUser root -SSHPort 22
```
Затем локальный Windows test runner выше (не меняет VPS/установку). Mutating
update не запускать на основании одного зелёного лабораторного отчёта.

## Подтверждение владельца: чистый Windows, c9c8af1

Владелец выполнил test-activation-local.ps1 на c9c8af1: Go platform/windows,
client-service и fresh-pc PASS; C# 145/145; WPF 0 errors/4 CS8604;
PS5.1 redirected fake SSH fixture PASS. Это подтверждение именно c9c8af1,
не native Windows проверка последующих production-изменений 5adc8e5.
На ПК потребовались Git/Python3.12/Go/.NET SDK8.0.426. Источников NuGet не было,
NU1100 устранён ручным добавлением nuget.org; теперь runner делает это сам.
Одна загрузка testhost17.11.1 прошла после повтора из-за сетевого timeout60s;
автоматический retry restore в этой задаче не добавлялся.
