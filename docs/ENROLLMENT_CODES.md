# Коды активации VELIQ

## Схема и совместимость

Дополнительная миграция `002_activation_codes.sql`: activation_codes (случайный ID,
SHA256 высокоэнтропийного кода UNIQUE, kind club/personal, seat_limit, name,
expires_at, revoked); activation_slots (code_id + machine_hash PRIMARY KEY,
device_id, disabled). Слот остаётся отключённым до явного решения администратора,
повтор после freeze его не оживляет. Код хранится в БД только как hash; audit и
метрики используют случайный code_id, не hash/code. Админские devices API и
root-SSH fresh_machine_slots остаются совместимыми. Новые слоты привязаны к коду:
нельзя подставить hw hash, чтобы отозвать чужое SSH/legacy устройство.

`VQ-` + 24 случайных base32 символа (120 бит), группы по 4. Пример формата с
заполнителями, не рабочий ключ: VQ-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX. Public release
не содержит ни кодов, ни administrator token, ни private CA. Обычное перечисление
админом возвращает ID/метаданные, никогда исходный код/hash. Инвентарь — страницы до 128 строк с next_cursor; tools/codes принимает --after. Создание возвращает
код один раз; tools/codes не пишет его в файл/лог, только явно в терминал владельца.

Пошаговые команды владельцу после успешного deployment: [ACTIVATION_OWNER_RUNBOOK.md](ACTIVATION_OWNER_RUNBOOK.md). Там отдельно clean-PC ActivationOnly, public CA/CP CA, GUI, freeze и безопасное освобождение места (disable не нужен для обычной переустановки).

## API

* POST /api/v1/enroll: code + существующий CSR request (device_id, machine_hash,
  csr), без admin token. Проверка подписи CSR и Ed25519/subject/limits — существующая
  core/freshpc. Никакой выдачи private device key, CA key или echo/admin token.
* Admin bearer: /api/v1/codes POST create / GET list; /api/v1/codes/{id}/machines
  GET; /api/v1/codes/{id}/revoke POST; /api/v1/codes/{id}/machines/{hash}/disable POST.
  CLI читает admin token из файла, не argv; код вводится/возвращается без логов.
* Известные ошибки: ACTIVATION_INVALID, ACTIVATION_REVOKED, ACTIVATION_EXPIRED,
  ACTIVATION_LIMIT, MACHINE_DISABLED, ACTIVATION_RATE_LIMIT, ACTIVATION_UNAVAILABLE.
  Ошибки/логи не включают тело запроса, код, hash кода или CSR.

Транзакция берёт существующий advisory lock публикации и блокировку кода. Лимит
считается по слотам, не по накопленным revoked devices. Повтор того же CSR
идемпотентен. Новая identity того же (code,hardware) атомарно заменяет старую,
отзывает её и публикует полный signed config; DB/publication failure откатывает всё.
Новый сертификат формируется до commit, но выдаётся только после успешного commit.
Старые отозванные заявки не воскресают. Отзыв кода и отключение слота публикуются
той же транзакцией; existing auth/ticket/session renewal сохраняет revoked checks.

## Идентификатор машины

Старый SSH путь использовал SHA256 UUID v1. Сохраняется поддержка его существующих
слотов; не переводим их молча. Общий модуль hardware v2 принимает SMBIOS UUID,
серийник платы и MAC основной UP физической карты (выбор по route metric, стабильная
сортировка). MachineGuid не используется. Normalize + HMAC-SHA256 с публичной
installation/deployment солью (не случайной после каждой загрузки); на сервер
уходит только 64 hex. Соль поставляется вместе с доверенной публичной конфигурацией,
не загружается из неподтверждённого HTTPS. Fresh tooling получает тот же v2 helper
как опцию, legacy v1 остаётся для совместимости. Сырые значения не логируются.

HW ID — inventory, не удалённая аппаратная аттестация. Обладатель клубного кода
может скопировать его из образа или подделать hw hash: полностью закрыть это без
TPM/постоянного секрета вне freeze нельзя. Меры: SYSTEM/admin ACL, индивидуальные
ключи, лимит мест, IP/code/global rate limits, срок кода, отключение слотов и отзыв
кода. Администратор ПК может извлечь код; это честное ограничение, не обещание DRM.
Ротация hardware/MAC может создать новый слот, который админ должен освободить.

## Клиент и GUI

Служба принимает код по owner-authenticated IPC и хранит его в ProgramData только
SYSTEM/Administrators; GUI не читает файл обратно. Публичные CA/signing trust и
endpoint заранее установлены/проверены; TOFU и отключение TLS запрещены.
Ключ создаётся на ПК. При отсутствии действующей identity и наличии кода служба
в фоне делает CSR enroll, сохраняет certificate с прежними ACL и подключается;
временные сбои повторяются с bounded exponential backoff. Startup/IPC не блокируются.
Повтор потерянного ответа использует тот же CSR/ключ. Старые зарегистрированные
устройства без кода используют прежний ConnectRemote/renew путь.

GUI: «Введите код активации» / «Активировать», masked input; в Настройках только
«Код активации: активирован / Сменить». Нет кодов в exception/telemetry/diagnostics.
Никаких публичных обещаний про число серверов, игровых маршрутов или размер клуба.

## Server certificate renewal

Root systemd timer ежедневно проверяет leaf; за 10 суток выдаёт новый server leaf
на 30 суток тем же CA, с прежними SAN (в том числе VPS IP и 127.0.0.1). CA/ключи
identity не ротируются. Проверяет срок/CA signature/SAN, делает root-only постоянный
backup, ставит независимый rollback timer, атомарно заменяет CP/relay TLS files,
перезапускает CP -> relay. Проверка HTTPS8443 и настоящего QUIC4433 mTLS /3 через
краткоживущую локальную probe identity с обязательным отзывом. При любой ошибке
восстанавливает старые TLS files; не продлевает expired CA, не ослабляет TLS.
Диагностика показывает публичные CA/server NotAfter и предупреждение до истечения,
не ключи. Смена CA отдельно, в этот этап не входит.

## Выпуск и остановки

Сначала isolated PostgreSQL/race, client/GUI/renewal fake-clock tests, vet/build и
Windows compile. Деплой только при зелёных проверках, через существующий upgrade
с pg_dump, постоянным backup и rollback. Разрешение владельца распространяется на
2.56.177.4, не veliq-swe-01. Если SSH недоступен, выполняются только подготовка и
точные команды владельцу; тестовые club/personal коды до реального deployment
не создаются и не выдаются как работающие. На ПК не обещать PASS без owner retest.


Решение владельца об откате: возвращаем бинарники/units/leaf, **сохраняем текущие
nonce/revocations и совместимую добавочную схему**, pg_dump — резервная копия,
не автоматический pg_restore после публичных запросов. Это явно согласованное
уточнение первоначального требования полного отката БД.

Измерительные пробы сохраняют существующий authenticated echo: CP получает
существующий probe token через systemd LoadCredential и отдаёт его только после
успешного code+CSR enrollment, как прежний fresh ответ. Это не admin/CA credential
и не право open proxy. На ПК токен, как и device identity/code, закрыт SYSTEM/admin
ACL; публичный релиз его не содержит. Без этого runtime credential новый endpoint
показывает enrollment_ready=false, не выдавая ложную готовность.

Чистая установка службы допускает `install.ps1 -ActivationOnly` с проверенным
публичным trust bundle; identity/CSR заранее не нужны. Для образа —
`stage-club-activation.ps1`: один закрытый ввод кода администратором, активация
отложена до следующей загрузки; подготовка отказывается при наличии device keys.
Образ не должен содержать ни зарегистрированную identity, ни pending private keys.
Неверная смена кода хранится отдельно (.pending), рабочий код/identity не удаляются.
Срок кода ограничивает новую регистрацию/re-enrollment; автоматическая оплата и
истечение подписки не реализованы. Явный отзыв кода/ПК блокирует существующие
устройства через прежнюю архитектуру revocation и lease.

## Передача production-обновления владельцу

Из среды разработки SSH к VPS недоступен. Production не обновлён, leaf не продлён,
реальные коды ещё не созданы. Ниже **изменяющая сервер команда**, запускать только
после зелёного CI нужного полного commit и с разрешения владельца. Не использовать
её как обычную установку ПК; не запускать bootstrap/CA rotation повторно.

В PowerShell из клона, checkout `main`, без локальных изменений:

```powershell
git pull --ff-only origin main
$release = (git rev-parse HEAD).Trim()
& .\tools\windows\update-activation-vps.ps1 -ExpectedCommit $release -ConfirmDeployment 'ACTIVATE-CODES-2.56.177.4'
```

Одна host-verified SSH-сессия, интерактивный пароль владельца; собирает Linux
бинарники именно из проверенного checkout, проверяет SHA256 всех артефактов,
показывает read-only preflight, принудительно обновляет даже совместимые `/3`
бинарники. Требует уже существующую `/3` baseline, systemd ≥247, тот же CA/SAN,
root-only CA key и существующий echo credential. PostgreSQL migration 002 — только
добавление. Штатный binary upgrade сохраняет pg_dump, старые binaries и units в
напечатанном `/etc/neexitlag.bak-<id>`; локальный authenticated TCP/UDP proof создаёт
и отзывает временное устройство. Identity владельца не заменяется.

Внешняя транзакция сохраняет `/etc/neexitlag`, leaf и управляемые units/helper в
`/var/backups/neexitlag-activation/<id>`. Независимый rollback timer 480 с и boot
recovery работают из постоянной копии. Затем устанавливает LoadCredential,
maintenance helper/timer, принудительно продлевает leaf тем же CA на 30 суток,
проверяет HTTPS и настоящий QUIC/mTLS `/3`, готовность enrollment. У leaf есть
свой rollback watchdog. При ошибке — возврат leaf/units/binaries; security-записи
БД не откатываются. При несовместимости старого binary с текущей security state
штатный rollback останавливает службы, сохраняя БД для безопасного разбора.

Для ручного отката на VPS под root (подставить **напечатанный** backup, не выдумывать):

```bash
python3 /var/backups/neexitlag-activation/<id>/deploy-activation.py rollback --backup /var/backups/neexitlag-activation/<id>
```

Только после `ACTIVATION_DEPLOYMENT_COMMITTED` и проверки владельцем существующего
клиента (билет + TCP/UDP) на VPS под root создать тестовые коды. Не включать запись
терминала/PowerShell transcript, не перенаправлять вывод в файл. Код отображается
один раз; впоследствии доступен только его публичный ID/статус, не исходный код.

```bash
/opt/neexitlag/maintenance/veliq-codes create --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token --kind club --limit 40 --name 'Тестовый клуб' --days 90
/opt/neexitlag/maintenance/veliq-codes create --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token --kind personal --limit 2 --name 'Личная проверка' --days 90
```

`list`/`machines --id <id>` возвращают страницу ≤128 записей и `next_cursor`.
Для продолжения — `--after <cursor>`; тихого обрезания нет. `revoke --id <id>`
отзывает весь код, `disable --id <id> --machine <hash>` блокирует конкретный слот.

Проверка ПК после обновления service/GUI: в Настройках — «Сменить», ввести код
через закрытое поле. Дождаться «активирован»; `activation.status` и обычный diag
показывают только состояния/сроки, не код. Перезапустить службу, проверить повторное
подключение; freeze на чистом activation-only образе — новый device key, тот же
слот, предыдущий ключ отозван. Не копировать зарегистрированный private key в образ.
Публичный trust bundle должен быть заранее проверен/подписан издателем; из
непроверенного ответа enrollment корневой CA не устанавливается.

Границы проверок: локальные тесты не доказывают production systemd/SSH rollback,
реальный UAC-off/WinDivert/GUI или работу у провайдера. 50 замен identity проверяются
на isolated PostgreSQL, а HTTPS с потерянным ответом — настоящим TLS тестового CA.
Hardware spoofing/администратор, имеющий клубный код, не устраняются без аппаратной
аттестации. При долгой freeze-эксплуатации revocations растут; лимит подписанного
конфига 1 MiB остаётся fail-closed, очистка security history автоматически не делается.

Плановое продление leaf перезапускает CP и relay согласно согласованному порядку:
это maintenance-событие с возможным кратким разрывом активных relay-соединений.
Оно отличается от 30-минутного same-session lease renewal, который не менялся.
Горячая перезагрузка server TLS без restart в этот этап не входит.

## Отказ обновления после CA-ротации: диагностика и первая команда

В `3f31c1f` binary preflight не учитывал уже выполненную fresh CA-ротацию:
требовал `test -r control/ca.key` от пользователя CP, хотя ключ намеренно root:600
и выдаётся службе через `LoadCredential`. Не были также допущены штатный
`91-veliq-fresh-ca.conf` и ровно `%d/veliq-device-ca-key`. Это воспроизведённая
несовместимость; старый `SAFE_DEPLOYMENT_FAILED` не сохранил точный exit/status
конкретного запуска, поэтому фактическое состояние VPS нужно сначала прочитать.
Пароль был принят и preflight исполнялся на сервере; scp здесь не используется,
SSH-сессия одна. Dot-source bootstrap не выполнял enrollment благодаря старому
entry guard, но давал вводящий в заблуждение `SSH_ENROLLMENT_FAILED` callstack.

**Первое действие владельца — read-only, не повторять deployment вслепую.**
PowerShell (обычный либо full-admin) из папки существующего репозитория:

```powershell
git pull --ff-only origin main
& .\tools\windows\verify-activation-vps.ps1
```

Пароль/host-key OpenSSH остаются интерактивными. На VPS Python работает из памяти:
нет staging/lock-файлов, сборки, enrollment, proof identity, миграций, pg_dump,
изменения конфигурации/таймеров или start/stop/restart. Запросы PostgreSQL заключены
в `BEGIN READ ONLY`; вывод содержит только публичные версии/хеши бинарников,
PID/start-time/состояния служб, порты, схему/количества строк, имена/состояния
таймеров и фазы backup. Ключи, коды, токены, raw stderr и содержимое конфигов
не выдаются. SSH-аудит и обычная статистика ОС/БД при чтении естественно меняются.

Для этого неудачного запуска baseline по умолчанию — установленные binaries
`2c06089f61c7b7a27cdf575f5cea4b834992426d`, migration 1. Поля:
- `binary[].same_binary`: running hash равен installed; `commit` сверяется с baseline.
- `database.activation_migration_not_applied`: migration 002 и её таблицы отсутствуют.
- `ca_access`: root-only ключ, прямое чтение службой и совпадение runtime-копии.
- `units` / `timers` / `backups`: следы старого внешнего guard, phase и путь backup;
  `BASELINE_WITH_DEPLOYMENT_ARTIFACTS` **не означает**, что вообще ничего не менялось.
- `historical_no_changes_proven=false`: без снимка ДО операции нельзя доказать
  отсутствие всех прошлых записей. Активный клиент также пишет nonce/телеметрию.

Старый coordinator создавал внешний backup и recovery unit **до** полного binary
preflight; его rollback мог перезапустить службы даже при неизменных binaries/БД.
По одному старому сообщению `no installation performed` обещать отсутствие
изменений нельзя. Если `PENDING_RECOVERY_REQUIRES_REVIEW` — сначала разобрать
указанный backup; read-only команда сама ничего не восстанавливает и не удаляет.

Исправление разрешает только точный проверенный LoadCredential layout. Права CA
не расширяются; runtime credential сравнивается с root-ключом приватно, служба
должна читать runtime-копию. Owned override `94-veliq-production-upgrade.conf`
идёт после 91/92 и сохраняет credential, удаляя bootstrap seeds и управляя полной
публикацией. Неизвестные drop-in/подстановки по-прежнему отвергаются.

Полная проверка кандидата теперь предшествует любому постоянному backup/guard и
остановке служб. Диагностика содержит `stage`, `step`, `command`, `exit_code`
(null, если дочерней команды не было), санированный `stderr`, `vps_modified`,
`backup`, `rollback`. Stderr — только allowlisted категории, например
`PERMISSION_DENIED`; непроверенный текст заменяется `REDACTED_UNRECOGNIZED_STDERR`.
Это намеренно не «маскировка по regex» с риском оставить неизвестный секрет.
`NO` — production изменений не запрашивали; `BACKUP_ONLY` — backup/частичный backup;
`YES` — были изменения; `POSSIBLY`/`UNKNOWN` требуют read-only проверки.
`rollback=COMPLETE_SECURITY_STATE_PRESERVED` не означает отсутствие предыдущих
перезапусков и не откатывает nonce/revocation/schema. Backup печатается сразу после
создания. При потере SSH нет ложного утверждения «VPS не изменён».

Повторный изменяющий запуск — только после разбора read-only отчёта и зелёных
проверок нового commit; в `-ExpectedCommit` нужен новый полный SHA, не `3f31c1f`.
На production в ходе разработки исправления ничего не выполнялось.


### Отказ read-only снимка (21.10.2026)

Причина `READ_ONLY_SNAPSHOT / RuntimeError` в 81b99ed воспроизведена:
в значении baseline по умолчанию было 38 hex-символов (пропущено `7d`),
а Python требует полный 40-символьный commit. PowerShell не валидировал
значение параметра по умолчанию. Исправлены оба defaults и добавлена проверка
до SSH. Этот дефект не относится к паролю, правам CA или версии Debian.

Общая диагностика read-only/update теперь содержит `code`, `step`, `command`,
`exit_code`, классифицированный `stderr`, `traceback` (только имя проверенного
исходника и номер строки; без текста строки, переменных и аргументов).
Неизвестный текст исключения и stderr скрываются. `READ_ONLY_COMMAND_PSQL`
отличает отказ БД от `READ_ONLY_REMOTE_IDENTITY`, `READ_ONLY_BASELINE`
и `READ_ONLY_CA_METADATA`. Для updater сохраняются backup/rollback/change state.
Вывод stdout больше не теряется при ненулевом SSH exit.

Фактический транспорт — ProcessStartInfo + base64 исходников + JSON stdin,
без scp и без shell heredoc; `Get-Content -Raw | ssh` не используется.
Исходники CRLF/UTF-8 BOM проверены через `compile(bytes)`; JSON bytes допускает
BOM. Launcher нормализует собственный CRLF/BOM, EnvironmentFile читается как
UTF-8 BOM-aware с проверкой единственного точного адреса (без shell/eval).
Updater использует тот же guard/диагностику; модуль включён в SHA256 manifest
и в постоянную копию rollback, поэтому rollback не зависит от временной папки.

Повторить только read-only проверку (PowerShell, корень клона, SSH root пароль):
```powershell
git pull --ff-only origin main
& .\tools\windows\verify-activation-vps.ps1
```
Эта команда не обновляет бинарники, не вызывает enroll/миграции/rollback,
не перезапускает службы. Настоящий результат Debian/VPS требует запуска владельцем;
локальные фикстуры не доказывают состояние production.

### После LEAF_RENEWAL_FAILED на 5bbf629

Сначала только read-only: `& .\tools\windows\verify-activation-vps.ps1`.
Разбор journal mismatch, schema 2/security-monotonic rollback, сертификатов,
повторного запуска и результатов — [ACTIVATION_DEPLOYMENT_RECOVERY.md](ACTIVATION_DEPLOYMENT_RECOVERY.md).
Полный pg_restore/DROP не выполнять: nonce/отзывы сохраняются. Наличие старых
бинарников со schema 2 не означает, что коды уже работают; нужен подтверждённый
новый deployment и активный renewal timer. Production этим не меняется.

Подписки, личный кабинет и привязка кодов к оплате — [ACCOUNTS.md](ACCOUNTS.md).
