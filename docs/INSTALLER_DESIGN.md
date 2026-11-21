# Проект установщика VELIQ

Дата: 19.10.2026. База аудита: `ea4afdf`, ветка `main`.
Статус: **проект, не реализованный установщик**. Документ не разрешает новые
зависимости, выдачу production credentials, изменение сертификатов или deployment.

## 1. Продуктовый результат и выбранный формат

Пользователь скачивает из GitHub Releases подписанный `VELIQ-Setup.exe`, запускает,
подтверждает штатный UAC и нажимает «Установить». Получает службу, драйвер и GUI.
Git, Go, .NET SDK, NuGet и PowerShell-команды на ПК не нужны. GUI публикуется
self-contained с .NET runtime внутри, как уже делает `build-desktop.ps1`.
«В один клик» не означает обход UAC, активации или согласия на сетевые политики.
Регистрация выполняется в GUI; при отсутствии сети установка возможна, активация
ожидает подключения. Установка файлов и готовность маршрутизации — разные статусы.

**Выбор: Inno Setup, один EXE, офлайн payload.** Причины: русский мастер,
UAC/elevation, ярлыки, запись в «Установленные приложения», silent-install для
управления клубом; меньше упаковочной сложности для первого выпуска, чем WiX MSI
с custom actions и отдельным EXE bootstrapper. Сам Inno не решает атомарность
службы/данных: её реализует отдельный подписанный установочный helper.

| Вариант | Решение |
|---|---|
| Inno Setup EXE | Рекомендуемый первый выпуск; компилятор нужен только CI |
| WiX MSI + Burn EXE | Следующий вариант при обязательном MSI/GPO/Intune; сложнее ownership/per-user actions и транзакции |
| MSIX | Не выбирать для первого выпуска с существующим SYSTEM service и kernel driver |
| EXE, запускающий текущий setup-e2e.ps1 | Не продуктовый путь: смешивает подготовку, credentials и разработку |

Версию Inno, лицензию для коммерческого распространения/стоимость и способ получения
компилятора утверждает владелец **до** добавления в CI. Пиннинг компилятора, его
подписи/SHA256 и версия Windows SDK/signing tools обязательны. Сейчас они не
добавляются. Первый поддерживаемый runtime — Windows 10/11 x64; ARM64 не обещается.

### Что уже есть и что предстоит сделать

Проверены чтением: `tools/windows/{install,install-desktop,update-service,uninstall,
reinstall-state,fetch-windivert,build-desktop}.ps1`, `core/controlclient/client.go`,
`core/security/signed.go`, `services/control-plane/{server,store}.go`, миграция
`001_initial.sql`, текущие workflows. Скрипты установки/enroll/provision не запускались.

- Текущий service install требует готовые device/trust файлы и owner SID.
- `tools/enroll` использует admin token для `POST /api/v1/devices`.
- Идентификатор и Ed25519 seed генерируются CSPRNG; повторно используются только
  при сохранённом `identity.json`. Потеря файла создаёт новую identity, не stable PC.
- Продление сертификата по signed device proof уже есть:
  `POST /api/v1/devices/renew`; tickets/mTLS/lease renewal остаются действующими.
- GUI уже self-contained; текущий workflow публикует Actions artifacts, но это
  ещё не готовый подписанный Setup в GitHub Releases.
- Activation codes, club slots, installer journal и безопасный pre-enrollment
  service mode пока отсутствуют. Нельзя выдавать их за настройки существующего API.

### Состав пакета и совместимость

| Компонент | Состав / размещение |
|---|---|
| Служба | Готовый `neexitlag-service.exe`, SYSTEM, AutoStart/recovery; существующий SCM ID сохраняется, DisplayName — «VELIQ Routing Service» |
| Захват | Неизменённые x64 WinDivert DLL/SYS, `pins.json`, лицензия и сведения о corresponding source |
| GUI | `VELIQ.exe` self-contained; совместимый alias `NeExitLag.exe` сохраняется, новых старых ярлыков нет |
| Ярлыки / удаление | Только VELIQ: меню «Пуск», необязательный рабочий стол, «Установленные приложения» |
| Trust bundle | Только публичные CA, публичные ключи проверки подписанного config и известный HTTPS endpoint; версия/сроки/подпись манифеста |
| Состояние | Существующие `%ProgramData%\neexitlag`, `%LOCALAPPDATA%\NeExitLag`, owner SID, service.json, IPC token, профили и recovery state сохраняются |
| GUI placement | Для первой версии существующий `%LOCALAPPDATA%\Programs\VELIQ` исходного пользователя; другой пользователь/клуб — явно назначенный SID, не SID повышенного аккаунта |
| Дополнения | Подписанные setup/helper/uninstaller, release manifest, лицензии; без debug tools, enroll/provision и ключей |

Не переносить машинную службу в каталог, доступный пользователю на запись. Для
совместимости первый выпуск сохраняет защищённый текущий путь service binary;
новый `%ProgramFiles%\VELIQ` возможен только отдельной миграцией SCM/recovery/firewall.

Установочный helper использует SCM/ACL/registry API, не исполняет скачанные скрипты
или произвольные команды. Его временный elevated IPC ограничен исходным SID,
одноразовым nonce, фазой установки и закрытым набором операций; пути проверяются
на reparse points и подмену. Непривилегированный GUI никогда не может указать
SYSTEM произвольный EXE, CA, источник обновления или исполняемый путь.

В payload — точные версии GUI/service/IPC/protocol/trust/schema, git SHA и SHA256
всех файлов в подписанном release manifest. `pins.json` сейчас генерируется
`fetch-windivert.ps1` после проверки закреплённого upstream ZIP; это не файл с
секретами и не самостоятельный корень доверия. Пакет включает его и сверяет с
утверждёнными source pins для WinDivert **2.2.2-A**: ZIP, DLL, SYS. Затем повторно
проверяет файлы при установке и runtime. Манифест фиксирует ожидаемый signer SYS;
DLL upstream unsigned — проверяется хешем, требовать от неё подпись ошибочно.
Драйвер не переподписывать и не менять его байты ради брендинга.

Trust bundle не содержит CA private key, signing private key, admin/echo/bootstrap
tokens, device identity/certificates конкретного ПК. Не устанавливать relay CA в
общесистемное Trusted Root для браузеров: доверие служебное, не MITM HTTPS.
Поворот trust — отдельная подписанная совместимая процедура, не «принять новый CA
с того же непроверенного URL». Неподходящая подпись/endpoint останавливает активацию.

### Порядок первой установки

1. До UAC сохранить реальный initiating user SID/session и выбранный club owner SID;
   elevation другим admin не должна превратить его HKCU в профиль пользователя.
2. Проверить OS, права, свободное место, подпись/manifest/pins, существующие SCM,
   owner и ACL. Foreign installation/policy не перезаписывать. Создать journal.
3. Разместить payload, установить ACL, службу и owned firewall admission для
   native TCP. Проверить ActiveStore/GPO; не отключать firewall/Defender.
4. Запустить службу в новом ограниченном `SETUP_PENDING_ACTIVATION` режиме:
   только локальный bootstrap/status IPC, без захвата и без fake/demo PASS.
   Этот режим предстоит реализовать, текущую службу без identity так не запустить.
5. Поставить GUI/ярлык исходному пользователю, открыть unelevated GUI, выполнить
   активацию. Приватный device key генерирует только служба на этом ПК.
6. Проверить identity/certificate/trust, подписанный config, IPC, backend и
   readiness. Optimize включать по согласию пользователя/клубной политике, после
   готовности. Для браузеров сохранить актуальный owned PAC crash-guard; fresh
   без guard не объявлять готовым. Автоустановка не обходит существующий blocker.
7. Завершить journal. При CP outage — «Установлено; активация ожидает подключения»,
   при driver/GPO failure — конкретная ошибка/откат, не «Всё работает».

## 2. Регистрация без admin token на каждом ПК

### Предлагаемый контракт control-plane (новая разработка)

Администратор в защищённом кабинете/отдельном admin tooling создаёт grant. Только
там остаются admin credentials. Публичный release содержит лишь endpoint и trust.
Обычный пользователь вводит полученный код/сканирует QR в GUI; код передаётся
службе по защищённому IPC. Не помещать код в командную строку, URL query, логи,
общий реестр или общедоступный конфиг.

Grant: случайный секрет не менее 128 бит энтропии (предпочтительно 256), сервер
хранит его хеш, ID, tenant/club, назначение `enroll-only`, expires_at, max_redemptions,
счётчик, статус отзыва, допустимые slots/версию клиента и audit. Это не relay ticket
и не право администрирования. Предлагаемые сроки, утверждаемые владельцем:
личный код — 24 часа/1 новый ПК; клуб — 72 часа/36 первичных slots. Не продлевать
его автоматически после каждого reboot.

Новые endpoints, условно `/api/v1/activation/{challenge,redeem}`:

1. Служба генерирует и надёжно сохраняет pending device ID/Ed25519 key; получает
   короткоживущий одноразовый challenge. Подписывает domain-separated proof,
   включающий challenge, grant ID, public key, requested device ID, request ID,
   slot/generation и назначение. Проверяются время, nonce, TLS и размер запроса.
2. В одной DB-транзакции сервер проверяет grant/revocation/expiry, proof, доступный
   slot и квоту; регистрирует public key и redemption, расходует один activation.
   Уникальные constraints + блокировка/условный UPDATE защищают от 37 параллельных
   регистраций при лимите 36. Ошибка БД не превращается в успешную регистрацию.
3. Повтор того же request ID **и того же ключа** возвращает тот же результат без
   расходования второго места; другой ключ с тем же request ID отвергается.
   Операция имеет durable pending/completed state, чтобы сбой выдачи сертификата
   не терял слот. Потеря ответа не запускает генерацию новой identity.
4. Сертификат выпускается существующим CA с теми же проверками; после сохранения
   используется существующая signed-proof auth, ticket replay protection,
   certificate renewal и QUIC mTLS. При утрате только ответа/сертификата сервер
   допускает безопасное восстановление по доказанному уже зарегистрированному
   ключу, без повторного enrollment и без обхода revocation.

Защита endpoint: отдельные bounded rate limits по source/grant/slot, лимит pending
challenges и их TTL, constant-time проверки секретов, redaction и audit без самого
кода. Учесть 36 ПК за одним NAT: throttling не должен навсегда блокировать клуб.
Запрет grant останавливает новые регистрации; **не равен** отзыву существующих ПК.
Отдельный отзыв device/slot прекращает auth/renewal и публикуется relay через
существующую полную signed revocation publication. Указать владельцу фактический
проверенный срок распространения отзыва; не обещать нулевую задержку при outage.

Существующий `/api/v1/devices` и `tools/enroll` остаются для admin/dev сценария;
новый публичный endpoint не перенаправляет на них клиентский admin token. Сейчас
Store.Register делает INSERT, не idempotent upsert/замену ключа: новая логика
нуждается в собственной миграции и тестах, не в повторении старого POST на reboot.
Старые клиенты, identities, CA, config signatures, tickets и `/3` не меняются.
Доступность activation API проверяется явно; старый CP возвращает понятный
`ACTIVATION_UNSUPPORTED`, а не fallback на anonymous/admin enrollment.
Реализация потребует отдельного одобрения и deployment CP; этот документ его не делает.

### Можно ли вшить код в установщик клуба

**Не в публичный GitHub Release.** Рекомендуется один публичный подписанный EXE
и отдельный приватный provisioning grant. Для unattended установки management
система передаёт его через защищённый канал SYSTEM, без argv/общего share.

Если владелец выбирает персонализированный club EXE, это отдельный приватный
подписанный пакет с коротким grant (72 часа/36), никогда не public artifact/cache.
Секрет из EXE извлекаем: упаковка/подпись его не шифрует и не делает machine-bound.
Утечка допускает захват оставшихся slots до expiry; нужны отзыв, наблюдение и
при необходимости подтверждение списка ПК владельцем. Для production предпочтительны
36 одноразовых slot credentials, а не один общий bearer на все ПК. Ни один из них
не является общим device private key или вечным bypass на повторное enroll.

## 3. Клуб: образ, 36 ПК и ежедневный откат

### Рекомендация: образ без identity + постоянное защищённое состояние каждого ПК

В golden image включаются подписанные binaries, WinDivert, pending-activation
служба, публичный trust и шаблон профилей. **Не включаются** identity/seed, device
certificate, IPC token, использованный grant и активный пользовательский PAC с
адресом/nonce другой машины. Image-seal проверка должна остановить выпуск при их
наличии. Приватный activation grant не оставлять внутри общего образа.

Для каждого физического ПК настроить исключение rollback для защищённого состояния
службы в `%ProgramData%\neexitlag` (или отдельный persistent volume с поддержанной
миграцией путей). Не предлагать junction как обход: текущие install/reinstall
защищаются от reparse points. Состав постоянного состояния: identity, сертификат,
IPC token, owner binding, актуальная service.json, profiles/state, journal и
metadata поколения. Код/драйверы обновлять в образе в maintenance window. GUI state
по прежнему per-user; нельзя смешивать профили разных SID.

| Событие | Ожидаемое поведение |
|---|---|
| Первое развёртывание | Локальная CSPRNG identity, один grant/slot, атомарная активация |
| Каждый reboot/rollback | Та же identity/device ID/slot; проверка версии/ACL, обычный auth/renewal; новый grant не нужен |
| Истёк сертификат, ключ сохранён | Обновить по existing signed proof; CP down — bounded retry и явный pending, без нового device |
| Потеря постоянного хранилища | Не генерировать бесконечно новые регистрации; `IDENTITY_RECOVERY_REQUIRED` и отдельный replacement workflow |
| Переустановка OS / смена SID | Явно подтверждённый rebind/replace; не присваивать прежнюю identity по одному имени ПК |
| Отзыв ПК | Slot/device заблокирован; reboot/старый snapshot не восстанавливает доступ |

Состояние доступно SYSTEM/admins, не игрокам. Текущий ACL helper уже даёт GUI owner
доступ к binary/IPC token/public guard, но **не** к identity/seed: это сохранить.
IPC token даёт локальный доступ в рамках назначенного owner, не регистрацию новых
устройств. GUI остаётся без elevation. Для клуба с одним ограниченным Windows
аккаунтом SID назначается явно на каждом ПК после imaging, а не копируется SID
admin из золотого образа. Несколько разных session/user SID на одной машине —
отдельное расширение текущего single-owner IPC; первый выпуск это не обещает.

36 ПК получают 36 независимых случайных ключей, не производных MAC/SMBIOS/hostname.
Эти признаки можно использовать как необязательный диагностический сигнал, не как
доказательство владения. Проверка образа должна выявлять повторный public-key
fingerprint. ACL/BitLocker и исключение из snapshot защищают локальную копию;
локальный администратор всё ещё может извлечь файловый ключ. Защита от его
клонирования требует отдельного hardware-backed механизма, не обещается сейчас.

### Machine slots и замена ключа

Slot — стабильное место `club/PC-01`, не секрет. Его текущие device ID, public key,
generation, status и last_seen хранятся сервером. Повторная аутентификация того же
ключа не создаёт строку devices. При согласованной замене используется proof старого
ключа плюс подтверждение клубного администратора либо отдельный одноразовый
replacement grant, привязанный к slot. Номер generation монотонный на сервере.

Замена создаёт новую key/device generation, старую атомарно отзывает и планирует
полную signed publication. Не оживлять revoked device и не менять key под прежним
ID без анализа fingerprint/ticket binding. Оборванный ответ идемпотентно восстанавливается;
новый доступ не считать готовым до требуемой публикации отзыва. Хранить audit и
revocation tombstones; при ошибке publication явный pending/retry, не тихий успех.

Если **вообще нет** ни persistent storage/TPM, ни внешней системы с отдельным
machine-bound credential, после полного стирания состояния невозможно безопасно
доказать, что это тот же ПК, автоматически и без нового секрета. Общий вечный
club code и «тот же MAC» эту задачу не решают. Такое развёртывание блокирует
unattended требование; владелец должен выделить persistent исключение или отдельный
управляемый аппаратный bootstrap. TPM-wrapped Ed25519 seed — возможный следующий
этап; это не заявление о текущей поддержке Ed25519 в Windows TPM/CNG.

Stale cleanup: `last_seen`/inventory, ограниченные pending registrations с TTL,
архивация abandoned slots по политике владельца. Молчание не означает отзыв:
не удалять живые офлайн-ПК автоматически. Удаление старых записей не должно удалять
revocation evidence, пока возможны валидные сертификаты/tickets/config snapshots;
конечные сроки хранения и безопасную компактацию сначала доказать тестами.

## 4. Подпись, SmartScreen и антивирусы

Владельцу нужны проверенная личность издателя, сертификат/доверенный сервис
Authenticode signing для Windows и допустимое по политике CA защищённое хранение
ключа (hardware token/HSM/managed signing), timestamp service и бюджет на продление.
Подписывать GUI, service, setup/helper/uninstaller и итоговый EXE установщика;
проверять publisher/chain/timestamp после сборки. Ключ подписи не хранить в Git и
не выдавать PR workflow. Плановая ротация publisher/release keys должна иметь
доверенную цепочку, а не принимать любой «Valid» сертификат другого издателя.

Подпись не гарантирует немедленного исчезновения SmartScreen и всех AV срабатываний.
Новый издатель/редкий бинарник с WinDivert может получить предупреждение; EV не
обещает автоматического обхода репутационных проверок. Нужны пилот на чистом Win11
с Secure Boot/Memory Integrity, Defender/SmartScreen, проверка целевых клубных AV,
процедура отправки false positive в Microsoft/AV и стабильное имя издателя.
Не предлагать отключать Defender, Secure Boot или включать test signing.

SYS остаётся официальным подписанным драйвером с прежними pins; подлинность SYS
не заменяет подпись собственных EXE. Проверить redistribution условия WinDivert
LGPLv3, комплект license/NOTICE и соответствующий source/build для точной версии,
заменяемость DLL в рамках требований лицензии и зависимостей .NET/Inno. Не
разрешать runtime загрузку изменённой DLL, обходящую security pins: другой build
требует явной безопасной политики и выполнения лицензионных обязательств.

## 5. Обновление, откат и удаление

### Обновление тем же Setup EXE / кнопкой «Обновить»

Первый этап — тот же подписанный Setup поверх установленной версии; автоматический
скачиватель позже. GUI unelevated, повышенный helper подтверждает update по UAC
или клубному management agent. Проверять не только HTTPS/SHA256, но подпись
доверенного release manifest, publisher, channel, min/max IPC/schema и разрешённую
версию; старый валидно подписанный пакет не должен позволять незаметный downgrade.

1. Определить существующую установку, SCM binary path, owner SID, versions, ACL и
   состояние браузерных policies. Ничего не re-enroll и не менять trust/identity.
2. Проверить payload до остановки службы; staged files на том же volume. Создать
   защищённый persistent backup binary/config/state/ACL/manifest и journal.
   Секреты в backup имеют не более широкие ACL; bounded retention/квота диска.
3. Согласованно закрыть только GUI/recovery helper своей установки. Браузеры и
   игры не убивать. Наличие чужого handle/процесса — понятная ошибка/отложенный
   restart, не массовый taskkill. Не обещать сохранение service-owned sockets:
   остановка службы их прерывает, приложения восстанавливают соединения.
4. Сохранить owned PAC fail-closed guard, заменить совместимые binaries атомарно
   по journal, восстановить ACL, проверить действующее app-scoped firewall.
   Не переписывать foreign policies. Состояние менять только миграцией с backup.
5. Запустить службу; проверить actual build/hash, IPC version, backend/driver,
   identity fingerprint, config validation, профили и GUI connection. Online
   tickets/TCP/UDP readiness — отдельная проверка при доступном CP/relay, не
   основание заново регистрировать устройство или удалять старую конфигурацию.
6. При локальной readiness/миграционной ошибке восстановить binary, state/ACL и
   owned policy из journal, повторно проверить старую службу. После power loss
   journal продолжается/откатывается до known-good; новый payload не считается
   installed только по наличию файлов. Не заменять shared WinDivert при занятых
   handles: проверка потребителей и при необходимости явный reboot pending.

Если миграция несовместима со старым binary, backup state обязателен; backup не
может откатить серверный отзыв/generation. Не восстанавливать отозванную identity.
При невозможном rollback — «Восстановление требуется», сохранённые backups и
код ошибки, без тихого DIRECT для protected или попытки provision VPS.

В клубе обновлять baseline image и persistent-state schema согласованно: иначе
после reboot старый binary увидит новый формат. Gate проверяет минимальную версию,
club rollout: 1 ПК → 3 ПК → остальные; сохранённый предыдущий образ для отката.
Self-update в rollback overlay без обновления образа не считается обновлением.

### Удаление и ремонт

«Установленные приложения → VELIQ → Удалить» / «Восстановить». По умолчанию удалить
службу и наши executables/ярлыки/autostart, **сохранить** identity/config/profiles
для reinstall с явным сообщением. Отдельная неподставленная заранее опция
«Удалить также данные и регистрацию устройства» требует подтверждения; online
device revoke/new reinstall описываются отдельно, offline показывает pending.
Удаление файлов само по себе не отзывает серверный доступ.

Сначала согласованно отключить Optimize для владельца, разобрать owned PAC/recovery,
восстановить предыдущую политику только если её текущее значение всё ещё наше,
потом закрыть listener/службу и убрать принадлежащие нам firewall rules. Если
пользователь отключён/его hive недоступен или foreign policy уже изменилась,
не стирать чужой HKCU; предусмотреть безопасный owner-logon cleanup либо завершить
с явным pending. Нельзя оставить Mandatory PAC на мёртвом proxy или молча снять
защиту при неудачном upgrade. При явном полном удалении пользователь подтверждает
прекращение защиты. Shared WinDivert не удалять, если им пользуется другой продукт.

Текущий uninstall.ps1 удаляет SCM и сохраняет файлы: полноценный uninstaller
должен реализовать остальные шаги отдельно, не выдавать этот скрипт за готовое удаление.
Repair проверяет pins/ACL/owned policy, восстанавливает **ту же** identity; не меняет
owner SID, device key или сертификаты без отдельной причины/согласия.

## 6. Интерфейс и бренд

Весь обычный UX на русском: «Установить VELIQ», «Активация», «Готово», «Требуется
подключение», «Восстановить», «Удалить», прогресс и конкретная ошибка с безопасным
кодом. DisplayName службы, ARP entry, tray/ярлыки/название загрузки — VELIQ.
Нового случайного логотипа нет; до утверждения используем согласованные текущие
ресурсы. Оформление — минимальное, чёрное/белое, с учётом контраста, масштаба и
штатных Windows/UAC controls; не менять системный диалог ради бренда.

Не выводить внутренние legacy identifiers в обычных сообщениях мастера. При этом
SCM `neexitlag`, pipe `neexitlag-v1`, exe службы, ALPN, каталоги, mutex/HKCU Run,
wire/config IDs **не переименовывать**. В расширенной системной диагностике/пути
файла Windows они могут быть видны; абсолютное отсутствие старого имени во всей
ОС несовместимо с требованием сохранить эти идентификаторы. Переименование —
отдельная миграция, не часть установщика. Юридический издатель в UAC/подписи должен
быть настоящим; он может отличаться от торговой марки VELIQ.

При применении Chrome/Edge policies браузер может показывать «Управляется вашей
организацией»: честно объяснить, что VELIQ управляет своим PAC. Не скрывать надпись
обманом и не обещать её устранение установщиком. Native-only crash-safe architecture
ещё не реализована; установка не является разрешением на снятие guard/этап (в).

## 7. GitHub Actions и выпуск

Release-only pipeline (проект): защищённый tag `vX.Y.Z` → фиксированный git SHA →
Windows/Linux tests → упаковка → подпись → чистая VM install/upgrade/rollback →
публикация GitHub Release. Скачиваемый asset: `VELIQ-Setup.exe`; рядом versioned
manifest, SHA256SUMS и подпись/attestation manifest, без персональных club пакетов.
Tag/версия/GUI/service build должны совпадать. Повторный выпуск того же номера с
другими bytes запрещён; исправление получает новый номер.

- PR builds: no signing secrets/write release permission; installer smoke без
  production credentials на disposable VM, activation через isolated CP/DB/relay.
- Build tools/WinDivert закреплены по версии и SHA256; обязательны installable
  license/source notices и проверка trusted SYS. Паковать обычный runtime payload,
  не текущий весь `bin/release/tools/windows` с административными dev-скриптами.
- Собрать собственные EXE → подписать их → вычислить **post-signing** file hashes
  → составить payload manifest → собрать/подписать Setup → вычислить окончательный
  SHA256 Setup и подписать внешний release manifest. Timestamp меняет bytes:
  хеши до signing не объявлять хешами загрузки.
- Release job получает минимальный `contents:write` только в защищённом environment
  после gates/approval владельца; предпочтительно короткоживущая signing identity
  через OIDC, если выбранный сервис поддерживает. Не подписывать недоверенный PR.
- Создать draft release, загрузить assets, скачать обратно и сверить SHA256,
  подписи, manifest, содержимое; лишь затем publish. Частичный upload не «успех».
  Provenance содержит workflow/tool versions/SHA, но воспроизводимость подписанного
  EXE byte-for-byte не обещается из-за timestamp; unsigned payload сравним отдельно.

### Квота артефактов

Текущая квота Actions artifacts уже мешает CI; это release blocker, а не PASS.
Не добавлять ещё полные дубли `VELIQ`/legacy установщика на каждый push. Существующих
потребителей legacy artifacts не ломать: сначала инвентаризация/согласованная
миграция, затем изменение retention/дубликатов, не удаление молча.

Для нового packaging job: один canonical installer artifact на сборку; короткий
retention (предложение 3 дня для PR, 7 для тестовых builds), малые sanitised logs,
кэши только инструментов/зависимостей, никогда credentials. Успешный release
установщик хранится как **GitHub Release asset**, а не полагается на истекающий
Actions artifact. Лимиты Releases, bandwidth, billing и политики хранения тоже
проверить по тарифу: это не обещание безлимитного/вечного бесплатного хранилища.
Можно передавать release payload в том же job и публиковать после всех gates,
не создавая лишний большой промежуточный artifact. Ошибку требуемой загрузки не
маскировать continue-on-error. Удаление старых artifacts/изменение бюджета —
только отдельное решение владельца; эта задача ничего не удаляет.

### Обязательные gates будущего установщика

1. Чистая Windows VM без Go/Git/.NET SDK, обычный user с UAC; install/activation,
   GUI unelevated, hashes/signatures/pins, SCM/ACL/IPC и no secret logs.
2. Activation: expiry, revoke, 36 параллельных success/37-й отказ, replay, lost
   response, crash до/после commit, CP/DB outage, wrong key/slot/tenant; old enroll
   и existing signed-proof/tickets/revocations не сломаны.
3. Образ на двух независимых ПК → разные fingerprint/IPC tokens; 36 slots ×
   повторные reboot/rollback не увеличивают devices. Порядок image/overlay version,
   утрата persistent identity, replacement и revoked snapshot recovery.
4. Upgrade существующей установки: прежние SID/key/device ID/profiles/config,
   Chrome/Edge recovery; чужие policies/SCM/каталоги; UAC другого admin; abort/power
   loss после каждой journal фазы, disk full, locked driver/GPO, automatic rollback.
5. Без ручного закрытия браузера: подготовленные owned guards, новые соединения
   работают по существующей архитектуре; old TCP pinned, protected no DIRECT,
   games DIRECT, driver failure/crash fail-closed. Не путать local health с ISP PASS.
6. Uninstall/repair/reinstall, optional data wipe, offline revoke/pending, несколько
   продуктов с WinDivert, запуск после отсутствующего owner user/hive.

## 8. Решения владельца, риски и этапы

До реализации владелец утверждает:

- Inno Setup/версию/лицензию и новые CI build tools; нужен ли MSI сразу.
- Юридического publisher, signing provider/сертификат/HSM, расходы, release approval.
- Пользовательскую активацию: кто выдаёт коды, сроки/квоты, revoke/replacement,
  privacy/audit retention; HTTPS endpoint и состав публичного trust bundle.
- Для клуба: persistent rollback exclusion, owner/session SID модель, 36 slots,
  приватную доставку bootstrap и maintenance окна обновления образа.
- Автообновления/consent/перезапуск службы, backup retention, release канал,
  retention/billing Actions и разрешённую cleanup политику.

| Приоритет / этап | Результат и ориентировочный объём одного инженера |
|---|---|
| P0 — уточнение (1–2 раб. дня) | Решения выше, лицензии, аудит чистой VM, согласованный manifest/identity контракт |
| P0 — installer foundation (4–6 дней) | Подписываемый EXE/helper, pending mode, UAC/SID/ACL, offline payload, first install и smoke |
| P0 — activation CP + GUI (5–8 дней) | Миграция grants/redemptions/slots, signed challenge, idempotency/revocation, GUI и isolated integration |
| P0 — club imaging (3–5 дней) | Seal image, persistent state/owner binding, unattended bootstrap, reboot/rollback/36 PC simulation |
| P0 — servicing (4–6 дней) | Update journal, backups, policy cleanup, repair/uninstall, fault injection и rollback |
| P1 — signing/release/pilot (3–5 дней) | Protected Actions, signing, SHA256 roundtrip, VM matrix, 1/3/36 pilot и AV проверка |
| P2 — после пилота (отдельная оценка) | Background updater, MSI/MDM, multi-user IPC, hardware-backed anti-clone, inventory cleanup UI |

Ориентир до первого проверяемого production-кандидата: **20–32 инженерных дня** плюс
пилот 3–5 дней; это порядок объёма, не обязательство даты. Фазы частично пересекаются;
выдача signing identity, AV review и организационные решения могут занять недели
дополнительно. Подписанный installer без activation/club lifecycle — промежуточная
сборка, не завершённый сценарий «36 ПК после отката».

Главные release blockers: clone/утрата identity; утечка club grant; неверный SID при
UAC; foreign/мёртвый Mandatory PAC; откат image на несовместимую schema; доверие
чужому signer/manifest; неподдерживаемый driver/GPO; Actions quota. Всё это требует
проверок на Windows, не только наличия красивого setup EXE.

### Вероятные будущие файлы (ничего из списка сейчас не меняется)

- Новые `deploy/windows/installer/*` (Inno script, локализация, manifest schema),
  новый подписанный setup helper, `tests/installer/*`, release workflow.
- `services/client-service/cmd/service/*`, manifest/ACL/IPC helpers — pending mode,
  bounded installer operations/journal; GUI activation/update UI и desktop tests.
- `services/control-plane/{server,store}.go`, новая migration, `core/controlclient/*`
  — grants/slots/idempotency; существующий `tools/enroll` контракт сохраняется.
- Windows integration: существующие install/reinstall/update/firewall/recovery
  контракты использовать как проверяемые требования, не переписывать молча.
- `docs/INSTALLER_DESIGN.md`, будущие installation/club runbooks; изменение правил
  ownership и deployment — по отдельной реализации, не этим документом.

Этот коммит содержит только проект. На ПК ничего запускать не требуется; production
VPS, сертификаты, credentials, код и PR #8 не изменяются.
