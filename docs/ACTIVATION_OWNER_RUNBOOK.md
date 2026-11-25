# Коды VELIQ: сценарий владельца после deployment

21.10.2026, по сообщению владельца deployment ecd310a прошёл:
COMPATIBLE_ADDITIVE_SCHEMA2_SECURITY_STATE_PRESERVED, renewal SCHEDULED,
leaf до 20.11.2026, activation_codes=0. На VPS ничего не выполнялось.
Ниже команды выполняет только владелец. CA rotation/provision/update повторять
не нужно. Код активации не содержит CA и не заменяет проверенный public trust.

## 1. Создать два кода

На доверенном ПК владельца: PowerShell, обычный пользователь, любая папка.
Не использовать запись терминала/transcript, Tee-Object/перенаправление вывода.
В этой сессии будут один раз показаны секретные коды. Сначала открыть одну SSH
сессию; сверить host key с уже известным ключом сервера, не отключать проверку:

```powershell
ssh root@2.56.177.4
```

Следующие команды — уже в shell VPS под root. Первые две только читают:

```bash
/opt/neexitlag/maintenance/veliq-codes list --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token
```

```bash
openssl x509 -in /etc/neexitlag/control/ca.pem -noout -fingerprint -sha256
```

Сохранить public CA fingerprint для проверки скачанного public CA ниже.
Создание — это запись в БД, не read-only. Выполнить каждую команду ОДИН раз:

```bash
/opt/neexitlag/maintenance/veliq-codes create --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token --kind club --limit 40 --name Club-40 --days 90
```

Сразу сохранить `code` и `id` в менеджер паролей с копией вне freeze-ПК
(например, синхронизированном на телефоне владельца). Поле `id` — публичный
идентификатор, `code` — секрет. Не вставлять code в чат/скриншот/командную строку,
не сохранять plaintext в репозитории. `list` не сможет восстановить забытый code.
Клубный код рассчитан на 40 активных машин, не на 40 запусков или CSR.

```bash
/opt/neexitlag/maintenance/veliq-codes create --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token --kind personal --limit 2 --name Personal-trial --days 7
```

Аналогично сохранить второй code/id. Лимит personal в текущем API ровно 2.
Сроки в этом примере: клуб 90 суток, пробный личный 7 суток. `--days` ограничивает срок приёма новых активаций/enroll. Это не таймер
принудительного отключения уже активированного устройства: ticket/certificate
пути проверяют отзыв device, а не expires_at кода. Для завершения теста явно
использовать revoke ниже; мгновенное закрытие всех существующих сессий не обещается.
На сервере хранится
только SHA256 кода, metadata и слоты; admin token остаётся на VPS. На активированном
клиенте сам код сохраняется в защищённом SYSTEM/Administrators хранилище для
повторного enroll. Нормальный GUI его обратно не читает.

```bash
exit
```

## 2. Пустой Windows-ПК: установить без старой device identity

Git, Go, .NET SDK 8, Python уже установлены. Команды по одной из корня клона в
профиле владельца, например `$HOME\VELIQ`; путь C:\VELIQ не требуется.
Исходники — main. Не выполнять bootstrap-fresh-pc: это другой, SSH-enroll
путь, он не проверяет сценарий активации кодом.

```powershell
git pull --ff-only origin main
```

В обычном PowerShell владельца (при UAC off — существующий full-admin под тем же
пользователем, как на тестовом ПК). Проверить SDK, не только наличие dotnet:

```powershell
dotnet --list-sdks
```

```powershell
. .\tools\windows\activation-nuget.ps1
```

```powershell
Initialize-ActivationNuGetSource
```

```powershell
& .\tools\windows\build-e2e.ps1
```

```powershell
& .\tools\windows\build-desktop.ps1
```

```powershell
& .\tools\windows\fetch-windivert.ps1
```

fetch-windivert предназначен для пустой папки .e2e\windivert; если уже подготовлена,
не удалять/пересоздавать, использовать её pins.json. Скрипт проверяет закреплённые
SHA256 и подпись SYS. Устаревшие/другие драйверы не подставлять.

Создать папку только для ПУБЛИЧНОГО CA:

```powershell
New-Item -ItemType Directory -Force .\.e2e\activation-trust | Out-Null
```

У владельца есть root SSH. Скачать только public ca.pem через SSH с проверенным
host key (пароль вводится в SSH, не в аргументы). Не копировать ca.key/admin.token,
identity/device.pem или весь /etc/neexitlag:

```powershell
scp -o StrictHostKeyChecking=yes root@2.56.177.4:/etc/neexitlag/control/ca.pem .\.e2e\activation-trust\ca.pem
```

На новом ПК сначала установить доверие к SSH host key обычным `ssh root@2.56.177.4`
и сверкой с известным ключом; затем выйти и повторить scp. Отпечаток public CA
вычисляется по DER сертификата (не SHA256 текстового PEM файла):

```powershell
$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 ((Resolve-Path .\.e2e\activation-trust\ca.pem).Path)
```

```powershell
$sha = [Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-',':') } finally { $sha.Dispose(); $cert.Dispose() }
```

Он должен совпасть с openssl fingerprint из доверенной SSH-сессии. При несовпадении
остановиться. В текущем развёртывании после ротации один CA обслуживает relay
и control-plane. Нужен также явный cp-ca.pem для HTTPS-клиента control-plane;
одного ca.pem недостаточно для ConnectRemote после активации:

```powershell
Copy-Item .\.e2e\activation-trust\ca.pem .\.e2e\activation-trust\cp-ca.pem
```

Оба файла ПУБЛИЧНЫЕ; содержимое одинаково только для текущей общей CA.
Этот public CA можно включить в доверенный клубный образ/пакет,
тогда SSH на каждом клиенте не нужен. Код и ключи устройства в public пакет не входят.
Публичный CA не скачивать через неподтверждённый HTTPS и не брать из enroll reply.

Для установки службы: elevated PowerShell под ТЕМ ЖЕ владельцем, та же папка клона.
На UAC-off ПК окно уже full-admin; отдельная эскалация не нужна. Служба должна
отсутствовать — это именно чистый ПК; установленную службу не удалять ради теста.

```powershell
$ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

```powershell
$pins = Get-Content .\.e2e\windivert\pins.json -Raw | ConvertFrom-Json
```

```powershell
& .\tools\windows\install.ps1 -ActivationOnly -ServiceExecutable .\bin\windows-e2e\veliq-service.exe -OwnerSid $ownerSid -TrustDirectory .\.e2e\activation-trust -DriverDirectory .\.e2e\windivert -DllSha256 $pins.dll_sha256 -DriverSha256 $pins.driver_sha256 -ControlPlaneUrl https://2.56.177.4:8443 -ProbeTarget 2.56.177.4:40000 -TCPProbeTarget 2.56.177.4:40000
```

Приватный device key при этом не импортируется. install фиксирует fingerprint
проверенного CA в service.json и сохраняет обычные ACL/owner IPC checks.
В обычном PowerShell того же владельца (при UAC off — существующий режим):

```powershell
& .\tools\windows\install-desktop.ps1
```

```powershell
Start-Process (Join-Path $env:LOCALAPPDATA 'Programs\VELIQ\VELIQ.exe')
```

В GUI должен появиться экран «Введите код активации». Вставить ОДИН из сохранённых
кодов в закрытое поле, нажать «Активировать». При уже существующей legacy identity:
Настройки → «Сменить»; это другой сценарий, не clean-PC. Подождать «Код активации:
активирован», затем включить «Оптимизировать». Не закрывать Chrome/Edge ради активации.

Read-only проверка на ПК, из клона под SID владельца:

```powershell
. .\tools\windows\common.ps1
```

```powershell
Invoke-ServiceIPC 'activation.status' | Select-Object state,error,has_identity,ca_not_after,server_not_after
```

```powershell
Invoke-ServiceIPC 'status' | Select-Object connected,optimizing,demo
```

Успех: state=ACTIVATED, has_identity=True, error пустой, connected=True, demo=False;
после Optimize — optimizing=True. Дополнительно реальное открытие нужного сайта/
приложения и routing diagnostics: ACTIVATED само по себе не доказывает Internet PASS.
CODE_REQUIRED/ACTIVATING/ACTIVATION_ERROR не являются успехом. При отсутствии
активации не выводить activation-code.json/private files; безопасный status выше достаточен.

## 3. Freeze и повторная установка

Если baseline действительно пустой, после reboot программа и введённый код
исчезнут: нужно снова установить ActivationOnly и ввести ТОТ ЖЕ код. Новый код
выпускать не нужно. Для того же (code, hardware hash) новый private key создаётся
на ПК, новый device_id атомарно заменяет предыдущий, прежний device отзывается,
а активный слот остаётся ОДИН. Число строк devices/revoked при этом растёт — это
не число занятых мест. UUID платы, serial и MAC выбранного физического адаптера
должны быть прежними; MachineGuid Windows не используется. Замена/переключение
основного адаптера может изменить hardware hash и занять другое место.

Для клуба без ручного ввода после каждого reboot нужен подготовленный freeze-образ:
ActivationOnly service + GUI + проверенный public CA/driver, БЕЗ device identity.
До сохранения образа, elevated под владельцем, выполнить:

```powershell
& .\tools\windows\stage-club-activation.ps1
```

Ввести клубный код скрыто. Успех staging: CODE_STAGED, это ЕЩЁ НЕ серверная
активация. Не перезапускать службу/ПК и не активировать GUI перед сохранением образа:
первый boot каждого физического ПК должен самостоятельно создать свой ключ.
Образ содержит защищённый код, но не общий private device key. После каждого
freeze boot новый ключ заменяет старый в том же слоте. Администратор образа может
извлечь код; код можно отозвать/ограничить по сроку и числу мест.

## 4. Read-only серверная проверка и освобождение места

PowerShell на ПК владельца → одна SSH-сессия:

```powershell
ssh root@2.56.177.4
```

В shell VPS, root, только чтение:

```bash
/opt/neexitlag/maintenance/veliq-codes list --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token
```

Подставить публичный ID нужного кода из ответа create/list (НЕ секретный code):

```bash
/opt/neexitlag/maintenance/veliq-codes machines --id CODE_ID --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token
```

Ответ machines содержит machine_hash, device_id, disabled. occupied seat =
disabled=false. `next_cursor` непустой -> повторить ту же команду с `--after CURSOR`;
не считать одну страницу полным перечнем. При 40/2 слотах обычно одна страница.
Сводка БД без code_hash/секретов (имя БД в текущей установке neexitlag):

```bash
runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d neexitlag -c "SELECT c.id,c.kind,c.seat_limit,c.revoked,count(s.machine_hash) FILTER (WHERE NOT s.disabled) AS occupied FROM activation_codes c LEFT JOIN activation_slots s ON s.code_id=c.id GROUP BY c.id ORDER BY c.id;"
```

При повторном freeze/enroll occupied для этого кода не должен увеличиться;
device_id того же machine_hash изменится. Проверить последнюю identity/отзыв:

```bash
runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d neexitlag -c "SELECT s.code_id,s.machine_hash,s.device_id,s.disabled,d.revoked FROM activation_slots s JOIN devices d ON d.id=s.device_id ORDER BY s.code_id,s.machine_hash;"
```

ОБЫЧНАЯ ПЕРЕУСТАНОВКА ТОГО ЖЕ ПК: ничего не освобождать вручную.
Для навсегда выведенного/заменённого ПК — отдельная изменяющая команда:

```bash
/opt/neexitlag/maintenance/veliq-codes disable --id CODE_ID --machine MACHINE_HASH --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token
```

Она освобождает место для ДРУГОГО hardware hash и отзывает действующий device,
но этот hash останется MACHINE_DISABLED для данного кода, включая после переустановки.
В текущем CLI нет enable/reset slot. Не применять disable «на всякий случай» и
не DELETE/UPDATE таблицы вручную. Случайно отключённый ПК потребует другого кода
или отдельной будущей admin-функции; freeze сам блокировку не отменяет.
Повторить machines, проверить disabled=true. Отзыв всей лицензии (изменяет БД,
все её машины теряют разрешение, не использовать вместо освобождения одного места):

```bash
/opt/neexitlag/maintenance/veliq-codes revoke --id CODE_ID --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token
```

```bash
exit
```

## Подтверждено и границы

Пользователь подтвердил deployment/renewal на VPS, но создание/использование новых
кодов на production пока не проверено. SSH/deployment/enroll на VPS не выполнялись.
Действующий код уже реализует этот путь; runtime изменений для инструкции не нужно.
Тесты/результаты текущей сверки фиксируются в CURRENT.md. Нельзя переносить результаты
fixture на Internet/WinDivert/freeze конкретного ПК без проверки владельцем.

Проверки 21.10.2026: targeted Go race с отдельной PostgreSQL17 — PASS для
core/enrollment, services/control-plane, services/client-service; tools/codes
собран go test (тестовых файлов нет). В том числе 50 freeze replacements/один
слот/отзыв старых keys, HTTPS enroll/lost response, disable/лимит/publication
rollback. HardwareHash stability test — PASS. Обе SQL SELECT выполнены на
временных fixture tables в отдельной PG17; 23 PowerShell блока распарсены,
параметры install.ps1 сверены с реальным ParamBlock; install НЕ запускался.
Собственный PG container остановлен/удалён. Clean-PC GUI/code activation и freeze
на production ещё не проверены владельцем; runtime не менялся.

## Исправление ActivationOnly: плата без серийного номера и оставшийся PAC

`HARDWARE_ID_UNAVAILABLE` не означает недоступный control-plane. Прежний код
требовал одновременно UUID, надёжный board serial и MAC. `Default string` не
содержит уникальности. Теперь допустимы UUID+MAC или board serial+MAC; один MAC
недостаточен. При наличии всех надёжных компонентов прежний v2 hash сохранён;
для неполного набора применяется v3. При выборе физического адаптера сохраняется
прежний доступный physical default route; VPN-only default route больше не
скрывает включённый Ethernet. Отключённый Wi-Fi не участвует. Смена реальной
сетевой карты/UUID может потребовать освобождения слота, неизменность при любом
изменении оборудования не обещается. UUID/MAC не являются криптографическим
доказательством владения ПК; авторизация по коду и mTLS остаётся обязательной.

`activation.status.hardware` сообщает только ACCEPTED/PLACEHOLDER/MISSING/INVALID,
схему и имя недоступного компонента, без UUID, MAC, board serial и machine hash.
GUI показывает HARDWARE_ID_UNAVAILABLE с пояснением, а не «нет соединения».

До успешного enroll и authenticated connect запрещены Backend.Start/WinDivert,
Optimize, восстановление listener/PAC и browser mutation IPC. В `status` появились
`capture_active`, `capture_permitted`, `capture_blocked_reason`. Сам конструктор
backend драйвер не открывает. Режим ActivationOnly не меняет сеть.

`install.ps1 -ActivationOnly` и `install-desktop.ps1` сами proxy не записывают.
В прежней версии Automatic стартовал capture до активации, затем GUI вызывал
browser IPC. Служба писала **ProxySettings** (JSON PAC) в
`HKU\<OwnerSID>\Software\Policies\Google\Chrome` и
`HKU\<OwnerSID>\Software\Policies\Microsoft\Edge`. Поэтому пустые ProxyMode/
ProxyPacUrl и WinINET ProxyEnable=0 не доказывали отсутствие PAC.

Обновлённая credential-less служба чистит только свой оставшийся ProxySettings
по защищённому journal `browser-transport.json`/`edge-transport.json`. При штатном
Stop-Service/shutdown и uninstall такой owned PAC удаляется; при crash/kill
остаётся fail-closed guard. На уже активированном boot ожидание CP guard не
снимает. Чужой PAC, HKLM policy, split-ключи, WinINET/WinHTTP и настройки Happ
не удаляются. Недоступный owner hive/повреждённый journal даёт ошибку очистки,
а не разрешение удалять чужие настройки. Uninstall проверяет SCM path и вызывает
установленный `-cleanup-browser-policy` до удаления службы; ошибку не игнорирует.

### Обновить существующую установку без enroll/переустановки

Только ПК владельца, корень существующего клона. В трее закрыть **только GUI
VELIQ**, Chrome/Edge не закрывать. Сначала обычный PowerShell владельца (при UAC
off — текущий full-admin с тем же SID):

```powershell
git pull --ff-only origin main
```
```powershell
& .\tools\windows\build-e2e.ps1
```
```powershell
& .\tools\windows\build-desktop.ps1
```

Затем PowerShell **администратор под тем же SID** (UAC-off: то же окно):

```powershell
& .\tools\windows\update-service.ps1
```

Этот путь сохраняет service.json, owner SID, trust, identity, код, ACL и профили;
не добавлять -NativeTcpFirewall. Проверка реально установленного файла:

```powershell
Get-FileHash .\bin\windows-e2e\veliq-service.exe,"$env:ProgramData\VELIQ\veliq-service.exe" -Algorithm SHA256
```

Оба SHA256 должны совпасть; служба должна быть Running. Обычный owner PowerShell
(при UAC-off то же окно):

```powershell
& .\tools\windows\install-desktop.ps1
```
```powershell
Start-Process .\bin\release\VELIQ.exe
```

Ввести **тот же** клубный код, если сохранённый pending code не активируется
автоматически. Не создавать новый код, не переустанавливать CA/сертификаты.
Read-only проверки из корня клона:

```powershell
. .\tools\windows\common.ps1
```
```powershell
Invoke-ServiceIPC 'activation.status' | ConvertTo-Json -Depth 5
```
```powershell
Invoke-ServiceIPC 'status' | Select-Object connected,optimizing,capture_active,capture_permitted,capture_blocked_reason
```

До активации ожидаются capture_active=False, capture_permitted=False,
ACTIVATION_REQUIRED; после успешной активации capture разрешён, а наличие
реального capture зависит от Optimize. activation.status.policy_cleanup отражает
результат owned cleanup. Для проверки наличия политики без вывода PAC/токенов:

```powershell
'Google\Chrome','Microsoft\Edge' | ForEach-Object { [pscustomobject]@{Browser=$_;ProxySettingsPresent=($null -ne [Microsoft.Win32.Registry]::GetValue("HKEY_CURRENT_USER\Software\Policies\$_",'ProxySettings',$null))} }
```

После штатного Stop-Service own policy отсутствует; чужая остаётся. После Start
активированная установка вправе снова применить owned guard. Новые соединения
работающего браузера перечитывают policy по его механизму, существующие TCP
остаются pinned. Реальное время подхвата этого исправления на ПК ещё не измерено.

## Временный тестовый код `test` (удалить поддержку до публичного релиза)

**Не обычный клубный код.** Это заведомо известное слово, а не секрет. Любой,
знающий адрес сервера и это слово, может попытаться занять два места. Ограничения
по IP/хешу кода, CSR и mTLS сохранены, но они не предотвращают использование
известного кода посторонним. Создавать только на время контролируемого теста,
не распространять и отозвать сразу после него. При удалении тестового feature
не удалять security/revocation историю.

Команды ниже выполняет только владелец. На production ничего не выполнялось.
**Текущие старые бинарники не понимают `test`.** Нужны новые control-plane,
`veliq-codes` и клиент этой ветки. Обновление сервера — отдельное действие
владельца; выполнение create-test само сервер не обновляет.

Сначала read-only из корня чистого клона на доверенном ПК:

```powershell
& .\tools\windows\verify-activation-vps.ps1
```

После проверки отчёта владелец при необходимости выполняет существующий
безопасный deployment (запись на VPS, отдельное явное подтверждение; CA не
ротируется, identities/security records сохраняются):

```powershell
& .\tools\windows\update-activation-vps.ps1 -ExpectedCommit ((git rev-parse HEAD).Trim()) -ConfirmDeployment ACTIVATE-CODES-2.56.177.4
```

Требуется чистый checkout точного проверенного коммита main, а не другая
локальная сборка. Добавочная миграция **schema 2→3** расширяет kind, добавляет
ограничение test=2 места и срок не более 14 суток. Club/personal, слоты, salt,
nonce/revocations не изменяются. Схема 3 остаётся совместимой с чтением и обычными
операциями прежних бинарников; короткий code прежние бинарники отвергают.
Новый verify принимает schema 2 и 3 отдельными явными verdict, не выдаёт их за
чистый schema1 baseline. Откат сохраняет добавочные таблицы и security history.

Далее обычный PowerShell владельца (любой каталог):

```powershell
ssh root@2.56.177.4
```

В shell VPS root — **создание**, запись в БД. Ровно два места и 14 суток
задаёт сервер, переопределить их флагами нельзя. Только точное значение `test`
разрешено этой временной командой, произвольных коротких кодов нет:

```bash
/opt/neexitlag/maintenance/veliq-codes create-test --value test --name Owner-PC-test --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token
```

JSON результата содержит id, kind=test, limit=2, name с префиксом [TEST], expires_at.
Секрет admin token не передаётся в argv и остаётся на VPS. Сохраняется только
SHA256(`test`), plaintext столбца нет. Обычные create по-прежнему случайные VQ-коды.
В стандартном list видна отметка test/[TEST]:

```bash
/opt/neexitlag/maintenance/veliq-codes list --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token
```

На чистом ПК пройти **раздел 2 этого документа**, уже с обновлённой сборкой:
build-e2e → build-desktop → закреплённый WinDivert → проверенные public CA →
install -ActivationOnly → install-desktop. Ни старые device keys, ни SSH/admin
token на клиент не нужны. Запустить GUI:

```powershell
Start-Process .\bin\release\VELIQ.exe
```

При уже установленной ActivationOnly службе вместо ввода в GUI допустим тот же
owner IPC (обычный PowerShell в корне клона; UAC-off — то же owner full-admin):

```powershell
. .\tools\windows\common.ps1
```
```powershell
Invoke-ServiceIPC 'activation.set' @{code='test'} | Select-Object state,error,has_identity
```

Это запускает асинхронный enroll, ответ ACTIVATING ещё не PASS; затем проверить
activation.status командой из предыдущего раздела. Для обычного пользователя
использовать GUI.

В поле активации ввести `test` и нажать «Активировать». Ожидается ACTIVATED,
HasIdentity=True, connected=True. При HARDWARE_ID_UNAVAILABLE смотреть безопасные
component states, как в предыдущем разделе. До этого capture/PAC запрещены.
Срок 14 суток означает срок **нового enroll**, как у обычных кодов; это не
автоматический kill уже выданных сессий. Для завершения теста обязателен отзыв.
Freeze-переустановка на том же неизменном hardware занимает тот же слот и отзывает
прежнюю identity; второй ПК может занять второе место, третий получает LIMIT.

Одна команда **отзыва всех тестовых кодов и связанных устройств**, VPS root:

```bash
/opt/neexitlag/maintenance/veliq-codes revoke-tests --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token
```

Транзакция отзывает только kind=test, публикует полный подписанный revoke config;
club/personal остаются рабочими. Повторный запуск безопасен. Строки и слоты не
удаляются: list покажет revoked=true. Повторное создание того же значения после
отзыва/истечения **отвергается TEST_CODE_ALREADY_EXISTS**: известный старый код
никогда не оживляется. Не обходить это удалением строк из БД. Уже открытые relay
сессии завершаются по действующей политике применения отзыва; мгновенный обрыв
всех существующих потоков эта команда не обещает.

### Что убрать перед релизом

1. Сначала выполнить revoke-tests, read-only проверить revoked test codes/devices
   и доставку signed revocations; не удалять devices/nonces/slots для «очистки».
2. Удалить `core/enrollment/test_code.go` и ветку вызова из CodeHash, а также
   тесты временного исключения; обычные VQ-коды оставить.
3. Удалить административные `/codes/test`, `/codes/revoke-tests` handlers,
   `codes_temporary*.go`, CLI create-test/revoke-tests и test_operation*.go,
   когда отзыв всех тестовых кодов подтверждён. Удалить эти инструкции из release.
4. **Сохранить миграцию 003 и schema3 compatibility/history** для обновления уже
   установленной БД. Не делать destructive downgrade и не восстанавливать pg_dump
   поверх новых revocation/nonces. Удаление поддержки test не требует удаления
   таблиц и не отзывает обычные коды.

Локальные тесты не подтверждают активацию на production/реальном Windows. Этот
сценарий до выполнения владельцем остаётся непроверенным на его ПК/VPS.

## Исправление PAC lifecycle после успешной активации (21.10.2026)

Активация и готовность сети — разные состояния. `ACTIVATED/has_identity=True`
означают выданную identity, а не работающий WinDivert или маршрут браузера.
`ActivationOnly` — способ установки без прежних credentials; после активации
захват должен запускаться обычным Optimize/Automatic, постоянного запрета драйвера
в этом режиме нет. install.ps1 копирует и проверяет WinDivert и при ActivationOnly.

Найдены три дефекта кода:

- Snapshot.connected раньше означал только Backend.Ready; GUI при успешном IPC
  безусловно писал «Подключено». Теперь connected требует capture и живую
  authenticated relay session; `relay_connected` отдельно показывает транспорт.
  Quality warming_up не заменяет transport readiness и не запрещает MANUAL.
- Optimize требовал PAC до запуска capture. При этом PAC можно было записать
  по одному listening=True, не проверяя backend/relay. Startup-зависимость
  разорвана: сначала backend, затем проверка готовности и только затем owned PAC.
  Ошибка первого автоматического запуска раньше игнорировалась без повторов;
  теперь startup повторяет попытку, а явное Optimize off отменяет pending retry.
- Silent timer восстанавливал policy при Automatic off/потере готовности.
  Теперь disable/mode change/потеря готовности снимают только owned policy,
  сохраняя нужный профиль для автоматического восстановления.

Если новый WinDivert всё ещё не стартует, точный Windows-отказ до проверки на ПК
неизвестен: смотреть backend.error и connection_reason=CAPTURE_START_FAILED.
Нельзя считать, что исправление startup само доказало отсутствие driver/pin/ACL
проблем именно на ПК владельца.

### Новый явно разрешённый владельцем контракт доступности

По требованию владельца **каждый результат рабочего PAC оканчивается DIRECT**.
Для защищённого хоста: primary; DIRECT. Для обычного: primary; recovery; DIRECT.
Это разрешает прямой выход ранее защищённых сайтов при отказе proxy infrastructure
или снятии policy. Прежнюю гарантию «никогда DIRECT даже при crash» больше
заявлять нельзя. Пока рабочий proxy обрабатывает запрос, правила RELAY_REQUIRED
и отсутствие DIRECT retry после его upstream-отказа остаются прежними.
PAC fallback браузера действует при отказе соединения с прокси; ответ CONNECT
502/403 сам по себе не гарантирует переключение Chrome на следующий proxy.
Поэтому DIRECT в PAC дополняет readiness/cleanup, а не заменяет их.

ProxyPacMandatory=true оставлен: он требует корректного выполнения inline PAC,
но не запрещает DIRECT, который этот PAC явно возвращает. Это проверяется
исполнением PAC в Node и native registry contract. TLS/mTLS/signature verification
и настройки Windows/других приложений не ослаблялись.

Перед записью policy одновременно нужны: activation ready, Optimize+Automatic,
Backend.Ready, authenticated relay session и успешные CONNECT+TLS+HTTP проверки
обоих loopback proxy. Проверяется /healthz CP с полной проверкой сертификата и
HTTP 200/status=ok. Одного listen/TCP ACK/CONNECT 200 недостаточно. Служебная
случайная capability допускает только фиксированный CP health target, не
произвольный proxy target и не browser owner bypass. Capability не попадает в
status/логи и не является device/admin credential. Самопроверка не записывается
как реальный запрос браузера и не доказывает загрузку Internet-сайта.

Проверка живого relay не ждёт quality.health=healthy. Самопроверки endpoints
ограничены общим бюджетом 4 с на lane, успешный результат кэшируется на 10 с
для ограничения TLS/CPU нагрузки. Состояние capture/relay/enabled проверяется
при каждой записи и каждом тике. В packet path нет HTTP/реестра/Backend.Status:
только atomics и срок допуска 15 с. При зависшем checker этот допуск истекает,
новые browser flows получают owner-authorized DIRECT. Games и desktop profiles
не входят в эту ветку. Уже установленные TCP не мигрируют на новый egress.

### Независимый сторож и freeze

Установка/update регистрируют задачу **VELIQ-BrowserPolicyWatchdog** от SYSTEM,
с triggers AtStartup и AtLogOn. Это отдельный процесс установленного service EXE
с -browser-policy-watchdog, без backend, enroll, SSH или Internet запросов.
Он читает только локальный authenticated IPC и journal-owned registry values.
Missing IPC, not ready, stale probe timestamps: удалить только соответствующий
owned PAC. Чужие policy/task сохраняются. Штатный Stop/shutdown/uninstall очищают
policy синхронно; Automatic off/Optimize off — в соответствующем IPC transaction.
Таймер службы и независимый процесс проверяют состояние каждую секунду.

Если IPC трижды подряд недоступен у уже наблюдавшейся службы, watchdog проверяет
SCM binary/config path и запрашивает custom control 128. Только этот control
заканчивается failure exit, который включает существующие SCM recovery actions;
обычный Stop/Shutdown возвращает success и не запрашивает restart. Это позволяет
освободить зависшие WinDivert handles, а не только удалить PAC. Для ещё ни разу
не ответившего нового PID предусмотрена startup grace 30 с; повторные запросы
recovery ограничены минутой. Браузеры не завершаются и не перезапускаются.
При update останавливается только owned SYSTEM watchdog, не Chrome/Edge;
после замены бинарника задача восстанавливается. При uninstall она удаляется.

**Нулевая задержка при полном зависании службы не доказана и не гарантируется.**
Очистка по polling имеет задержку до следующего тика/тайм-аута IPC; принудительный
SCM recovery включает до 10 с остановки и существующую 5-секундную задержку restart.
Самопроверка зависшего proxy также имеет bounded timeout. Новый PAC имеет DIRECT
fallback, но старый freeze-образ может восстановить старый PAC без него ещё до
запуска любого VELIQ-кода. Для клуба нужно один раз обновить базовый образ вместе
со службой и scheduled task. Обещать отсутствие даже секунды отказа до запуска
SCM/task на старом образе технически неверно; отдельный kernel guard остаётся
будущей архитектурой. Ежедневных действий конечного пользователя не требуется.

### Команды обновления и read-only проверок на тестовом ПК

Корень существующего клона, PowerShell **администратор под тем же SID владельца**.
В известном UAC-off режиме это текущее окно. Закрыть через трей только старый
GUI VELIQ, чтобы заменить его файлы/recovery helper; Chrome и Edge не закрывать.
Это операция владельца обновления, не ежедневный пользовательский сценарий.

```powershell
git pull --ff-only origin main
```
```powershell
& .\tools\windows\build-e2e.ps1
```
```powershell
& .\tools\windows\build-desktop.ps1
```
```powershell
& .\tools\windows\update-service.ps1
```
```powershell
& .\tools\windows\install-desktop.ps1
```
```powershell
Get-FileHash .\bin\windows-e2e\veliq-service.exe,"$env:ProgramData\VELIQ\veliq-service.exe" -Algorithm SHA256
```

Оба SHA256 должны совпасть. Далее read-only:

```powershell
Get-Service VELIQ
```
```powershell
Get-ScheduledTask -TaskName VELIQ-BrowserPolicyWatchdog | Select-Object TaskName,State
```
```powershell
Get-ScheduledTaskInfo -TaskName VELIQ-BrowserPolicyWatchdog | Select-Object LastRunTime,LastTaskResult
```

Для непрерывно работающей задачи LastTaskResult может быть 267009 (0x41301,
currently running), это не код отказа. Проверить recovery configuration:

```powershell
sc.exe qfailureflag VELIQ
```
```powershell
sc.exe qfailure VELIQ
```
```powershell
. .\tools\windows\common.ps1
```
```powershell
Invoke-ServiceIPC 'activation.status' | Select-Object state,error,has_identity,capture_permitted
```
```powershell
Invoke-ServiceIPC 'status' | Select-Object service_pid,connected,relay_connected,optimizing,capture_active,capture_permitted,connection_reason
```
```powershell
(Invoke-ServiceIPC 'status').backend | ConvertTo-Json -Depth 4
```
```powershell
(Invoke-ServiceIPC 'status').browser_policy | ConvertTo-Json -Depth 4
```
```powershell
Invoke-ServiceIPC 'browser.status' | Select-Object listening,policy_ready,last_error,silent_activation
```
```powershell
Invoke-ServiceIPC 'edge.status' | Select-Object listening,policy_ready,last_error,silent_activation
```

Проверить только наличие ProxySettings, не выводя PAC/внутренние capabilities:

```powershell
'Google\Chrome','Microsoft\Edge' | ForEach-Object { [pscustomobject]@{Browser=$_;ProxySettingsPresent=($null -ne [Microsoft.Win32.Registry]::GetValue("HKEY_CURRENT_USER\Software\Policies\$_",'ProxySettings',$null))} }
```

Запустить новый GUI из установленного ярлыка (на UAC-on обычным пользователем;
на UAC-off владелец остаётся full-admin). Без browser restart/диалогов.
В тестовом текущем UAC-off окне допустимо:

```powershell
Start-Process "$env:LOCALAPPDATA\Programs\VELIQ\VELIQ.exe"
```

При готовности: connected/optimizing/backend.ready=True; после настройки обоих
recovery helpers browser_policy.{chrome,edge}_ready=True, свежие checked_at и
policy_ready=True. При not ready: policy_ready=False, owned ProxySettings отсутствует,
GUI не пишет «Подключено» при connected=False. Desktop relay и игровые DIRECT
проверять отдельно. Для контрольного выключения оптимизации через owner GUI
достаточно одной кнопки; policy снимается, список приложений сохраняется.
Ни перевыпуск identity/CA, ни новый код test, ни VPS deployment не нужны.

Пока не подтверждено на реальном Windows: фактическая registration/recovery SCM
под Langame, подхват обновлённого PAC открытыми Chrome/Edge, Internet страницы,
полный freeze boot и время восстановления при suspend/kill. Локальные тесты не
являются этими доказательствами. Не вводить активационный код заново без причины.

### Порядок завершения (A1)

Крестик VELIQ выключает маршрутизацию до скрытия в трей/закрытия; «Выход» делает то же. Браузеры не закрываются. Штатный Stop, режим DIRECT и отзыв снимают только journal-owned PAC до остановки транспорта. При crash это делает независимый SYSTEM watchdog (опрос 1 с плюс RPC до 1 с); мгновенная очистка в уже погибшем процессе невозможна. При обесточивании код не выполняется: после boot служба сначала чистит сохранённый owned PAC, затем проверяет готовность и только после неё возвращает policy. Старый freeze-образ должен быть обновлён один раз; до запуска службы/task Windows может восстановить старую policy. Чужие политики не удаляются.

### Временные тестовые коды

Перед релизом выполнить `docs/TEST_CODE_RETIREMENT.md`. Важно: **revoke-tests
отзывает и все устройства, привязанные к тестовым кодам**. Пока ваш ПК активирован
таким кодом, это не команда проверки. Она не запускалась. Schema 003 и история
security state сохраняются после удаления временного runtime.

## Автоматические браузеры после clean activation

С новой native реализацией Chrome/Edge автоматически получают AUTO; не нужны
ручные profile.set/browser.silent.apply, PAC-кнопки или Reload policies.
Подготовка и границы доказательства: [BROWSER_AUTOMATIC_START.md](BROWSER_AUTOMATIC_START.md).
Точные owner update/fresh/freeze и short acceptance команды:
[BROWSER_AUTOMATIC_ACCEPTANCE.md](BROWSER_AUTOMATIC_ACCEPTANCE.md).
install/update теперь по умолчанию проверяют app-scoped TCP reflection rule;
это не включение capture до активации и не глобальное firewall правило.
