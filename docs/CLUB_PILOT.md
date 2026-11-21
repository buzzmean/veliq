# Пилот VELIQ: один образ, отдельная identity каждого ПК

Статус: подготовлено для пилота; **настоящий Inno Setup/установка/сетевая загрузка
ещё не проверены**. Сначала 2–3 ПК, затем остальные. Production VPS, CA и сертификаты
эти команды не меняют. Установщик публичный; клубный код в него не вшивается.
На гостевых ПК не нужны Git, Go, Python, .NET SDK, SSH или ручная активация.

## Обязательные условия общего образа

1. Провайдер загрузки должен давать **каждому ПК отдельный writable overlay** для
   ProgramData, профиля пользователя, реестра и временных файлов. Общая read-only
   база допустима. Одновременно общий writable ProgramData/профиль — **недопустимо**:
   ключи и состояния могут перезаписываться. VELIQ не управляет Langame/iSCSI и не
   может достоверно определить тип overlay по наличию сетевого диска.
2. В образе нет device identity, сертификата устройства, probe token, pending key
   или boot-ready marker. Проверка запечатывания откажется, сохранив эти файлы.
   Нельзя клонировать уже активированный тестовый ПК.
3. У каждого ПК уникальны аппаратный UUID и стабильный физический проводной MAC.
   Заглушка серийного номера платы допустима при валидных UUID+MAC. SID/MachineGuid
   в hash не входят. Замена платы/адаптера может потребовать освобождения места.
4. В этом пилоте GUI запускается под тем же SID/профилем Windows, под которым
   установлено приложение. Один SID на разных ПК допустим: named pipe только
   локальный, remote clients запрещены; ключ устройства у каждого ПК свой.
   Произвольные другие гостевые SID и roaming/shared writable профили не покрыты.
5. **Гость с полными правами администратора не может быть ограничен VELIQ.**
   Нужен стандартный гостевой аккаунт. Можно установить/запечатать под будущим
   гостевым SID в техническом режиме, затем средствами Windows убрать его из
   Administrators, сохранив отдельного администратора владельца. Это решение
   владельца образа, скрипты не меняют Windows-аккаунты. Пароля администратора
   VELIQ сейчас нет; используется граница прав Windows.
6. Существующий CA действителен, CP/relay доступны, клубный код действителен и
   имеет 40 мест. Freeze не обходит срок кода/отзыв. Запуск образа после его
   запечатывания считается настоящей загрузкой и активирует его — не сохранять
   такое runtime-состояние обратно в базу.

Частный iSCSI TCP/3260 исключён из native network queue и маршрутизации, включая
192.168.88.252:3260. При сборке Setup выполняется официальный read-only
WinDivertHelperEvalFilter, который проверяет это исключение на пакетах; драйвер
не открывается. Это не доказательство стабильности реальной дисковой сети.

## 1. Сборка на тестовом ПК владельца

PowerShell администратора **из корня клона**, например `$HOME\neexitlag`.
Нужны Git, Go, .NET SDK8, публичный `.e2e\activation-trust\ca.pem`, сеть для
пакетов. Один build-command добавит отсутствующий nuget.org, найдёт или установит
через winget закреплённый Inno Setup 6.4.3, проверит версию/подпись компилятора,
соберёт службу/GUI и проверит закреплённый WinDivert. Без winget установка Inno
автоматически невозможна: установить утверждённый 6.4.3 отдельно или передать
`-Compiler '<путь ISCC.exe>'`. Сборка не устанавливает VELIQ и не ходит по SSH.

```powershell
git pull --ff-only origin main
```

```powershell
& .\tools\windows\build-setup.ps1
```

Выход: `bin\installer\VELIQ-Setup.exe`, `bin\installer\SHA256SUMS`, строка
`SETUP_BUILD_PASS commit=... sha256=...`. При желании закрепить полный HEAD
параметром `-ExpectedCommit <40 hex>`. Dirty tracked checkout не упаковывается.
В пакете только публичный CA, адрес CP `https://2.56.177.4:8443`, echo
`2.56.177.4:40000`, хеши и бинарники. Проверка CA включает DER SHA256, сроки и
CA constraints; приватные ключи и коды не копируются. На гостях код сохраняется
только SYSTEM/Administrators, не доступен стандартному пользователю.

Setup пока **не подписан**: возможен SmartScreen/UAC при установке владельцем.
Драйвер остаётся оригинальным подписанным WinDivert, версия не меняется.
Подпись публичного production-установщика — отдельное действие владельца.

Дополнительная проверка без установки, SSH и активации:

```powershell
& .\tools\windows\test-club-local.ps1
```

Проверка native Go по умолчанию без `-race` (не требует GCC на чистом Windows).
При уже настроенном race toolchain можно передать `-Race`. Официальный DLL
filter evaluator обязателен в build-setup; без его пути обычные Go-тесты этот
Windows-сценарий пропускают. PostgreSQL интеграция здесь проверялась отдельно
в одноразовом контейнере, локальная команда не устанавливает PostgreSQL.

## 2. Подготовка чистого образа в техническом режиме

Перенести публичный Setup и проверить SHA256 по файлу сборки (это не секрет).
В техническом режиме один раз открыть PowerShell администратора под **будущим
SID владельца установки**. На чистом образе не должно быть старого VELIQ identity.
Chrome/Edge должны быть установлены до запечатывания: обнаруживаются стандартные
пути и App Paths HKLM32/HKLM64/HKCU. PUBG должен быть установлен в Steam Library;
его имеющийся discovery включает локальный UDP-обход автоматически. Не включать
несовместимые драйверные античиты без отдельной проверки.

Для ввода кода использовать helper из клона владельца (можно заранее создать
private file на административном носителе/закрытой папке). Код вводится скрыто,
не аргументом и не в чат; это единственный ввод **владельцем**, не гостями.
Папка назначения уже должна существовать; файл не должен существовать:

```powershell
& .\tools\windows\New-ClubCodeFile.ps1 -Path "$HOME\veliq-club-code.txt"
```

Запускать Setup с этим файлом, например из корня клона (путь заменить, если
Setup перенесён в другую папку). Команда ждёт завершения и проверяет exit code:

```powershell
$p = Start-Process -FilePath '.\bin\installer\VELIQ-Setup.exe' -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CLUBIMAGE=1',('/CLUBCODEFILE="'+$HOME+'\veliq-club-code.txt"')) -Wait -PassThru; if($p.ExitCode -ne 0){throw ('SETUP_FAILED exit='+$p.ExitCode)}
```

Установщик ставит службу Automatic, GUI, WinDivert, публичный CA; сохраняет
защищённый staged code, регистрирует SYSTEM task `VELIQ Club Boot` и HKCU
автозапуск GUI в трее, затем останавливает службу. Enrollment при подготовке
образа не выполняется. Старые/чужие задачи не перезаписываются. Публичное дерево Setup и зависимости
SYSTEM-задачи получают owner Administrators и admin-only write ACL; будущий
стандартный гость не сохраняет права владельца на boot-скрипты.

```powershell
Get-Service neexitlag | Select-Object Status,StartType
```

Ожидается Stopped/Automatic. Проверить отсутствие runtime-state, не печатая его:

```powershell
@('identity.json','device.pem','probe.token','club-boot-ready.json') | ForEach-Object { [pscustomobject]@{Name=$_;Exists=(Test-Path (Join-Path "$env:ProgramData\neexitlag" $_))} }
```

Все Exists=False. Наличие любой identity — STOP, не копировать этот образ.
Результат установки: `%ProgramFiles%\VELIQ Setup\install-result.json`, PASS;
не считать одну надпись Setup доказательством работы браузера.
Исходный private code file убрать из общедоступных папок/профиля до публикации
образа; защищённая копия в ProgramData нужна, удалять её не надо. Не публиковать
сам образ/его staged code вне клуба. Надёжная копия code/id — в менеджере паролей
владельца вне freeze-ПК. Копирование файла не позволяет гарантировать его
физическое стирание с SSD; ограничить доступ к исходной папке.

**Сейчас сохранить технический образ средствами системы загрузки.** Не стартовать
службу/не запускать GUI/не перезагружать эталон перед сохранением. Автоматического
API Langame в репозитории нет: режим записи/commit образа выполняет владелец
в панели своего загрузчика. После сохранения эталон считается sealed.

## 3. Пилот 2–3 ПК после загрузки

Загрузить 2–3 разных физических ПК из sealed image, обычный режим с отдельными
overlay. SYSTEM-задача создаёт private boot marker, запускает службу. Каждый ПК
создаёт случайный Ed25519 key, проходит pinned-CA enrollment клубным кодом по
своему hardware hash, получает отдельный сертификат/identity. Общих device keys
в образе нет. При повторной freeze-загрузке ключ новый, но слот того же железа
переиспользуется; прежняя identity отзывается транзакционно. История revoked
devices растёт — это не новые занятые места. Не удалять security history вручную.

GUI стартует скрыто в трее; обычный гость видит только состояние, не режимы,
код активации, технические страницы, отключение оптимизации или выход. Внешний
IPC тоже запрещает изменения в club mode. Automatic включён, Chrome/Edge AUTO
native; обычные игры остаются DIRECT. PUBG — существующая ограниченная ladder,
никаких новых настроек VPS/античита/файлов игры. Перезапуск браузеров не выполняется.
Существующие TCP закреплены до закрытия. Строгую гарантию скрытого ECH+DoH inner
при owner-выбранном unknown DIRECT не обещаем: см. BROWSER_OPAQUE_ROUTING.md.

Одна локальная read-only команда (обычный пользователь; исходники не нужны):

```powershell
& "$env:ProgramFiles\VELIQ Setup\tools\windows\Get-ClubStatus.ps1"
```

Один структурированный журнал текущей загрузки:
`%ProgramData%\neexitlag\club-status.json` (обновляется каждые10с).
`club-boot.json` содержит состояние SYSTEM boot task, если служба не поднялась.
`BASELINE_PASS_RUNTIME_UNVERIFIED` означает activation+capture+backend и настоящий
nonce/HMAC TCP+UDP roundtrip через authenticated relay. Начальная проверка
рассредоточена на0–29с, успешные повторы5мин, неудачные30–59с. PENDING не есть PASS.
Браузеры: `ARMED_NOT_OBSERVED` ещё не загрузка сайта, `BIDIRECTIONAL_NOT_PAGE_PROOF`
лишь реальный обмен. Игры без трафика/неустановленная PUBG не считаются матч-PASS.

На каждом пилотном ПК без закрытия уже работающих Chrome/Edge открыть новые
вкладки VK, YouTube, claude.ai, Telegram Web. Проверить normal DIRECT/known relay
в диагностике и реальную загрузку. Если PUBG установлена — короткий настоящий
матч; это не заменяется статусом "READY_NEW_FLOWS". Проверить iSCSI/network boot,
звук/игры и отсутствие стороннего winws/zapret конфликта.

Перезагрузить эти же2–3ПК в freeze и повторить локальную сводку. На сервере
владелец отдельно проверяет: осталось ровно2–3занятых места, текущие device IDs
разные, старые revoked, нет identity из эталона. Read-only команды ниже.
Только после этого назначать image оставшимся ПК в панели загрузчика.

Сбор с нескольких ПК возможен **только при уже существующем admin-share доступе**
администратора. Никакой SMB/WinRM/firewall/пароли скрипт не настраивает:

```powershell
& .\tools\windows\Get-ClubStatus.ps1 -ComputerName PC01,PC02,PC03
```

Читает `\\PC\C$\ProgramData\neexitlag\club-status.json`; старше60с — STALE,
без доступа — UNAVAILABLE. Файл — снимок, не remote attestation; stopped service
может иметь свежий файл до60с. Для живого подтверждения использовать локальную
команду. Без существующих административных прав доступна только локальная сводка.

## 4. Отзыв и новый код

Эти серверные команды **выполняет только владелец**, здесь они не запускались.
Подключение с административного ПК (пароль/ключ не логировать):

```powershell
ssh root@2.56.177.4
```

Read-only список (код не возвращается):

```bash
/opt/neexitlag/maintenance/veliq-codes list --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token
```

Read-only занятые места/текущие devices без hardware значений:

```bash
runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d neexitlag -c "SELECT c.id,c.kind,c.seat_limit,c.revoked,count(s.device_id) FILTER (WHERE NOT s.disabled) AS occupied FROM activation_codes c LEFT JOIN activation_slots s ON s.code_id=c.id GROUP BY c.id ORDER BY c.id; SELECT s.code_id,s.device_id,s.disabled,d.revoked FROM activation_slots s JOIN devices d ON d.id=s.device_id ORDER BY s.code_id,s.device_id;"
```

Создать replacement code (запись; выполнить один раз; сохранить показанный секрет
в менеджере паролей, не присылать в чат):

```bash
/opt/neexitlag/maintenance/veliq-codes create --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token --kind club --limit 40 --name Club-pilot-next --days 90
```

Выход из SSH:

```bash
exit
```

Создать новый private file через New-ClubCodeFile.ps1 с другим именем. Для уже
установленного пилотного ПК (PowerShell админа) без переустановки и browser restart:

```powershell
& "$env:ProgramFiles\VELIQ Setup\tools\windows\Set-ClubActivationCode.ps1" -CodeFile "$HOME\veliq-next-code.txt"
```

Перезапускается **только служба**; identity не удаляется, новая принимается после
валидного enrollment. Проверить Get-ClubStatus. На freeze-клиенте это изменение
overlay не переживёт reboot: заменить также ровно **один private file** в sealed
base — `ProgramData\neexitlag\activation-code.json.pending`.

Для редактирования оригинального sealed base до его загрузки/офлайн, когда он
смонтирован провайдером как папка (а не активированный runtime), helper из клона:

```powershell
& .\tools\windows\Set-ClubActivationCode.ps1 -CodeFile "$HOME\veliq-next-code.txt" -InstallDirectory 'X:\ProgramData\neexitlag' -Image
```

`-Image` не запускает enrollment и требует чистый image. Не использовать его
для runtime-копии с identity/boot marker. Если загрузчик допускает только загрузку
техобраза, который уже успел активироваться, **не запекать его identity**: вернуться
к сохранённому чистому sealed baseline и отредактировать offline либо повторить
чистую установку образа. Автоматическое стирание identity не реализовано намеренно.
Helper image-режима с чужим смонтированным диском не должен останавливать службу
административного ПК; файловая операция локальная, данные на целевом image.

Проверить новый код на пилотных ПК, затем владелец отзывает старый по публичному ID
(запись, все устройства этого кода отзываются; возможен перерыв на ещё старом образе):

```powershell
ssh root@2.56.177.4
```

```bash
/opt/neexitlag/maintenance/veliq-codes revoke --id OLD_CODE_ID --ca /etc/neexitlag/control/ca.pem --admin-token-file /etc/neexitlag/control/admin.token
```

Отзыв действует по текущим CP/config/session правилам, не обещает мгновенного
закрытия всех уже открытых TCP. Не удалять revoked/nonces и не восстанавливать
старую БД ради мест. Снятие слота после замены железа — штатный `veliq-codes disable` из
ACTIVATION_OWNER_RUNBOOK, не ручной DELETE SQL. Это блокирует старый hardware slot;
для возврата той же машины сейчас нужен новый код, отдельной enable-команды нет.

## Проверено и границы

Локальные Go race/PostgreSQL фикстуры подтверждают reuse seat и отзыв старого ключа,
одинаковый SID не входит в hardware hash. PS фикстуры проверяют seal guards,
защиту чужой задачи, code replacement и отказ. C# unit/WPF cross-build проверяют
модель и компиляцию. Native Windows Inno/SCM/ACL/задача/реальная сеть/iSCSI overlay,
физические36ПК, античит и пользовательские сайты требуют пилота владельца.
GitHub Actions блокируется биллингом до шагов; CI PASS не заявляется.


Откат пилота: вернуть сохранённый чистый образ в панели загрузчика. Не подменять
один бинарник старой версией: старые клиенты не знают club_image/club_browser_paths
и могут отвергнуть новый manifest. Для обычного удаления использовать штатный
VELIQ Setup uninstaller под SID владельца; он удаляет только owned boot task,
службу/GUI, сохраняет credentials/state для явного решения администратора.

Нагрузка на VPS1vCPU/2GB для36одновременных браузеров не подтверждена. Клиентский
лимит8googlevideo tunnels не является лимитом всего клуба. Начать с2–3ПК,
проверить число сессий/очереди/CPU, затем увеличивать группу. Существующие relay
session/flow limits остаются bounded; установщик их не повышает. Владелец может
в своей SSH-сессии выполнить только чтение, не присылая приватные журналы:

```bash
top -b -n 1
```

```bash
ss -s
```

```bash
journalctl -u neexitlag-relay --since '-10 minutes' -n 100 --no-pager
```
