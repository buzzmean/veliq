# Игровой UDP-обход VELIQ

Реализация в `main`; это не подтверждение загрузки PUBG с новым кодом на
реальном Windows или совместимости с античитом. Владелец доказал эффективность
подобного первого UDP-полёта другим инструментом на своём провайдере. Здесь свой
генератор и отправитель: код, бинарники и fake-файлы zapret/Flowseal не используются.
VPS, сертификаты, билеты и 30-минутный lease не изменялись.

## Включение и область

Служба сама ищет установленные Steam PUBG, CS2, Dota 2 и Apex по реестру Steam
**владельца установки**, обоим HKLM views, стандартным каталогам и
`libraryfolders.vdf` (до 32 библиотек), манифесту приложения и точному exe.
Содержимое exe и память игры не читаются, процессы не изменяются и не завершаются.
PUBG включён по умолчанию. CS2, Dota 2 и Apex остаются DIRECT до явной кнопки
«Включить UDP-обход» в разделе «Приложения → Игровой UDP-обход».
Для другой игры: добавить обычный профиль по полному пути exe, оставить DIRECT
или AUTO, выделить его и нажать «Игровой UDP: включить». До 8 выбранных игр.
Это отдельная настройка; обычный AUTO игр по-прежнему не наследует глобальный RELAY.
Профили браузеров, Discord, Steam и защищённых приложений здесь не принимаются.
Явные MANUAL/BLOCK и доменные правила не переписываются.

Режим действует только на выбранный **полный путь + PID + время создания**,
IPv4 UDP к публичным адресам с портом назначения ≥1024. TCP, DNS/53, UDP/443,
LAN/loopback/multicast, IPv6 и другие приложения не меняются. Выключенная
оптимизация, ActivationOnly без активации, внешний VPN, неизвестный fingerprint,
неработающий capture/детектор конфликтов приостанавливают игровой механизм.
Для принятого потока маршрут закреплён; работающие потоки не мигрируют и их
пакеты не переигрываются. Смена варианта/ступени касается следующего нового потока.

## Лестница, здоровье и ограничения

**PUBG с исправлением после e5e0127:** для неизвестного публичного endpoint
сразу LOCAL_UDP K12/N2, без начального DIRECT trial. Это применяется при Steam
discovery, ручном enable и восстановлении сохранённого game-udp.json v2.
Другие игры сохраняют DIRECT-first и opt-in. После недостаточного ответа —
следующий local вариант на следующем новом tuple, затем прежний bounded relay
fallback. Первые24приманки не отправляются в VPS, оригиналы идут как DIRECT.

Исключение — ранее подтверждённый sustained DIRECT **этой сети, exe и адреса:порта**.
TTL6часов и реальная cadence остаются обязательными. App-wide/чужой endpoint/
другая сеть/просроченный DIRECT не разрешают прямую пробу к новому серверу.
Географию адреса не угадываем: неизвестный российский endpoint тоже получит
короткую local-приманку; origin по-прежнему видит клиентский IP, не VPS.
Успех после приманки не выдаётся за доказанную работоспособность без неё.
Не добавляем фоновые копии/повторную отправку неизвестных игровых запросов.


Для остальных игр, кроме PUBG, пара (fingerprint сети, точный exe) без измеренного результата:

1. DIRECT, без приманок и релея.
2. При недостаточном устойчивом ответном трафике — следующий **новый** поток
   использует локальную приманку. Начало: K=12 перед каждым из первых N=2
   исходящих оригиналов. Следующие варианты: K6/N3, K10/N3, K14/N3,
   K12/N4, затем другая C0-форма K10/N2.
3. Только после неудачного DIRECT и всех ограниченных локальных вариантов —
   новый поток через существующий authenticated RELAY (VPS-01, либо relay_id
   выбранного профиля). Эта ступень fail-closed: ошибка relay не переправляет
   её пакеты DIRECT. mTLS, свежие билеты, pool/renewal остаются штатными.
4. После неуспешного последнего варианта — bounded cooldown, без бесконечного
   перебора. Время подтверждённого результата — до 6 часов; незавершённого
   подбора — 10 минут, исчерпания — 1 час. После TTL снова DIRECT.

При исчерпании/переполнении таблицы новый поток остаётся обычным DIRECT без
приманок; это отмечается `GAME_UDP_VARIANTS_EXHAUSTED`/`GAME_UDP_FLOW_CAPACITY`
в lifecycle, а не выдаётся за рабочий обход. Это не fallback **уже открытого**
RELAY-потока. Защищённые приложения/домены этим механизмом не обслуживаются.

Оценка не разбирает игровой протокол. Нужно ≥6 входящих ответов в ≥3 разных
секундных интервалах, со span ≥2 с, при продолжающемся исходящем трафике.
Окно cadence — последние 6 с; минимум 6 исходящих пакетов. Одиночный reply или
короткий burst не подтверждают здоровье. Первичная probation — 6 с, дальнейшая
деградация cadence/тишина при исходящем трафике — 5 с, единичный read timeout
ничего не переключает. Idle не считается поломкой. Это **транспортный признак**,
не доказательство загрузки матча или хорошего пинга. Рабочий DIRECT подтверждается отдельно для адреса:порта: здоровый QoS-сервер
не удерживает заблокированный игровой сервер в DIRECT, а подтверждённый здоровый
сервер не наследует ненужный RELAY. Перебор вариантов остаётся scoped к сети/игре;
healthy endpoint churn не вытесняет failure ladder. Кэш сети/игры не влияет на
другие игры/сети. Смена fingerprint останавливает остаток first-flight и обучение
старых потоков, не переносит их пакеты/маршрут. Устаревшее решение classifier
отклоняется; новое подключение начинает обучение в новом сетевом контексте. Параллельные неудачные потоки не прокручивают всю лестницу.

Важно: VELIQ не заставляет игру создавать новый UDP tuple и не переигрывает
её запросы. Если игра продолжает один неработающий tuple, новый вариант появится
только при её следующем новом подключении/попытке матча. Обещания исправить
тот же уже использованный поток без переподключения нет. При включении на уже
работающей игре нельзя гарантировать исправление текущего матча.

Приманка — собственная QUIC-v1-Initial-подобная датаграмма 1250 байт, C8/version1,
DCID и SCID по 8 случайных байт и случайное тело на **каждый поток**. Для альтернативы
C0 — 1280 байт. Это не настоящая QUIC-сессия. Исходные payload, адреса и порты не меняются; штатная checksum-обработка
WinDivert остаётся прежней. Добавленным пакетам пересчитываются IPv4/UDP длины/checksum, адреса/порты/TTL
сохраняются. Ни TLS, ни HTTPS не расшифровываются.
Отдельное исключение из generic DIRECT+ «≤5 выходных на входной»: K≤16, N≤4,
не более 64 приманок за lifetime потока. Общий на ПК бюджет ≤256 приманок/с и
358400 байт/с (реальные wire bytes учитываются отдельно), таблица 128 потоков
и 16 записей обучения (сети + healthy endpoints) на игру. Без очереди/сна для оригиналов: при лимите/ошибке приманки
оригинал всё равно проходит; неполный first-flight не обучает кэш как неудачу сети.
Доказательство нового потока берётся из native FLOW endpoint; неизвестный или
уже использованный endpoint/tuple сохраняет DIRECT без приманки. Отметка first-flight
переживает очистку 60-секундного packet cache. Есть честный код
`EXISTING_UDP_PINNED_DIRECT_NO_FIRST_FLIGHT_PROOF`; это требует Windows-проверки
порядка FLOW/NETWORK событий под реальной нагрузкой.

## Античиты и конфликты

Совместимость нового кода с BattlEye пока **не подтверждена**. Нет injection,
чтения памяти, патча exe, DLL в игре, эмуляции/отключения античита или обхода его
проверок. Это не гарантия разрешения со стороны издателя/античита: владельцу
нужно отдельно принять этот риск и проверить действующие правила игры.
PUBG/BattlEye включён по решению владельца. Установленный или загруженный FACEIT/
Vanguard для другой игры больше не блокирует PUBG. Службы Stopped, даже с
StartType=System, не означают activity. В guard отдельно видны driver/client флаги;
legacy driver_anti_cheat оставлен только как информационное поле.
Valorant и сами FACEIT exe остаются compatibility-gated. CS2/VAC opt-in допустим
при одном загруженном FACEIT driver без активного клиента/службы. Для CS2 с
активными FACEIT driver+client/service сохраняется gate; точное определение
FACEIT-матча по этим metadata невозможно, отдельной интеграции с матчами нет.
Неизвестное состояние FACEIT применимо к CS2, не к PUBG. Другие игры не наследуют
чужую compatibility policy. Это не обещание совместимости нового кода с BattlEye.
SCM открывается только с CONNECT/QUERY_STATUS (не ALL_ACCESS), без start/stop/config.
SCM/Toolhelp опрашиваются вне mutex из пути обработки пакетов; startup остаётся
pending до первой проверки, результат старого scan после capture reset не принимается.
Остальные пресеты кроме PUBG — opt-in, не compatibility PASS.

WinDivert v2 REFLECT наблюдает уже открытые и новые foreign handles. После fence
собственного inbound SNIFF handle detector готов. Compiled filters из подписанного
драйвера проверяются штатным HelperEvalFilter на **этом** игровом пакете; при
пересечении своя приманка не отправляется. Чистый sniffer не считается конфликтом.
Дополнительно определяются имена winws/winws2/goodbyedpi без чтения памяти/модулей
игры. Наличие BattlEye/EAC отдельно отражается в `anti_cheats`: само имя античита
больше не считается доказательством чужого WinDivert, не блокирует браузеры;
настоящие interceptor conflicts сохраняются. При ошибке/переполнении detector — честная пауза, оригиналы DIRECT.
Другие версии драйверов, скрытый/переименованный перехватчик без доступного
REFLECT и гонка одновременного открытия чужого handle не покрыты универсальной
гарантией. Не запускать zapret/winws вместе с приёмкой VELIQ.

## Диагностика без секретов

`gameudp.status`: профили, gate/reason, foreign PIDs, стадия каждого потока,
PID/creation/exe, destination, variant, реальные outgoing/reply/fake counters,
wire fake bytes, first_reply, cadence state, cache/TTL. `gameudp.set` принимает
`{profile_id,enabled}`; существующий owner IPC/ACL не менялся. Opt-out и learning
хранятся атомарно в защищённом `%ProgramData%\neexitlag\game-udp.json`;
обычное обновление их сохраняет. После freeze локальное обучение может пропасть:
это честный новый DIRECT baseline, а не сохранённый fake PASS.

`capture.diagnostics`/`capture.changes` содержат `game_udp` и `game_fake_packets`,
`game_fake_bytes`; relayed/direct counters отдельно. `diag-no-vpn.ps1 -Only game`
показывает их кратко. Для матча `diag-game-udp.ps1` инкрементально продвигает cursor,
не складывает cumulative counters, ограничивает страницы/время, отмечает потерю
доказательств. Экспорт — только метаданные, не payload, identity, ключи или токены.
Никакого PASS по наличию ответов вместо наблюдения владельца за матчем.

## Обновление и приёмка владельца (команды по одной)

В папке клона `main`, под владельцем установленной службы. Закрыть только
GUI VELIQ через «Выход», если он мешает замене EXE; не завершать игру средствами
VELIQ. Окно PowerShell администратора под тем же SID (UAC-off: обычный full-admin).
Команды ниже **не ходят на VPS**:

```powershell
git switch main
```
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
Get-FileHash .\bin\windows-e2e\neexitlag-service.exe,"$env:ProgramData\neexitlag\neexitlag-service.exe" -Algorithm SHA256
```

Оба SHA256 должны совпасть, служба Running. Открыть GUI и включить «Оптимизировать»;
PUBG определяется службой без ручного профиля. Happ и winws/zapret выключить.
Для последующих диагностик достаточно обычного окна владельца:

```powershell
. .\tools\windows\common.ps1
```
```powershell
Invoke-ServiceIPC 'gameudp.status' | ConvertTo-Json -Depth 16
```

Должны быть точный exe PUBG, enabled=true, reason пустой и guard.ready=true.
Pending/конфликт/античит — не PASS. Очистка DNS (администратор):

```powershell
Clear-DnsClientCache
```

Перед следующим матчем (обычный PowerShell):

```powershell
& .\tools\windows\diag-game-udp.ps1 -DurationSeconds 300
```

Во время записи запустить новый матч. В отдельном обычном окне можно получить
DNS-подсказки региона (пустой кэш ничего не опровергает):

```powershell
Get-DnsClientCache | Where-Object { ($_.Entry+' '+$_.Data) -match 'eu-central-1\.compute\.amazonaws\.com' } | Select-Object Entry,Data
```

Удалённый **реальный** адрес:порт берётся из `game_udp.destination`, не из
`Get-NetUDPEndpoint` (он показывает только локальные UDP endpoints). Для конкретного
адреса из отчёта допустим read-only PTR `Resolve-DnsName -Name <IP> -Type PTR -QuickTimeout`.
Имя AWS/регион — подсказка, не постоянная IP-allowlist и не основание маршрута.

Повторить запись для 3–5 новых матчей на Frankfurt. Зафиксировать фактическую
загрузку, отсутствие 2610, вариант/стадию, fakes, outgoing/inbound, first_reply и
relay bytes (если LOCAL работает — они 0). Лестница не пересаживает текущий поток;
при подборе нужен следующий tuple. Потом контроль через кнопку выключения либо:

```powershell
Invoke-ServiceIPC 'gameudp.set' @{profile_id='pubg';enabled=$false} | Select-Object -ExpandProperty profiles
```

Следующий новый матч — обычный DIRECT без новых приманок/relay этого механизма.
Не считать исчезновение/возврат 2610 заранее доказанным: это наблюдение владельца.
Вернуть режим:

```powershell
Invoke-ServiceIPC 'gameudp.set' @{profile_id='pubg';enabled=$true} | Select-Object -ExpandProperty profiles
```

Проверить незатронутую игру/приложение: её профилю не включать игровой UDP,
`capture.diagnostics` не должен содержать game_fake/новые relay flows по этому PID.
Широкие исторические WinDivert-фильтры в этом этапе не сужались.

## Проверки и остающиеся gates

Автоматически: генератор/рандомизация/checksum/cutoff, оригинал при ошибке fake,
точная область, один reply/burst, sustained/редкие replies/idle, лестница и TTL,
изоляция сети/игры/здоровых endpoints, общий budget, opt-out persistence, запрет protected/Valorant/FACEIT,
REFLECT native layout/fence/bounds, first-flight tombstone. Windows native seam
использует настоящий PID/birth lookup и capture dispatch с заменой **только**
финальной записи пакета; это не actual-driver/game acceptance. Workflow `Game UDP`
не требует VPS, secrets, установки игры или artifact uploads.

Нет доступного Windows runtime здесь: реальное внедрение пакетов, порядок FLOW
и NETWORK, BattlEye, драйверы других перехватчиков, RTT и 3–5 матчей не подтверждены.
CI не заменяет эти gates. Нельзя обещать отсутствие санкций античита или снижение
пинга по unit-тестам. Для релиза нужен результат владельца и отдельный compatible
allowlist по античитам; default-on PUBG — явное решение владельца для этой проверки.


## Статусы после исправления e5e0127

Для готового PUBG: `enabled=true` в engine, `state=ACTIVE`, `ready=true`, reason
пустой. `activity=WAITING_NEW_FLOW` означает, что режим готов, но приманок ещё нет;
`LOCAL_DECOYS_OBSERVED` — действительно наблюдались отправленные приманки.
ACTIVE сам по себе не доказательство работы матча. При проблеме — PENDING и
читаемая причина в обычном и клубном GUI; реальные WinDivert/process/VPN/capture/
network guards не сняты. Статус сверяет guard сразу, не ждёт следующего тика.

`engine.initial_policy=LOCAL_FIRST_UNCONFIRMED_ENDPOINT`, у нового потока
`selection_reason=LOCAL_FIRST_UNCONFIRMED_ENDPOINT`, stage=LOCAL_UDP,
variant=quic-v1-c8-k12-n2. После двух исходящих пакетов ожидаются24fake packets
при отсутствии ошибок/лимита. Проверять actual capture counters, а не только variant.
Exact DIRECT cache даёт `CONFIRMED_DIRECT_ENDPOINT`. Уже использованный tuple
получает `EXISTING_TUPLE_PINNED_DIRECT`: не приманивается и не переигрывается.

### Обновление тестового ПК: команды по одной

PowerShell **администратора под SID владельца установки**, из корня клона.
Античит-драйверы не останавливать; winws/zapret не должен обрабатывать этот же
трафик. Закрывается только GUI VELIQ через его same-owner/session pipe;
Chrome/Edge/игровые процессы helper не завершает. Обновлять до следующего матча.

```powershell
git pull --ff-only origin main
```

```powershell
& .\tools\windows\Close-VeliqGuiForUpdate.ps1
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
Start-Process "$env:LOCALAPPDATA\Programs\VELIQ\VELIQ.exe"
```

Проверить работающую службу и равенство хешей сборки/установленного service:

```powershell
Get-Service neexitlag
```

```powershell
(Get-FileHash .\bin\windows-e2e\neexitlag-service.exe).Hash -eq (Get-FileHash "$env:ProgramData\neexitlag\neexitlag-service.exe").Hash
```

```powershell
. .\tools\windows\common.ps1
```

```powershell
Invoke-ServiceIPC 'gameudp.status' | ConvertTo-Json -Depth 12
```

В случае загруженного FACEIT для другой игры наличие его driver flag ожидаемо;
оно не должно давать PUBG reason=DRIVER_ANTICHEAT_COMPATIBILITY_UNVERIFIED.
Если PUBG ещё не найдена — Steam discovery обновляется каждые15с; после этого
проверять установочный путь/профиль, не вручную включать режим по умолчанию.

```powershell
Get-Service FACEIT,FACEITService,vgk,vgc -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
```

Перед следующим новым подключением к матчу можно очистить DNS-кэш:

```powershell
Clear-DnsClientCache
```

Запустить сбор до начала матча (во время180с наблюдения перейти в игру и начать
следующий матч; скрипт не запускает игру и не делает тестовых игровых отправок):

```powershell
& .\tools\windows\diag-game-udp.ps1 -DurationSeconds 180
```

Проверить actual destination (например, наблюдавшийся18.156.243.140), LOCAL_UDP,
24fake для первых2оригиналов, inbound packets/first_reply и отсутствие relay
packets у этих local flows в capture.json. DNS hint eu-central-1 — подсказка,
не доказательство географии. Нужны3–5реальных загрузок франкфуртских матчей;
успешный winws тест не считается PASS текущего VELIQ. При старом reused UDP tuple
возможен PINNED_DIRECT, для нового first-flight нужна следующая попытка игры.
Служба не пересылает повторно уже отправленные игровые запросы.

Секреты/коды/identity/диагностические файлы не присылать в открытые каналы и git.
VPS/сертификаты для этого обновлять не нужно; на них ничего не запускалось.
