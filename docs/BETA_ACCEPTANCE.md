# VELIQ: приёмка кандидата и бета на 5–6 ПК

План следующей тестовой смены, 3 ноября 2026. Цель — принять ограниченную бету,
а не объявить все R1–R7 закрытыми за день. R6 требует наблюдения неделю; R7 —
отдельная выкатка на 40 ПК после пилота. На 7 ноября экспериментальные обновления
не планируются. Любой STOP ниже оставляет бету запрещённой.

## 0. Кандидат и текущий допуск

Ветка `release/beta-candidate-20261102` основана на #51/83dfad8 (CDN cold/resume,
отмена устаревших фоновых проб), с test-only origin gates из #54/e9f58b9.
Кандидат также включает шесть независимых исправлений #41/#42/#43/#44/#46/#48:
rollback ELF fixture, WPF technical preference, сохранение подтверждённого Edge PAC,
событийное ожидание native plan, Browser Disable sequence и PS5.1 reinstall CA.
#52/HTTP80, #53/QUIC, accounts/оплата и другие экспериментальные ветки не включены.
QUIC browser LOCAL не поддерживается. Состояние native H2 origin isolation и
live-policy uptake остаётся открытым до соответствующего исправления и evidence.
**Начальный допуск NO_GO**: шаблон намеренно не содержит PASS. На проверенной
Build618/code7be4f66 матрица origin13PASS/3FAIL: native-only H2 в обоих порядках и применение
owned PAC к уже работающему браузеру за30с. Это программные блокеры; ручная приёмка
на двух лабораторных ПК полезна параллельно, но даже её PASS не разрешает5–6ПК,
пока все три сценария не исправлены и не прошли на выбранном exact SHA.

Зафиксированный кандидат **Build618**, source_commit
`7be4f66b06f068a59488335b38c80dbec01df641`:
[скачать полный kit](https://github.com/buzzmean/veliq/actions/runs/41378361024/artifacts/13112765460).
Artifact SHA256: `0a469978ee6777f4e298ffb5c979ee12e1ed35b93ec4f073408faf382753f37c`.
`VELIQ-Setup.exe` SHA256: `7965e8022ffc1d337e1a6f3b197b69c2f958b68c857ecaa6d009d4049072bd43`.
Срок хранения artifact — до16ноября. Все CI ниже относятся к этому **code SHA**;
последующее уточнение этого плана не меняет бинарники Build618 и их допуск.
В README внутри kit находится версия плана на момент сборки; актуальные результаты
и уточнение безопасного сетевого теста приведены здесь.

Подтверждено на code SHA: полный [Verify Linux+Windows](https://github.com/buzzmean/veliq/actions/runs/41378361083),
[Beta4jobs](https://github.com/buzzmean/veliq/actions/runs/41378361024), Chrome/Edge,
27 YouTube LOCAL сценариев, GameUDP, isolated upgrade и relay tests — PASS.
Actual Setup install/update/uninstall и binary snapshot прошли в PS5.1 и PS7;
отрицательная установка CLUBIMAGE без кода возвращает exit1, SCM не создаёт.
[Origin gate](https://github.com/buzzmean/veliq/actions/runs/41378361012) — **FAIL13PASS/3FAIL**,
все8 same-authority outage/recovery/retry PASS. Прежний Edge efdb05e дал
HTTP_BODY_NOT_OBSERVED native-active в reflection-seam тесте; текущий PASS не
устанавливает причину того intermittent failure.

Workflow `Beta candidate kit (no deployment)` проверяет exact head: полный Windows
Go race/vet/build в отдельном обязательном job и независимую сборку/Setup smoke, C# контракты, self-contained GUI, службу отдельно в PS5.1 и PS7,
проверяет равенство exe и pinned DLL. Его artifact
`VELIQ-beta-candidate-win-x64-NOT-APPROVED` содержит exe, candidate.json и SHA256SUMS.
Build/Setup job может завершиться раньше validation job. Наличие artifact означает
сборку, а не разрешение раскатки: origin gate выполняется
отдельным workflow и его FAIL должен блокировать допуск. Все workflow берутся с
ОДНОГО source_commit. candidate.json содержит `approval=NOT_APPROVED`.

Комплект содержит полный `VELIQ-Setup.exe`, оба exe, этот план, шаблон отчёта,
`Get-BetaSnapshot.ps1`, `beta_acceptance.py` и подготовку защищённого файла кода клуба.
Setup собран с существующим публичным CA из опубликованного v0.3.577; installer SHA256
перед извлечением проверяется, старый Setup не исполняется. DER fingerprint CA:
`622db56fba69041b108fc31b5b3cf81a5ed722faa3110ef2b896b8fac42abd85`.
Парсер Inno6.4.3 закреплён commit/hash, используется только при сборке. Проверяются
CA constraints, self-signature и срок ≥14дней. Новая CA не создаётся, приватных
ключей, identity и кодов в комплекте нет; VPS не используется для его подготовки.

Отдельный настоящий Setup с эфемерным CA и только loopback endpoints проходит
install→update→uninstall в PS5.1 и PS7 на disposable Windows VM. Полный candidate
Setup с существующим CA **только компилируется**, не запускается в CI: реальная
клубная активация и сеть остаются приёмкой владельца. Это также не проверка подписи
конечного exe/SmartScreen на клубном ПК. Публичный release и auto-update feed
не изменяются. Начальный NO_GO сохраняется до всех gates ниже.

## 1. Подготовка перед сменой (30–45 минут)

Назначить PC01/PC02 лабораторными, остальные 3–4 ПК пока оставить без беты.
Нужны отдельный администратор для восстановления, будущий гостевой SID, физический доступ,
консоль Langame и исправный предыдущий образ/установщик. Сохранить hash старых exe
и путь к защищённой резервной копии. Не помещать identity/ключи/коды в чат или git.

Скачать `VELIQ-beta-candidate-win-x64-NOT-APPROVED` из успешного workflow #55
**на выбранном exact SHA**, распаковать в отдельную папку. Не выбирать «последний
зелёный» другой ветки. Сверить commit и hashes с журналом соответствующего CI;
затем в PowerShell из папки kit проверить весь комплект:

```powershell
& {
    $ErrorActionPreference='Stop'
    foreach ($line in Get-Content -LiteralPath '.\SHA256SUMS') {
        if ($line -cnotmatch '^([a-f0-9]{64})  ([A-Za-z0-9_.-]+)$') { throw 'INVALID_SUMS' }
        $expected=$Matches[1]; $name=$Matches[2]
        if ((Get-FileHash -LiteralPath (Join-Path $PWD $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected) { throw 'KIT_HASH_MISMATCH' }
    }
    $candidate=Get-Content -Raw '.\candidate.json' | ConvertFrom-Json
    if ($candidate.kind -cne 'installer-and-update-kit') { throw 'FULL_SETUP_REQUIRED' }
    Write-Output ('CANDIDATE '+$candidate.source_commit+'; NOT_APPROVED')
}
```

Этот блок проверяет целостность после сверки с доверенным CI, а не подпись издателя.
Новый commit/пересборка после начала приёмки требует новых проверок. Нельзя смешивать
службу Build601 и GUI другого кандидата. После установки проверять реальные hashes.
Windows PowerShell5.1 уже есть на гостевых ПК; Git/Go/.NETSDK/Inno не нужны.
Python3.10+ нужен только владельцу для проверки итогового отчёта; его также можно
проверить в рабочей среде по очищенным файлам. Если Windows блокирует скачанные
скрипты, разблокировать только проверенные по SHA файлы; не менять глобальную policy
и не отключать защиту.

Установка/запечатывание выполняется **под будущим SID владельца GUI** с повышением
того же аккаунта. Для клубного образа этот аккаунт временно имеет административные
права в техническом режиме, затем владелец средствами Windows убирает его из
Administrators, сохранив отдельного администратора для восстановления. GUI работает
без повышения под прежним SID. Подстановка пароля другого admin при UAC меняет
владельца и не подходит. Произвольный другой гостевой SID не поддерживается этим
пилотом; от него ожидается отказ доступа. В Club Mode гостю доступно состояние,
а изменение защищённых настроек/отключение оптимизации должно быть запрещено.
Смена групп/аккаунтов не выполняется скриптами VELIQ автоматически.

Для самостоятельной пересборки см. INSTALLER_BUILD.md:
exact checkout, существующий публичный CA, Inno6.4.3. `publish-release` не запускать.

## 2. Gate до установки на 5–6 ПК

| Gate | PASS | STOP |
|---|---|---|
| Exact build | Linux+Windows race/vet/build, DLL filters, C# и UI smoke на exact SHA | FAIL, CANCELLED, PENDING, отсутствие выполненных шагов |
| Origin | Защищённые authority не достигают DIRECT в HTTP2/native/PAC сценариях | Любой ORIGIN_ISOLATION/OUTAGE_ROUTE_VIOLATION; нельзя заменить прошлым PASS |
| Отказы | Relay/listener/capture и совместный отказ сохраняют защищённый floor; ordinary DIRECT доступен согласно контракту | DIRECT для защищённого запроса, зависание/повтор клиентского запроса |
| Setup | Чистая disposable VM: install/update/uninstall, signed pinned driver, same-owner UAC | Только компиляция Setup или parser PASS вместо установки |
| Серверы | Действующий CP/relay, известный резерв, ёмкость ≥6 мест, срок сертификатов и кода покрывает пилот | Неизвестный срок/остаток мест; отключение единственного production relay для теста |
| Секреты | Runtime identity отсутствует в базовом образе; тестовые/засвеченные коды обработаны владельцем | Общий device key на клонах или опубликованный код |

Старый Windows job125004701705 от #54 завершился CANCELLED, не PASS. Build618
получил собственные завершённые Windows race/vet/build и Verify на code7be4f66.
Независимые Python rollback/WPF/Edge fixes включены; совместный прогон пройден.
Результаты другой версии не подменяют проверки выбранного кандидата.

## 3. На двух тестовых ПК (2–4 часа, параллельно)

Сохранить baseline без оптимизации: обычные сайты, YouTube, Discord, игра,
RTT/jitter/loss, NIC RX/TX и начальные счётчики VELIQ. Использовать те же версии
браузера/игр и одну сеть. Не требовать «улучшения пинга» без сравнимого замера.

| Проверка | Действия и evidence | PASS |
|---|---|---|
| Install/update | PC01 чистый Setup, PC02 обновление существующего VELIQ; записать SHA service/GUI, статус SCM | Идентичная candidate версия, сохранены настройки/слот; GUI без elevation |
| Гостевой режим | Не elevated GUI под owner SID: обычный режим Optimize/Отключить/Диагностика; в Club Mode только состояние; проверить второй неразрешённый SID | Нет UAC; чужой SID не управляет службой; Club Mode запрещает гостю менять настройки; обычный UI без технических ошибок |
| Браузеры | Chrome и Edge: YouTube, Telegram, ChatGPT, Claude, Discord; один браузер открыт до Optimize, другой после | Полный ответ/страница, фактический маршрут; pending uptake не засчитывается READY |
| Ordinary | VK, Яндекс, обычная загрузка до/после Optimize и при relay failure | DIRECT, без новых relay bytes для этого трафика, без существенной регрессии baseline |
| YouTube cold/warm | Чистый proof: 2160p ≥2мин; ещё5мин, перемотка,2 автоперехода; затем warm повтор | Подтверждённые resolution/player stats, нет остановок; новая media нагрузка LOCAL, googlevideo RELAY≈0 после допуска |
| Discord | Реальный собеседник, ≥10мин двустороннего голоса, вход/выход/смена канала, совместно с видео | Слышно обе стороны, нет обрывов; voice UDP LOCAL, не выводить LOCAL по одному UI status |
| PUBG | Полный матч, сверить actual exe/UDP counters/route | Нет античит-ошибок, игровой трафик без VPS; сохранить RTT/jitter/loss |
| Valorant/Vanguard | Полный матч, вход/выход и restart игры | Guard сохранён; античит не отключался и не требует обхода |
| FACEIT | Полный матч с соответствующим античитом | Нет конфликтов/ошибок; непроверенный античит не считать поддержанным |
| OFF/ON/сеть | Optimize OFF→ON; на ПК с локальным диском отключить сеть на30с→вернуть. На Langame сохранять NIC/iSCSI, проверять отдельно отказ Internet/relay. Новые и старые requests | Новые flows восстанавливаются, старые не replay/migrate, ordinary не заперт |
| Отказы | Только лабораторный endpoint/правило на тестовом ПК: relay unreachable; stop/crash службы отдельно | Защищённое не становится DIRECT; ordinary работает; после восстановления новые flows корректны |
| Freeze | Два отдельных writable overlay, две одновременные загрузки, затем по2 перезагрузки | Разные device identity между ПК, тот же слот у каждого после reboot, нет ручной активации |
| Откат | PC02 вернуть проверенный предыдущий service/GUI/образ; повторить сайты/игру/SCM | Успешно за≤10мин, настройки/identity/слот сохранены; затем повторно проверить candidate |

**Бездисковый ПК:** не отключать NIC, LAN, iSCSI3260 или общий коммутатор для
имитации потери Internet. Полный разрыв NIC выполнять на отдельном лабораторном
ПК с локальным системным диском. На Langame использовать только контролируемый
отказ внешнего Internet/relay для тестового ПК, сохраняя дисковую сеть; если такой
изоляции нет, этот тест на diskless не выполнять и не ставить PASS. Адресное
блокирование relay проверяет отказ relay, а не смену сетевого fingerprint.

Счётчики сравнивать delta за точное окно. Старые pinned relay H2, CP/билеты и DNS
учитываются отдельно от нового googlevideo media. Не обрывать браузерные соединения
для искусственного PASS. Запросы, уже отдавшие origin bytes, не должны повторяться.
Запрет/блокировка защищённого запроса при отказе — корректный fail-closed исход;
нельзя требовать его загрузки в обход relay. TLS bypass/MITM не применять.

При несовместимости античита сразу отключить эксперимент и откатить тестовый ПК;
не добавлять AV exclusions, не отключать античит и не переносить риск на гостей.
Реальные сбои сохранять как FAIL, с временем/версией и очищенным evidence.

## 4. Установка и откат

Использовать штатные процедуры из [CLUB_PILOT.md](CLUB_PILOT.md) и
[INSTALLER_BUILD.md](INSTALLER_BUILD.md), сверяя современные пути VELIQ:
SCM `VELIQ`, `%ProgramData%\VELIQ`, exe `veliq-service.exe`.
Часть старых примеров этих документов содержит neexitlag и старый CP endpoint;
не копировать их как новые параметры. Существующий service.json читается общим
normalizer; CP/relay/CA не менять при обычном обновлении бинарника.

Основной путь — `VELIQ-Setup.exe` из проверенного kit: PC01 чистая установка,
PC02 обновление тем же владельцем. GUI закрыть через трей; браузеры принудительно
не закрывать. Установщик должен обновить службу и GUI одного кандидата. Сверить
реальные hashes, Running, install-result.json и сохранение настроек/identity/слота.
Не использовать отдельный per-user GUI поверх установки в ProgramFiles.

Для чистого freeze-образа **до первой активации** подготовить файл кода в закрытой
папке администратора. Из elevated PowerShell в папке kit (код вводится скрыто):

```powershell
& {
    $ErrorActionPreference='Stop'
    $private=Join-Path $env:ProgramData 'VELIQ-Beta-Private'
    New-Item -ItemType Directory -Path $private -Force | Out-Null
    $code=Join-Path $private 'club-code.txt'
    & .\New-ClubCodeFile.ps1 -Path $code
    $p=Start-Process -FilePath (Join-Path $PWD 'VELIQ-Setup.exe') -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CLUBIMAGE=1',('/CLUBCODEFILE="'+$code+'"')) -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw 'CLUB_IMAGE_SETUP_FAILED' }
    if ((Get-Service VELIQ).Status -ne 'Stopped') { throw 'IMAGE_SERVICE_MUST_BE_STOPPED' }
    foreach ($name in @('identity.json','device.pem','probe.token')) {
        if (Test-Path -LiteralPath (Join-Path "$env:ProgramData\VELIQ" $name)) { throw 'IMAGE_CONTAINS_RUNTIME_IDENTITY' }
    }
}
```

Создавать образ только из чистой системы; не удалять identity работающего ПК ради
этого блока. Не клонировать активированную машину. Файл кода остаётся закрытым,
не входит в отчёт. На двух клонах с отдельными writable overlay проверить первый
boot/активацию, разную identity и сохранение своего слота после двух reboot.
Полный freeze gate включает actual boot task/ACL/исключения записи из CLUB_PILOT.md;
остановленная служба при подготовке образа не заменяет эту проверку.

После обычной установки/обновления собрать безопасный binary snapshot. Из папки
kit под тем пользователем, у которого установлен/работает GUI:

```powershell
& {
    $ErrorActionPreference='Stop'
    & .\Get-BetaSnapshot.ps1 -Manifest '.\candidate.json' -PCId PC01 -OutputPath '.\PC01.json'
}
```

Для PC02 поменять id/имя файла. Существующий output не перезаписывается. Snapshot
читает только SCM/пути/хеши бинарников: не читает токены, не вызывает IPC/сеть,
не меняет службу/policy. Все ручные проверки в нём остаются NOT_RUN; commit пуст,
если служба не Running или hashes не совпали. Его запись добавить в `pcs` отчёта
(заменить соответствующую заготовку), а не считать автоматической приёмкой.

Откат: до обновления сохранить предыдущий рабочий образ/Setup и закрытую копию
бинарников и настроек. Вернуть проверенный прежний образ/Setup согласно штатной
процедуре с сохранением identity/слота; затем проверить фактические hashes, SCM,
сайты, игру и reboot. Для прежней script-managed установки exact checkout содержит
`update-service.ps1`: при неуспехе он восстанавливает binary/ACL; после успешного
обновления прежний binary берётся из напечатанного защищённого backup path.
GUI восстанавливать через соответствующий ему Setup/marker. Не копировать поверх
работающих процессов. Реальный откат должен уложиться в10мин; без PASS — STOP.

## 5. Отчёт и решение о расширении

Скопировать BETA_RESULTS.template.json в закрытую папку `beta-evidence/report.json`.
В той же папке сохранить очищенные отчёты/evidence, без identity/ключей/токенов.
У каждого PASS записать относительный путь и SHA256 файла. FAIL/PENDING/NOT_RUN
оставлять как есть. Записать exact SHA/hashes как сверху, так и для каждого ПК.
Значения брать из проверенного candidate manifest, а не подгонять под отчёт.

На машине владельца из папки kit:

```powershell
& {
    $ErrorActionPreference='Stop'
    & python --version
    if ($LASTEXITCODE -ne 0) { throw 'PYTHON_UNAVAILABLE' }
    $manifest=Get-Content -Raw '.\candidate.json' | ConvertFrom-Json
    $service=($manifest.files | Where-Object path -eq 'veliq-service.exe').sha256
    $gui=($manifest.files | Where-Object path -eq 'VELIQ.exe').sha256
    & python .\beta_acceptance.py '.\beta-evidence\report.json' --commit $manifest.source_commit --service-sha256 $service --gui-sha256 $gui
    if ($LASTEXITCODE -ne 0) { throw 'BETA_NO_GO' }
}
```

Это проверка полноты ручной приёмки и целостности evidence, не независимая
аттестация безопасности: содержание evidence и правдивость PASS проверяет владелец.
`READY_FOR_OWNER_DECISION` не устанавливает приложение и не запускает rollout.
Нельзя вручную ставить PASS на origin gate при известных native H2 violations.

Если все gates PASS: сначала добавить один ПК (всего3), наблюдать30–60мин;
потом ещё2–3 (итого5–6), наблюдать всю смену. Вести поПК: часыработы, NIC и relay
traffic delta, LOCAL/RELAY, crashes/reconnects, жалобы, версия. При первой утечке,
ошибке античита, потере активации после reboot или массовой недоступности — STOP
добавления и откат затронутых ПК. Лимит трафика Hostkey3ТБ/месяц оценивать по
сумме RX+TX согласно биллингу и месячному прогнозу с минимум30% запасом, без
придуманной гарантии по двухминутному видео. Недельный R6 продолжается после
дневной приёмки; 40ПК и публичный релиз в этот допуск не входят.

## Изменение PAC после воспроизведения совместного отказа

Seed ce0767f, run41369834272/job125037705516: AvailabilityV1 при listener=false,
capture_ready=false отправил outage.openai.com на DIRECT127.0.0.1, connection7,
SNI outage.openai.com, HTTP2 body48. Ordinary использовал то же H2 напрямую.
Guarded counterpart заблокировал оба; recovery обоих новых authority работал.
Это actual Windows/Chrome evidence в контролируемой среде, не публичная утечка.

AvailabilityV2 сохраняет DIRECT fallback для ordinary. Для всех bundled RELAY
floors, protectedSuffixes профиля и strictProxy из цепочки удаляются DIRECT entries;
если старый recovery PAC вернул только DIRECT, используется существующий
fail-closed proxy endpoint. Старый V1 owner journal оборачивается V2 идемпотентно.
Никакой TLS replay или переноса существующих TCP нет. Запрет fallback защищённого
имени означает, что при отсутствии listener запрос блокируется даже при здоровом
capture: браузер не должен угадывать наличие capture по отсутствующему proxy.

Это изменение не переписывает уже закешированный V1 внутри работающего браузера.
Нужен проверенный uptake новой policy; fresh native-only без PAC и старые H2
origin violations этим не исправлены. До их разрешения origin_isolation остаётся
FAIL и rollout запрещён. Результаты после исправления должны быть добавлены по SHA.


Повтор failed-authority после recovery проверяется той же последовательностью
без сброса proxy cache и без browser restart. Required снова должен дать полный
body через relay; ordinary может сохранить уже существующий DIRECT connection.
Byte delta и owner-bound actual ingress проверяются отдельно от новых TCP opens:
законный preconnect не обязан создавать ещё одно соединение в момент retry.

Для beta-ветки полный Windows Go race/vet/build выполняется один раз в workflow
Beta candidate kit по PR head. Origin workflow сохраняет actual browser/DLL gate;
YouTube LOCAL сохраняет 17 policy-change +10 cold/resume/RST сценариев. Служебный
R1 artifact для этой ветки не публикуется: единственный комплект — beta-kit.
Это убирает дублирование сборок, сохраняя обязательную проверку точного SHA.


В общем Windows прогоне кандидата обнаружена дополнительная same-clock-tick
коллизия: cancelled background очищал Retry нового media failure, если обе
трёхминутные задержки получили одинаковое время. Исправление сравнивает зарезервированное routing/learning/cooldown состояние, сохраняя
промежуточные реальные изменения и игнорируя лишь диагностические admission counters,
а не считает один Retry timestamp доказательством владения. Детерминированный
portable regression использует одинаковое now для реального foreground trial и
его failure; unchanged-background positive control обязан освобождать Retry.
