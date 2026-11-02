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
**Начальный допуск NO_GO**: шаблон намеренно не содержит PASS.

Workflow `Beta candidate kit (no deployment)` собирает exact head, полный Windows
Go race/vet/build, C# контракты, self-contained GUI, службу отдельно в PS5.1 и PS7,
проверяет равенство exe и pinned DLL. Его artifact
`VELIQ-beta-candidate-win-x64-NOT-APPROVED` содержит exe, candidate.json и SHA256SUMS.
Наличие artifact означает сборку, а не разрешение раскатки: origin gate выполняется
отдельным workflow и его FAIL должен блокировать допуск. Все workflow берутся с
ОДНОГО source_commit. candidate.json содержит `approval=NOT_APPROVED`.

Это update-kit для уже установленного тестового ПК. В нём нет драйвера, CA,
конфигурации, кодов и identity; это НЕ Setup для чистого образа. Для чистых машин
нужен `build-setup.ps1` того же commit с существующим публичным CA владельца и
проверенным Inno Setup6.4.3. CI дополнительно собирает настоящий Inno Setup6.4.3 с отдельным эфемерным CA и
loopback-only endpoint и проверяет install/update/uninstall в PS5.1 и PS7. Этот
Setup не публикуется, его CA не подходит production; это не приёмка клубной активации.
Публичный production CA в текущей среде отсутствует; production
VPS для его получения не используется. Нельзя подставлять новый тестовый CA:
установленные CP/relay ему не доверяют. Сборка Setup и первый install остаются
отдельным обязательным gate, даже если update-kit уже есть.

## 1. Подготовка перед сменой (30–45 минут)

Назначить PC01/PC02 лабораторными, остальные 3–4 ПК пока оставить без беты.
Нужны отдельный администратор, обычный гостевой пользователь, физический доступ,
доступ к консоли Langame и исправный предыдущий образ/установщик. Сохранить точные
hash старых exe и путь к локальной защищённой резервной копии. Identity, приватные
ключи, токены и staged code не помещать в git, чат или публичный результат.

Зафиксировать source_commit и hash обоих exe из candidate.json. Распаковать kit
в отдельную папку `bin/beta-kit` внутри exact checkout. Проверить каждый SHA256SUMS через Get-FileHash; несовпадение —
STOP. Новый commit или пересборка после начала тестов обнуляет допуск этой сборки.
Нельзя смешивать службу Build601 и GUI другого кандидата, а затем засчитать всё
как одну проверенную версию. Проверить и установленный hash после обновления.

У владельца: Git/Go1.25/.NET8/Inno6.4.3 нужны только для сборки Setup; Python3.10+
для проверки отчёта. Гостевые ПК этих инструментов не требуют. Проверить версии
реальным вызовом. В clean checkout exact commit сборка Setup без установки:

```powershell
& {
    $ErrorActionPreference='Stop'
    $commit=(& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'GIT_HEAD_FAILED' }
    & .\tools\windows\build-setup.ps1 -ExpectedCommit $commit -PublicTrustDirectory '.e2e\activation-trust'
}
```

Входная папка содержит существующий PUBLIC ca.pem. Не запускать publish-release:
он подписывает на production host и включает общий канал обновлений. Не выпускать
публичный release и не менять auto-update feed ради ограниченной беты.

## 2. Gate до установки на 5–6 ПК

| Gate | PASS | STOP |
|---|---|---|
| Exact build | Linux+Windows race/vet/build, DLL filters, C# и UI smoke на exact SHA | FAIL, CANCELLED, PENDING, отсутствие выполненных шагов |
| Origin | Защищённые authority не достигают DIRECT в HTTP2/native/PAC сценариях | Любой ORIGIN_ISOLATION/OUTAGE_ROUTE_VIOLATION; нельзя заменить прошлым PASS |
| Отказы | Relay/listener/capture и совместный отказ сохраняют защищённый floor; ordinary DIRECT доступен согласно контракту | DIRECT для защищённого запроса, зависание/повтор клиентского запроса |
| Setup | Чистая disposable VM: install/update/uninstall, signed pinned driver, same-owner UAC | Только компиляция Setup или parser PASS вместо установки |
| Серверы | Действующий CP/relay, известный резерв, ёмкость ≥6 мест, срок сертификатов и кода покрывает пилот | Неизвестный срок/остаток мест; отключение единственного production relay для теста |
| Секреты | Runtime identity отсутствует в базовом образе; тестовые/засвеченные коды обработаны владельцем | Общий device key на клонах или опубликованный код |

Windows job125004701705 от предыдущего #54 завершился CANCELLED; завершённый
журнал через connector недоступен. Это не PASS. Новый candidate должен получить
собственный завершённый полный Windows прогон. Прежние Python rollback/WPF/Edge блокеры имеют независимые исправления,
теперь включённые в candidate; их совместный CI должен подтвердиться на его SHA.
Заменять этот прогон результатом другой ветки нельзя.

## 3. На двух тестовых ПК (2–4 часа, параллельно)

Сохранить baseline без оптимизации: обычные сайты, YouTube, Discord, игра,
RTT/jitter/loss, NIC RX/TX и начальные счётчики VELIQ. Использовать те же версии
браузера/игр и одну сеть. Не требовать «улучшения пинга» без сравнимого замера.

| Проверка | Действия и evidence | PASS |
|---|---|---|
| Install/update | PC01 чистый Setup, PC02 обновление существующего VELIQ; записать SHA service/GUI, статус SCM | Идентичная candidate версия, сохранены настройки/слот; GUI без elevation |
| Гостевой режим | Вход обычным пользователем; Optimize/Отключить/Диагностика; второй неразрешённый SID | Нет UAC; чужой SID не управляет службой; обычный UI без технических ошибок |
| Браузеры | Chrome и Edge: YouTube, Telegram, ChatGPT, Claude, Discord; один браузер открыт до Optimize, другой после | Полный ответ/страница, фактический маршрут; pending uptake не засчитывается READY |
| Ordinary | VK, Яндекс, обычная загрузка до/после Optimize и при relay failure | DIRECT, без новых relay bytes для этого трафика, без существенной регрессии baseline |
| YouTube cold/warm | Чистый proof: 2160p ≥2мин; ещё5мин, перемотка,2 автоперехода; затем warm повтор | Подтверждённые resolution/player stats, нет остановок; новая media нагрузка LOCAL, googlevideo RELAY≈0 после допуска |
| Discord | Реальный собеседник, ≥10мин двустороннего голоса, вход/выход/смена канала, совместно с видео | Слышно обе стороны, нет обрывов; voice UDP LOCAL, не выводить LOCAL по одному UI status |
| PUBG | Полный матч, сверить actual exe/UDP counters/route | Нет античит-ошибок, игровой трафик без VPS; сохранить RTT/jitter/loss |
| Valorant/Vanguard | Полный матч, вход/выход и restart игры | Guard сохранён; античит не отключался и не требует обхода |
| FACEIT | Полный матч с соответствующим античитом | Нет конфликтов/ошибок; непроверенный античит не считать поддержанным |
| OFF/ON/сеть | Optimize OFF→ON, отключить сеть тестового ПК на30с→вернуть, новые и старые requests | Новые flows восстанавливаются, старые не replay/migrate, ordinary не заперт |
| Отказы | Только лабораторный endpoint/правило на тестовом ПК: relay unreachable; stop/crash службы отдельно | Защищённое не становится DIRECT; ordinary работает; после восстановления новые flows корректны |
| Freeze | Два отдельных writable overlay, две одновременные загрузки, затем по2 перезагрузки | Разные device identity между ПК, тот же слот у каждого после reboot, нет ручной активации |
| Откат | PC02 вернуть проверенный предыдущий service/GUI/образ; повторить сайты/игру/SCM | Успешно за≤10мин, настройки/identity/слот сохранены; затем повторно проверить candidate |

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

Для update-kit в уже установленный тестовый VELIQ — elevated PowerShell того же
owner SID, из exact checkout (папка kit задаётся явно):

```powershell
& {
    $ErrorActionPreference='Stop'
    $kit=(Resolve-Path '.\bin\beta-kit').Path
    & .\tools\windows\update-service.ps1 -ServiceExecutable (Join-Path $kit 'veliq-service.exe')
    if ((Get-Service VELIQ).Status -ne 'Running') { throw 'SERVICE_NOT_RUNNING' }
    foreach ($name in @('veliq-service.exe')) {
        if ((Get-FileHash (Join-Path $kit $name)).Hash -ne (Get-FileHash (Join-Path "$env:ProgramData\VELIQ" $name)).Hash) { throw 'INSTALLED_HASH_MISMATCH' }
    }
}
```

GUI предварительно закрыть через трей; Chrome/Edge не закрывать принудительно.
Проверить реальный путь установленного GUI. Если GUI принадлежит Setup и находится
в `%ProgramFiles%\VELIQ`, обновлять GUI только Setup того же SHA; per-user installer
ниже не обновляет этот путь и может оставить старый autostart. Не засчитывать такую
смешанную установку как candidate PASS. Для прежней per-user установки с marker
GUI обновляется тем же обычным пользователем (без admin):
`& .\tools\windows\install-desktop.ps1 -SourceDirectory '.\bin\beta-kit'`.
Сверить hash установленного `%LOCALAPPDATA%\Programs\VELIQ\VELIQ.exe`.

При неуспешном обновлении update-service автоматически восстанавливает прежний
binary/ACL; проверить фактический hash и Running, а не сообщение «готово».
Для функционального отката после успешной установки тем же update-service
передать `veliq-service.exe` из напечатанного защищённого backup path; GUI вернуть
из его backup с сохранением install marker, либо восстановить прежний чистый образ.
Не копировать файлы поверх работающего процесса. После отката повторить короткий
smoke и reboot. Не клонировать активированную identity в образ.

## 5. Отчёт и решение о расширении

Скопировать BETA_RESULTS.template.json в закрытую папку `beta-evidence/report.json`.
В той же папке сохранить очищенные отчёты/evidence, без identity/ключей/токенов.
У каждого PASS записать относительный путь и SHA256 файла. FAIL/PENDING/NOT_RUN
оставлять как есть. Записать exact SHA/hashes как сверху, так и для каждого ПК.
Значения брать из проверенного candidate manifest, а не подгонять под отчёт.

На машине владельца из exact checkout:

```powershell
& {
    $ErrorActionPreference='Stop'
    & python --version
    if ($LASTEXITCODE -ne 0) { throw 'PYTHON_UNAVAILABLE' }
    $manifest=Get-Content -Raw '.\bin\beta-kit\candidate.json' | ConvertFrom-Json
    $service=($manifest.files | Where-Object path -eq 'veliq-service.exe').sha256
    $gui=($manifest.files | Where-Object path -eq 'VELIQ.exe').sha256
    & python .\tools\beta_acceptance.py '.\beta-evidence\report.json' --commit $manifest.source_commit --service-sha256 $service --gui-sha256 $gui
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
трёхминутные задержки получили одинаковое время. Исправление сравнивает всю
зарезервированную запись learning, сохраняя любое промежуточное изменение,
а не считает один Retry timestamp доказательством владения. Детерминированный
portable regression использует одинаковое now для реального foreground trial и
его failure; unchanged-background positive control обязан освобождать Retry.
