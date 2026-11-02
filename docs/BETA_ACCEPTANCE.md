# Приёмка VELIQ перед бетой на 5–6 ПК

Текущий кандидат Build639/source d20e957 собран в [draft #56](https://github.com/buzzmean/veliq/pull/56)
поверх полного комплекта #55. Ссылка на итоговый kit, SHA256 и завершённый CI:
[BETA_CANDIDATE_2026-11-02.md](BETA_CANDIDATE_2026-11-02.md). Актуальные source SHA, BuildSequence и SHA256
бинарников находятся в `candidate.json` внутри нового kit. Берите комплект
`VELIQ-beta-candidate-win-x64-NOT-APPROVED` из успешного workflow **Beta candidate
kit (no deployment)** для этого SHA. Не смешивайте разные сборки.

Старый Build618/code7be4f66 из #55 **не допускается** к 5–6 ПК: у него оставались
три origin/lifecycle FAIL. Новый transport получает адресат через owner CONNECT
без PAC/GPO-зависимости; raw TLS без него временно использует authenticated RELAY.
Контракт, границы и доказательства: [BROWSER_AUTHORITY_TRANSPORT.md](BROWSER_AUTHORITY_TRANSPORT.md).

До расширения нужны полный exact-SHA CI и ручная приёмка 2–3 разных ПК.
Удачный installer, одно видео или один матч не заменяют остальные gates.
Все ручные результаты по умолчанию NOT_RUN; artifact не является public release,
auto-update или разрешением на rollout. Неделя наблюдения R6 не закрывается за день.

## Что подготовить

1. PC01 — чистая установка; PC02 — обновление существующей установки и rollback.
   При возможности PC03 — другой вариант Windows/античита/адаптера.
2. Лабораторный Windows 10/11 x64, установленный Chrome и Edge, Discord и нужные
   игры. Сборочные Go/.NET SDK, Python и Git на этих ПК **не нужны**.
3. Доверенный предыдущий Setup для отката, резервная копия установленного пакета
   и состояния с сохранением ACL. Не копировать identity/ключи между ПК.
4. Код активации — только закрытый файл через `New-ClubCodeFile.ps1` из kit;
   не помещать его в командную строку, JSON evidence, скриншоты или чат.
5. Подтвердить возможность активации 5–6 мест, сроки leaf/client сертификатов,
   основной/запасной relay и доступность CP. Это проверка реального состояния,
   которое локальная сборка не доказывает. Публичный CA в новом Setup уже есть;
   замена CA для этих тестов не нужна.

На обычном UAC ПК установка повышается под **тем же SID** будущего владельца GUI.
Ввод учётных данных другого администратора устанавливает другого owner и не
заменяет этот сценарий. Для клуба: установка техническим администратором и
последующее понижение того же SID проверяются отдельно; гостевой ClubMode read-only.

## Последовательность на каждом лабораторном ПК

| Шаг | Проверка | PASS |
|---|---|---|
| 1 | Setup / обновление | SCM `VELIQ` Running, GUI доступен, exact hashes совпадают, нет лишнего SCM/старого GUI |
| 2 | Обычный пользователь | GUI без elevation, профили/identity сохранены, другой SID не получает управление |
| 3 | Живые браузеры | Chrome и Edge открыты на обычных сайтах до Optimize; после включения защищённые сайты работают без restart/policy page |
| 4 | Экономия | обычные сайты остаются DIRECT; actual owner CONNECT наблюдается для каждого проверенного браузера |
| 5 | YouTube | холодный старт, 2160p не менее 2 мин, seek и autoplay; после LOCAL новые googlevideo flows имеют RELAY RX около 0 |
| 6 | Discord | реальный собеседник, речь в обе стороны 10 мин, voice LOCAL подтверждён, а не выведен из малого VPS ping |
| 7 | Игры | полные PUBG, Valorant и FACEIT матчи на соответствующих ПК, без anti-cheat ошибок и деградации |
| 8 | OFF / stop / recovery | исходный пользовательский proxy возвращается; обычное приложение работает; после recovery тот же failed authority снова открывается |
| 9 | Freeze / identity | разные overlays/identity, стабильный слот того же ПК после двух reboot, автоматический старт без диалогов |
| 10 | Rollback | возврат проверенного предыдущего пакета за ≤10 мин, сохранены identity, SID, профили и активация |

Сначала проверить две доступные обычные страницы с выключенным Optimize.
Оставить оба браузера открытыми на этих страницах, включить Optimize и только
затем запускать новое видео/защищённые сайты. Это проверяет уже запущенный
браузер, не создавая заранее старый видео TCP. Не закрывать процессы браузеров,
не открывать chrome://policy/edge://policy, не отключать HTTP/2, ECH или TLS checks.

Для YouTube записать 2160p/буфер/остановки и фактические LOCAL/RELAY media bytes.
Проверить второй ролик, seek и автопереход. Старые pinned relay flows, HTML,
CP/tickets и служебные байты не равны новым googlevideo media flows. Один ACK,
скрытая смена маршрута, короткий TLS ответ или скриншот качества не доказывают LOCAL.

Для Discord TCP login/control может быть RELAY; голос оценивается по UDP voice.
Тихий канал без собеседника не доказывает живость LOCAL. Если voice или 2160p не
прошли, результат FAIL/NOT_RUN, а не автоматическое разрешение на бету.

Для игр записать запуск/login/patch, полный матч, disconnect/anti-cheat сообщения,
RTT/jitter/loss относительно исходного состояния. Игровые AUTO остаются DIRECT;
не отключать защиту и не делать исключения для получения PASS. Наличие подписанного
WinDivert в CI не доказывает совместимость с FACEIT/Vanguard/BattlEye на целевом ПК.

## Два безопасных сборщика

`Get-BetaSnapshot.ps1` читает SCM и binary hashes, без IPC/identity/сети.
`Get-BetaRuntimeEvidence.ps1` дополнительно читает только локальные IPC агрегаты:
owner CONNECT state и requests/exchanges по profile ID. Tokens, SID, domains,
URLs, policy values и identity в результат не попадают. Оба создают новый файл,
не перезаписывают evidence и не ставят ручные checks в PASS.

Обычный PowerShell без повышения, из распакованного проверенного kit:

```powershell
& {
  $ErrorActionPreference='Stop'
  & .\Get-BetaSnapshot.ps1 -Manifest '.\candidate.json' -PCId PC01 -OutputPath '.\PC01-binary.json'
  & .\Get-BetaRuntimeEvidence.ps1 -Manifest '.\candidate.json' -PCId PC01 -Stage BeforeEnable -OutputPath '.\PC01-before.json'
}
```

После Optimize, открытия обычной/защищённой страницы в **каждом** браузере и видео:

```powershell
& {
  $ErrorActionPreference='Stop'
  & .\Get-BetaRuntimeEvidence.ps1 -Manifest '.\candidate.json' -PCId PC01 -Stage Enabled -OutputPath '.\PC01-enabled.json'
}
```

Ожидается `authority.system_proxy_applied=true` и requests/exchanges текущих
проверенных профилей >0. Один native-only exchange не подтверждает этот канал.
Если состояние pending/foreign-policy или наблюдения отсутствуют — STOP, не
выставлять browser_sites/owner_proxy_lifecycle в PASS. Для PC02/PC03 поменять PCId
и имена файлов; после reboot использовать новые имена, чтобы не затереть историю.

После явного OFF:

```powershell
& {
  $ErrorActionPreference='Stop'
  & .\Get-BetaRuntimeEvidence.ps1 -Manifest '.\candidate.json' -PCId PC01 -Stage AfterOff -OutputPath '.\PC01-after-off.json'
}
```

Проверить `optimizing=false`, `system_proxy_applied=false`, обычную сеть и
возврат исходных Windows proxy/PAC/auto-detect настроек. Чужую настройку не
очищать ради PASS. Затем снова включить Optimize: новые обмены должны наблюдаться.
Повторить intentional restart службы и GUI exit, сохраняя тот же owner SID.

## Сбои и восстановление

На лабораторном ПК проверить capture/listener/relay recovery и повтор того же
адресата после отказа. При полностью умершем proxy process новые запросы его
клиентов могут ждать SCM recovery; protected не должны получать DIRECT. PASS —
автоматический возврат за ≤30 с без ручного изменения proxy, рестарта браузера
или очистки cache. Полная service crash recovery — ручной gate, не вывод из
Controller fixture. Существующие TCP остаются pinned и не replay/migrate.

**На diskless Langame нельзя отключать NIC, LAN или путь iSCSI/3260.** Полный
30-секундный обрыв сети допустим только на подтверждённом local-disk lab PC,
чей системный том не зависит от этой сети. На diskless проверять ограниченный
relay outage, сохраняя storage/LAN. Это отдельный тест и не доказательство
смены network fingerprint. Не выдавать relay block за полный network-change PASS.

Для golden image сначала OFF/cleanup и возврат исходного proxy, затем seal.
Не запечатывать активный loopback proxy без его журнала. Проверить минимум два
разных overlay, две перезагрузки, разные device identity между ПК и стабильный
слот того же ПК. Исходный пользовательский SID не подменять другим администратором.

## Решение о расширении

В `BETA_RESULTS.template.json` записать факты отдельно для каждого ПК. Каждый
PASS ссылается на непустой evidence и его SHA256; `owner_proxy_lifecycle` включает
CONNECT uptake, обычное приложение, OFF/restore и recovery. Общие gates включают
exact-SHA Linux/Windows race/vet/build, pinned DLL filters, C#, origin isolation,
installer lifecycle, fail-closed, hashes, реальные серверы/места/сертификаты и матчи.

`beta_acceptance.py` проверяет структуру, hashes и полноту, но не является
независимой аттестацией заявленного PASS. Нужны 2–3 разных PC ID и owner_reviewed.
Его можно запустить на машине с Python; для самих ПК/игр Python не нужен.
Никакие NOT_RUN/FAIL не заменяются предположением об историческом PASS.

После всех gates: 3 ПК на 30–60 мин → 5–6 ПК на смену с готовым rollback → неделя
наблюдения R6. Клубный релиз на ~40 ПК — отдельное решение. Перед 7 ноября не
добавлять экспериментальные обновления; срок резервного сервера 12 ноября
требует отдельной проверки. Этот план не меняет production, БД, CA или коды.

## История предыдущего кандидата

Build618/code7be4f66, [artifact13112765460](https://github.com/buzzmean/veliq/actions/runs/41378361024/artifacts/13112765460),
имел installer/Windows/C#/CDN PASS и origin13PASS/3FAIL. Его ZIP SHA256:
`0a469978ee6777f4e298ffb5c979ee12e1ed35b93ec4f073408faf382753f37c`.
Это воспроизводимая прежняя проверка, а не результат нового кандидата.
Intermittent HTTP_BODY_NOT_OBSERVED старого reflection-seam Edge теста не считать
объяснённым только по очередному PASS. Архивные Build601/618 не смешивать с новым kit.
