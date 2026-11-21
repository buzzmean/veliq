# Игры и обычные приложения: DIRECT по умолчанию

## Подтверждённый случай CS

Владелец сообщил на Windows/4ba1bfe: 120 мс при Optimize и 25 мс без него.
Scoped capture во время матча показал у cs2 UDP к игровому серверу: 28025 relayed
packets, `source=profile`, `application default RELAY`, VPS-01. Это фактический
маршрут игры через VPS. Browser relay usage содержит только браузерные домены
и не доказывает отсутствие игрового UDP в relay.

Встроенный профиль `cs2` появился в `fa7cdc1` с `Mode=AUTO`. AUTO без специального
пресета брал глобального победителя optimizer, а transport engine мог повторить
этот выбор при открытии. RTT probe target не измеряет путь к игровому серверу.
Владелец отдельно подтвердил исходный `mode=AUTO`, а не MANUAL. Поэтому ручной
выбор RELAY для этого случая исключён: баг вызван автоматическим выбором маршрута.

`profiles.routing` отличает `built_in`, `local_override`, `custom`. Старые файлы
не хранят автора/время создания: для локального override нельзя достоверно сказать,
создал его GUI, PowerShell или иной IPC-клиент. Built-in без override не создавался
вручную в GUI. Поле `source=profile` — источник решения, а не автор профиля.

## Исправленная политика

- Свежий встроенный CS2 и Steam — DIRECT.
- Обычное добавление приложения из списка процессов или файла — DIRECT.
- Старые игровые/неизвестные AUTO-профили не берут global relay или его backups.
  Даже старый learned relay не авторизует автоматический relay неизвестной программе.
  Сами профили и кэши не удаляются/не переписываются.
- Браузерные per-domain AUTO, OpenAI/Anthropic/Telegram и Discord presets сохранены.
  Browser bootstrap/owned PAC/native activation остаются отдельным согласованным путём.
- MANUAL и явно заданные flow rules остаются намеренным выбором владельца.
  Перед сохранением MANUAL GUI предупреждает о возможном увеличении пинга;
  по умолчанию выбран ответ «Нет», отказ не посылает `profile.set`.
- WinDivert-фильтры, UDP queues, relay/mTLS/lease и production VPS не менялись.
  Из этих данных не следует измерение нулевой добавки самого перехвата.

## Сразу вернуть CS в DIRECT на установленной версии

GUI: «Приложения» → Counter-Strike 2 → DIRECT → «Применить».
Не удалять встроенный профиль: удаление запрещено, а default существует при старте.
Остальные игры/Steam-профили также можно явно оставить DIRECT, не меняя браузеры.

Эквивалент для **обычного PowerShell**, `C:\neexitlag`, только встроенный `cs2`:

```powershell
Set-Location C:\neexitlag
$ErrorActionPreference='Stop'
. .\tools\windows\common.ps1
$csProfiles=@(Invoke-ServiceIPC 'profiles' | Where-Object { $_.id -eq 'cs2' })
if($csProfiles.Count -ne 1){throw 'Профиль cs2 не найден однозначно; выберите его в GUI'}
$csProfile=$csProfiles[0]
$rules=$csProfile.PSObject.Properties['rules']
if($rules -and @($rules.Value).Count){throw 'У cs2 есть явные правила; автоматическое изменение остановлено'}
$csProfile.mode='DIRECT'
if($csProfile.PSObject.Properties['relay_id']){$csProfile.relay_id=''}
Invoke-ServiceIPC 'profile.set' $csProfile | Out-Null
Invoke-ServiceIPC 'profiles' | Where-Object { $_.id -eq 'cs2' } |
    Select-Object id,name,mode,relay_id
```

Не менять глобальный Optimize или профили защищённых приложений. Уже существующий
TCP не переносится на другой egress. После смены UDP egress игровой сервер может
потребовать переподключения к матчу; перезапускать остальные приложения не нужно.

## Короткая проверка после обновления службы и GUI

Обновить обе сборки обычным `build-e2e.ps1`, `build-desktop.ps1`, `update-service.ps1`
под elevated owner SID и `install-desktop.ps1` под обычным owner. Проверить SHA256
службы, затем открыть GUI. Никаких VPS/setup/enroll-команд.

Во время матча, **обычный PowerShell**, `C:\neexitlag`:

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only apps,ipc
```

Версия отчёта `2026-10-19.4`; раздел «Процессы с профилем RELAY» показывает origin,
configured default и реальные `FLOW` counters отдельно. На старой службе AUTO
помечается `UNKNOWN_LEGACY_AUTO`, а реально relayed CS не скрывается.
Снимки scoped по PID/creation time, group; sampling ограничен 64 профилями и
32 процессами, truncation/lost видны. Отсутствие flow в таком снимке не является
доказательством отсутствия relay во всех соединениях. Не коммитить diag-result.txt.

## Явное исключение: игровой UDP-обход

Обычный AUTO игр по-прежнему не наследует глобальный RELAY. Новый отдельно
разрешённый владельцем режим — [Игровой UDP-обход](GAME_UDP.md): DIRECT → локальные
приманки → RELAY только после неудачных предыдущих ступеней, лишь для новых IPv4
UDP-потоков выбранной игры. PUBG default-on, остальные игры opt-in одной кнопкой;
Vanguard/FACEIT заблокированы до проверки совместимости. Это не изменение режима
всех игровых профилей и не обещание лучшего пинга или совместимости античита.
