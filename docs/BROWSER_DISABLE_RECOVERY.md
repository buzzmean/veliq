# Выключение браузерной маршрутизации: cached PAC и DIRECT

Аудит регрессии 6adefe5, 21.10.2026. Проверка кода и изолированные тесты;
реальный Chrome/Edge владельца не запускался. VPS не меняется.

## A: CONNECT после выключения

Корневая причина воспроизводима из кода: `openBrowser` делегировал PAC native
upstream по признаку профиля даже при `current.enabled=false`. Уже остановленный
backend отвергал OPEN. Дополнительно planner сохранял protected guard для
выключенного AUTO. Browser PAC остаётся в памяти независимо от удаления registry
value, поэтому этого достаточно для ERR_TUNNEL_CONNECTION_FAILED.

Теперь после настоящей PID/birth/path/SID авторизации browser socket выключенный
режим открывает обычный OS TCP DIRECT без Engine, WinDivert, relay, learning и
повтора application bytes. Транзакционный SYSTEM guard разрешает то же recovery
helper только для своего executable/profile. При повторном Optimize временный
DIRECT grant отзывается до Start capture. При активной оптимизации protected
политика остаётся прежней; это не её fail-open downgrade.

Изменение Optimize/Automatic не закрывает все proxy TCP: существующие соединения
закреплены. Бесполезный listener снимается после трёх минут без сокетов/новых
запросов, активный TCP не закрывается по этому таймеру. Включение умеет заново
привязать прежний порт. Snapshot содержит last_activity/active_connections.

## B: изменение реестра не равно подхвату политики

`browserProxyPolicyRemove` всегда удалял **значение** ProxySettings; сам ключ
Chrome/Edge не удаляется. Гипотеза об удалении ключа не подтвердилась. Причина,
видимая в коде: после удаления не отправлялось user Group Policy notification.
Предыдущий GUI RequestRefresh вызывался только при apply/native enable, не при
снятии политики. В Chromium Windows loader действительно используется
`RegisterGPNotification(..., false)` для user policy:
https://github.com/chromium/chromium/blob/main/components/policy/core/common/policy_loader_win.cc
(исходник прочитан 21.10.2026; это не эмпирический результат конкретного Chrome).

После реального Set/Delete теперь запрашивается RefreshPolicyEx(USER, RP_FORCE).
Повтор записи того же значения, отсутствие value и отказ менять чужое value не
создают notification flood. SYSTEM выбирает только token проверенного owner SID
из WTS, вызывает API на отдельном impersonated thread и возвращает identity;
неудачный Revert не возвращает такой thread планировщику. GUI дополнительно
запрашивает user refresh при переходе Optimizing в false в своей user session.
Нет HKLM policy, запуска gpupdate/браузера, chrome://quit или диалога.

Запрос асинхронный и bounded (один native GP call на процесс); результат доступен
как policy_refresh в browser.status/edge.status. REQUESTED означает только вызов
API, live_uptake=NOT_OBSERVED. Отказ/недоступный owner session не откатывает уже
выполненное удаление owned value и не считается ошибкой активационного кода.

Не гарантируется, что любая версия Chromium немедленно обновит chrome://policy
или сетевую конфигурацию. Для этого нужны реальные Windows измерения. Именно
поэтому A обязателен: пока используется cached PAC, ordinary browser работает
через DIRECT compatibility. После полного закрытия локальных endpoints обычный
сетевой отказ proxy позволяет DIRECT, явно включённый в текущий availability PAC.
Старый сторонний/legacy PAC без DIRECT не позволяет одновременно гарантировать
нулевые listeners и работу браузера, который совсем не перечитывает policy;
такое состояние нужно явно выявлять, а не выдавать за PASS.

## C: SCM host, watchdog и recovery имеют одно имя файла

`veliq-service.exe --chrome-recovery` — отдельный owner-GUI child, а не второй
SCM host. Его старый lifecycle завершался только по stdin EOF/GUI Dispose; поэтому
он мог пережить Stop-Service. `-browser-policy-watchdog` — ещё один отдельный
SYSTEM процесс, но он не открывает CONNECT ports. По одному имени EXE и порту
нельзя установить роль PID 20012: нужна проверка SCM ProcessId/flags/parent.

Новый recovery CLI read-only проверяет SCM раз в250мс и сам завершает свой
listener/process при STOP_PENDING/STOPPED/NOT_INSTALLED. UNKNOWN или старт не
считаются остановкой. GUI не перезапускает helper при выключенной оптимизации;
полный SCM stop остаётся штатным exit0. Watchdog не запускает Stopped service:
recovery применяется только к действительно Running/hung host; crash перезапускает
существующая SCM recovery policy. Штатный останов не подменяется control128.

`diagnose-browser-processes.ps1` ничего не меняет: SCM state/PID, ограниченные
process roles/parent/birth/path и loopback ports. CommandLine только разбирается
внутри, никогда не печатается. Start/restart/credentials не вызываются. Новый
status proxy показывает process_role/process_id. Watchdog может оставаться как
процесс без слушателей — это ожидаемо; сам SCM host и его recovery listeners
после штатного stop оставаться не должны. Реальный Stop-Service/SCM на ПК ещё
не проверен. После закрытия всех endpoints cached current PAC использует свой
явный DIRECT fallback; legacy PAC без DIRECT — ограничение из B.

## D: подготовка браузера не является активацией устройства

Фоновый startup мог пройти проверку Optimizing, затем дождаться recovery/prepare
IPC и продолжить profile.set/silent.apply уже после выключения. Ошибка отвергнутой
мутации оборачивалась в EDGE_OPERATION_FAILED с текстом «Активация отклонена»;
ObserveAuxiliary оставлял технический Notice даже после здорового статуса.

Теперь подготовка использует generation ticket; Disable/Exit/смена состояния
инвалидируют старую работу. Перед следующим шагом применяется новая проверка,
а поздний результат не откатывает профиль поверх нового действия пользователя.
При выключенном/неподключённом режиме background не запускает подготовку PAC.
Обычные кнопки браузеров сначала включают оптимизацию, затем подготавливают lane.

Browser phase/code/type пишутся в существующий ограниченный GUI-журнал, без
сырых сообщений/секретов. На экране нейтральная подготовка либо «прямая сеть»;
это не ACTIVATE/REVOKE и не изменение activation.status. Успешная подготовка,
здоровый статус или успешное повторное наблюдение убирают свой transient Notice;
историческая диагностика сохраняется. Причины настоящих ACL/policy отказов не
теряются и не выдаются за PASS. UI-контракты обновлены именно для разделения
технического журнала и пользовательского статуса, а не ослабления проверок.

## E: что проверяет автоматика

- Core/service race: реальные локальные TCP bytes через compatibility, owner отказ,
  active protected guard, отрицательный deny/неверный executable, idle без закрытия
  активного TCP, rebind, отзыв disabled grant перед capture Start.
- Native registry fixture: только value, сохранённый key, foreign/no-op, notification.
- C#180 тестов: disable во время profile.set, disable/re-enable generation,
  отсутствие позднего apply/rollback, нейтральный startup failure, очистка на успехе,
  сохранение ACTIVATED/identity и немедленный DIRECT-статус без повторного мерцания.
- Windows browser fixture TestWindowsBrowserDisablePolicyContinuity (только env
  VELIQ_TEST_BROWSER_DISABLE=1 в одноразовой CI VM): настоящий Chrome/Edge,
  настоящий owner/SID и registry PAC, локальный HTTP body с новым marker для каждой
  фазы. Browser PID/birth не меняется при disable/host Close. Backend seam специально
  перестаёт принимать native dispatch; новый запрос обязан пройти без него.
  После host Close current cached PAC имеет DIRECT и браузер продолжает controlled
  HTTP. Нет TLS exceptions, proxy launch flags, ручного policy reload или Internet
  claims. Fake backend **не доказывает WinDivert/SCM runtime**; проверка HTTP, не
  обещание HTTPS/ISP результата. Только изолированный test browser убирается teardown.
- PS fixtures: пустой список процессов, роли без утечки command line, PS parse;
  в Verify предусмотрены Windows PowerShell5.1/7.

## Короткая проверка владельца на установленном ПК

Все команды по одной, PowerShell администратора под прежним SID, корень репозитория.
Никаких VPS/update-vps/enroll/provision/revoke команд. Chrome/Edge не закрывать.
Для обновления выйти только из VELIQ, затем:

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
(Get-FileHash .\bin\windows-e2e\veliq-service.exe).Hash -eq (Get-FileHash "$env:ProgramData\VELIQ\veliq-service.exe").Hash
```

Открыть VELIQ обычным ярлыком, включить Optimize. Оба браузера уже открыты.

```powershell
& .\tools\windows\check-browser-disable.ps1 -Stage baseline
```

Выключить оптимизацию в GUI и сразу открыть новую вкладку https://vk.ru. Не
нажимать «Повторно загрузить правила». Страница должна открыться; реальный
результат страницы записывает владелец, helper его не выдумывает.

```powershell
& .\tools\windows\check-browser-disable.ps1 -Stage disabled
```

Снова включить Optimize, затем выбрать «Выход» в трее VELIQ. Сразу открыть новую
вкладку vk.ru; Chrome/Edge не закрывать.

```powershell
& .\tools\windows\check-browser-disable.ps1 -Stage exit
```

Снова открыть VELIQ обычным ярлыком и включить Optimize, чтобы Stop проверял
живые primary/recovery, затем:

```powershell
& .\tools\windows\diagnose-browser-processes.ps1
```

```powershell
Stop-Service VELIQ
```

```powershell
& .\tools\windows\check-browser-disable.ps1 -Stage stopped
```

Helper ждёт до10с, включая5с стабильного Stopped: старый SCM process завершён,
50165/50166 не слушаются, browser PID/birth прежние и owned values отсутствуют.
Он не меняет service/registry/browser; пишет только несекретный baseline в
игнорируемый bin/diagnostics. STRUCTURE_PASS отделён от
NETWORK_NOT_AUTOMATICALLY_VERIFIED. Сразу открыть новую вкладку vk.ru и подтвердить
страницу отдельно. Любая оставшаяся политика может быть чужой: не удалять вручную.
Если порт/процесс остался, выполнить diagnose-browser-processes ещё раз — роли
и SCM events помогут отличить helper, настоящий restart или посторонний процесс.

Возврат службы после проверки:

```powershell
Start-Service VELIQ
```

Затем обычная кнопка Optimize. Protected маршруты должны снова проходить через
relay; разрешение disabled DIRECT не должно пережить enable. Нет команды
revoke-tests: она отключила бы тестовый ПК.

Уточнение при отрицательной проверке E: global Optimize/Automatic off отделён
от profile DIRECT/pending. При активной глобальной оптимизации pending-профиль
не получает disabled grant для protected origin. При глобальном off известный
owner browser с MANUAL профилем также не направляется в stopped backend.
Эти ветки проверяются отдельно; unknown/foreign executable всё ещё отвергается.
