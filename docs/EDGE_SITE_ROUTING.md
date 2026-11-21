# Edge: отдельная полоса сайтов VELIQ

Реализована отдельная полоса Microsoft Edge: свой IPv4 loopback CONNECT listener,
inline PAC, проверка готовности, recovery-процесс и сохранённое состояние.
Chrome PAC, Windows proxy, DNS Windows, SCM, credentials и сертификаты не меняются.
Сервер VPS не требует обновления.

## Активация и существующие профили

«Оптимизировать» обнаруживает установленный `msedge.exe`. Если профиля Edge ещё нет,
создаётся один custom-профиль с полным путём и AUTO / `edge-sites-pending`.
Внешние native потоки pending закрыты; рабочий `edge-sites` публикуется только после реальной проверки Edge. Существующий профиль (в том числе старый
OpenAI relay-first, MANUAL, DIRECT, DIRECT+) автоматически не заменяется.
Для существующего DIRECT/AUTO выберите его в «Приложения» → «Сайты Edge AUTO».
Для MANUAL/DIRECT+ сначала явно выберите подходящий режим; эти профили не мигрируют молча.

Явная активация записывает `app_preset: edge-sites` в этот профиль. Без этой метки
старые Edge AUTO/OpenAI профили сохраняют прежний relay-first/fail-closed контракт.
Одновременно поддерживается один Edge site-профиль владельца; второй не заменяет
PAC уже активного профиля. Chrome работает независимо, одновременно с Edge.

Последовательность: согласие закрыть Edge → listener/recovery ACK → protected guard →
штатный `edge://quit` (до 15 с, без убийства пользовательского процесса) → последний guard →
**повторный `edge.prepare` со свежим nonce** → recovery ACK → запись PAC службой → headless Edge с пустым временным профилем и **без proxy launch flags**
→ подтверждение nonce/политики/PID/SID → AUTO → открытие пользовательской сессии.
Фоновые процессы Startup Boost могут помешать штатному выходу: тогда активация
отказывается продолжать и сообщает причину; чужие процессы не завершаются.

## Привилегии и политика

GUI остаётся обычным пользовательским процессом. Только служба выполняет `edge.policy`
через существующий authenticated owner IPC и пишет:

`HKEY_USERS\<installation owner SID>\Software\Policies\Microsoft\Edge\ProxySettings`

Это JSON REG_SZ с `ProxyMode=pac_script`, inline `ProxyPacUrl` и
`ProxyPacMandatory=true`. HKLM/чужие HKU/HKCU Google Chrome не записываются.
Чужие machine/user proxy policy, отдельные ProxyMode/PacUrl/Server/Bypass значения
и неверный SID приводят к отказу. Произвольные PAC/ключи реестра через IPC не принимаются:
служба сама создаёт онлайн PAC и guard. До записи ведётся ограниченный журнал собственных
значений, чтобы сбой между файловой записью и реестром был восстанавливаемым.

В Edge появится стандартное «Управляется вашей организацией» / “Managed by your
organization”. `edge://policy` должен показывать `ProxySettings` в scope пользователя.
Это управление PAC Edge; VELIQ не читает содержимое страниц и не
подменяет TLS. Машинная политика другой организации не перезаписывается.

## Маршруты, readiness и диагностика

Используется существующий origin planner и transport: обычные сайты DIRECT-first,
неизвестные сайты — ограниченный AUTO с настоящими TLS/HTTP-пробами; protected OpenAI
только RELAY_REQUIRED. Рабочий локальный DIRECT+ для YouTube применяется только при
имеющейся подтверждённой конфигурации для Edge/сети. Новый профиль такой результат
не выдумывает. Флаг `youtube_via_relay` и логика застоя остаются прежними.
Перенос состоявшегося TCP-туннеля на другой egress не выполняется.

PAC разделяет proxy endpoint по доменам, ограничивая HTTP/2 coalescing между origin.
CONNECT передаёт TLS непрозрачно. HTTPS через PAC использует TCP; это не доказательство
полной native IPv6, UDP/QUIC или WebRTC поддержки Edge. DNS/53 остаётся прежним.
Loopback CONNECT исключён штатным WinDivert `!loopback`; внешние сокеты службы
исключаются существующей проверкой собственного процесса.

`edge.status`: `listening`, `policy_ready`, `ready_profiles`, `address`,
`recovery_address`, `last_error`, `rollback_guard_active`, `records`, `failures`, `truncated`, `lost`,
`activation_version=3`, `readiness_state`, `pending_profile`. Состояния nonce:
`WAITING_FOR_BROWSER_REQUEST`, `NONCE_INVALIDATED`, `NONCE_EXPIRED`,
`OWNER_NONCE_VERIFIED`; при проблеме политики — `POLICY_NOT_ACTIVE`.
`failures` отдельно сохраняет OWNER_SID_MISMATCH / OWNER_PROFILE_MISMATCH и другие
проверки владельца. Сам nonce в status не выводится.
Записи содержат реальные PID/creation time/exe/profile, домен, policy/route/reason,
байты, результат открытия. UI отдельно показывает домены и состояние Edge.
Origin HTTP 200 — только проверка origin, не доказательство работоспособности всей страницы.

Состояние службы: `edge-transport.json` рядом с локальными профилями в защищённом
каталоге установки. GUI/recovery: `%LOCALAPPDATA%\NeExitLag\edge-recovery.json`.
Сохраняются свои loopback-порты. Ошибка восстановления Edge диагностируется отдельно
и не останавливает восстановление Chrome. Существующие пути identity/ACL не мигрируют.

## Отказ и откат

«Отключить PAC Edge» и ошибка подтверждения автоматически заменяют рабочий PAC
статическим защитным PAC; ошибку до `edge.confirm` обрабатывает GUI, отсутствие
обращения Edge при confirm — сама служба. Только после успешной записи guard GUI
снимает native AUTO. Обычные сайты DIRECT без живого CONNECT/VPS, protected/custom
и YouTube до подтверждённой активации закрыты. В UI это явно названо защитным PAC,
`edge.status.rollback_guard_active=true`; `policy_ready=false` при этом ожидаем.

**Не выполнено буквально: автоматическое полное удаление ProxySettings.** Снять
весь PAC и одновременно гарантировать отсутствие protected DIRECT при ECH/DoH и
падении службы текущая архитектура не позволяет. `ProxyPacMandatory=false` и
глобальный `PROXY ...; DIRECT` эту защиту ослабляют и не включены.
Черновик URLBlocklist был отвергнут: Chromium URLBlocklistSubresources специально
проверяет, что заблокированный URL изображения загружается. Поэтому навигационный
blocklist не заменяет сетевой guard для всех запросов. См. [исходный тест Chromium](https://github.com/chromium/chromium/blob/main/chrome/browser/policy/test/url_blocklist_policy_browsertest.cc).
Новая URLBlocklist-политика в реализации НЕ устанавливается. Это открытое ограничение,
а не утверждение о выполненном удалении ключа. Ручное удаление ключей не требуется
для исправленной активации и не является безопасной инструкцией отката.

В Edge остаётся «Управляется вашей организацией», пока существует guard.
Перечитывание политик требует нового процесса Edge; GUI делает штатный перезапуск
с согласия владельца. Если Startup Boost/фоновые процессы не завершились за 15 с,
нужно закрыть Edge самостоятельно и повторить кнопку; пользовательские процессы
принудительно не убиваются.

**Причина отказа 3fec1ae:** GUI запрашивал nonce до `guard`, а `guard` вызывал
`Server.Forget(profile)` и удалял challenge. Это детерминированная ошибка порядка,
не доказательство неисправности SID/PID или необходимости увеличить тайм-аут.
Прежний native fixture пропускал guard; теперь воспроизводит полную последовательность.

При остановке службы recovery-процесс GUI сохраняет ordinary DIRECT только для
разрешённых профилем доменов. Protected домены не получают DIRECT fallback. После
старта службы возвращается тот же listener/PAC без переноса установленных потоков.
При утрате per-user recovery-state (например, после rollback Windows) повторное
«Оптимизировать» заново проверяет и активирует Edge; старый ready-флаг службы сам
по себе не подтверждает новый recovery-процесс.
Recovery требует запущенного GUI; если закрыты и GUI, и служба, онлайн PAC остаётся
fail-closed, а для освобождения обычных сайтов надо запустить службу/GUI и отключить PAC Edge.
Чужую политику VELIQ не удаляет даже при ошибке активации.

## Обновление на ПК владельца

Закройте GUI через трей и браузеры. В обычном PowerShell из репозитория:

```powershell
git status --short
git fetch origin
git switch main
git pull --ff-only origin main
& .\tools\windows\build-e2e.ps1
& .\tools\windows\build-desktop.ps1
```

При ошибке любой команды остановитесь; не запускайте старые binaries дальше.
Elevated PowerShell **под тем же SID владельца установки**:

```powershell
& .\tools\windows\update-service.ps1
Get-Service neexitlag
Get-FileHash .\bin\windows-e2e\neexitlag-service.exe
Get-FileHash "$env:ProgramData\neexitlag\neexitlag-service.exe"
```

Служба должна быть Running, SHA256 должны совпасть. В обычном PowerShell:

```powershell
& .\tools\windows\install-desktop.ps1
```

Откройте VELIQ, нажмите «Оптимизировать»; существующий Edge-профиль активируйте явно
кнопкой «Сайты Edge AUTO». Подтвердите штатный перезапуск Edge. В `edge://policy`
проверьте Microsoft Edge ProxySettings; настройки Chrome должны остаться прежними.

С VPN полностью OFF запустите существующую headless-диагностику обоих браузеров:

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser
```

Она открывает **изолированные пустые профили** Chrome и Edge для claude.ai, chatgpt.com,
YouTube, Telegram Web, Discord. Не коммитьте `diag-result.txt`. `PAGE LOADED`/DOM/title
не доказывают проигрывание видео, авторизацию, все API/WebSocket или отсутствие утечек.
Сопоставьте результат со свежими `edge.status` records; `ERR_*`, EMPTY PAGE и TIMEOUT
считать отказом, а не PASS. Для Edge IPC из обычного PowerShell:

```powershell
. .\tools\windows\common.ps1
Invoke-ServiceIPC 'edge.status' | ConvertTo-Json -Depth 12
```

Не запускать VPS/update-vps/setup-e2e/enroll/install/uninstall для этого обновления.

## Автоматические проверки

- Go race: DNS/bootstrap, legacy Edge semantics, separate Chrome/Edge state,
  refusal of unproved AUTO, listener failure, guard journal, guard-only restart.
- C#: discovery/dedup/full path, profile preservation, explicit marker, false ACK,
  guard failure before profile mutation, unchanged Chrome contract, no fake page PASS.
- `.github/workflows/edge-native.yml`: C# core tests, WPF build, actual Edge policy,
  девять simultaneous HTTPS/HTTP2 fixture-сайтов, реальный mTLS relay, protected
  source check, ordinary DIRECT recovery и service restart без замены браузера;
  отдельный отказ для чужой proxy policy и неверного SID.
- Existing Chrome tests/workflow остаются включены. Native Edge DIRECT+ packet
  transform и пользовательский ISP не объявляются проверенными этой фикстурой.

В Linux-окружении сборки .NET/Edge отсутствуют: C# локально не компилировался,
actual Windows acceptance здесь не выполнялся. CI должен подтвердить их отдельно.

## Исправление отказа кнопки (18.10.2026)

Кнопка теперь сама находит единственный профиль Edge; выделение строки Chrome/отсутствие
выделения не вызывает отказ до IPC. Ошибки Edge/recovery не очищают таблицу приложений
и не выключают кнопки. GUI выводит этап IPC, безопасный код и русское объяснение;
`edge.status.last_error` присутствует всегда, в том числе при ошибке до listener.
Собственные ошибки WPF/recovery передаются в службу как ограниченные phase/code через
`edge.failure`, без содержимого исключений, токенов и настроек recovery.

Новый профиль создаётся AUTO с `app_preset=edge-sites-pending`. Пока активация не
подтверждена, его внешние native flows закрыты, DNS/локальный transport не меняются;
он не получает старую глобальную Edge/OpenAI relay-first политику. После проверки
маркер меняется на `edge-sites`. Существующий DIRECT не переименовывается молча:
при нажатии кнопки AUTO публикуется только после readiness. При отказе устанавливается
guard и возвращается DIRECT; остальные профили сохраняются.

Порядок исправлен: recovery listener → служебный listener/nonce/профиль → recovery
configuration ACK → guard и штатный выход Edge → последний guard → свежий prepare/nonce → recovery ACK → live PAC → реальная проверка Edge
policy → confirm → AUTO. Отказ до live PAC не может оставить обязательный PAC на
несуществующий proxy. При любом последующем отказе служба заменяет собственный live
PAC статическим guard: обычные домены DIRECT, защищённые закрыты. `ProxyPacMandatory`
не выключается: иначе Chromium мог бы обойти PAC напрямую. Guard хранит custom
protected-домены и работает даже после удаления профиля. Чужая политика отвергается,
а не удаляется. Сообщение кнопки отката теперь прямо говорит о сохранении guard в
ProxySettings; оно больше не утверждает, что реестр не менялся.

### Где искать ошибки

Текущая SCM-служба пишет стандартный `slog` в stderr; файловый sink и каталог
`%ProgramData%\neexitlag\logs` установщиком **не создаются**. Отсутствие каталога
не доказывает отсутствие ошибки. SCM System log показывает жизненный цикл службы,
а не подробные ошибки IPC. Не запускайте второй экземпляр capture для получения лога.
Используйте безопасные диагностические поля:

```powershell
. .\tools\windows\common.ps1
Invoke-ServiceIPC 'edge.status' | Select-Object listening,policy_ready,ready_profiles,last_error | ConvertTo-Json -Depth 4
Get-Content "$env:LOCALAPPDATA\NeExitLag\gui-failure.json" -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=(Get-Date).AddMinutes(-15)} -MaxEvents 20 | Select-Object TimeCreated,Id,LevelDisplayName
```

GUI-файл содержит только фазу, безопасный код, тип исключения и время. Полные recovery-state, manifest,
identity и IPC token передавать не следует. Internet PASS на провайдере этим изменением
не заявлен; C#/WPF требуют запуска тестов CI/Windows.

При откате служба возвращает `ordinary_direct`: GUI сообщает DIRECT только если
собственный guard действительно разрешает его. Строгие custom rules и восстановленный
старый guard не выдаются за ordinary recovery. Политика из старого журнала без профиля
разбирается только в известном формате VELIQ; повреждённое состояние получает строгий
guard вместо угадывания защищённых доменов. Кто удалил ProxySettings в первоначальном
Windows-тесте, не установлено: текущий service writer не содержит удаления значения.

Новый GUI до создания AUTO pending/записи PAC проверяет read-only
`edge.status.activation_version >= 3`. Старый backend не получает неизвестный ему
pending-профиль: GUI требует обновить службу вместе с GUI. Проверка действует и
при ручном добавлении msedge.exe; существующие профили не изменяются.

## Проверки этой версии

Linux Go race/vet и cross-build не заменяют actual Edge. В `edge-native.yml` добавлены
полная guard→fresh prepare→policy→nonce транзакция. Отдельная Go-регрессия
проверяет отсутствие обращения Edge, автоматический guard и отказ ложного READY. C#/WPF и native runtime
проверяются на Windows; локальная Linux-сессия не имеет .NET/Edge. ISP PASS Edge не заявлен.
Chrome clean install: `EnsureBrowserCoverageAsync` → `EnsureChromeProfileAsync` создаёт
DIRECT full-path профиль один раз, затем штатная проверенная Chrome PAC активация
переводит его в AUTO. Existing Chrome любого режима не перезаписывается;
`BrowserCoverageTests` проверяет этот контракт. WPF на чистом ПК здесь не запускался.
