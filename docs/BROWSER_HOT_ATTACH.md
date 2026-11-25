# Браузеры без перезапуска: поэтапная проверка

> Актуальная native проверка 22.10.2026: из корня клона в обычном PowerShell
> `& .\tools\windows\test-browser-startup.ps1 -Phase baseline`, затем после
> запуска VELIQ и открытия новых вкладок в тех же браузерах —
> `& .\tools\windows\test-browser-startup.ps1 -Phase ready`.
> Браузеры не закрывать. Имя `test-browser-startup.ps1` без пути PowerShell
> не находит: до запуска скрипта это ошибка поиска команды, а не отказ native.
> При пропущенной фазе сам скрипт теперь выводит BROWSER_STARTUP_USAGE без
> интерактивного запроса. ECH/DNS маршруты и ограничения: BROWSER_OPAQUE_ROUTING.md.


> Актуальное решение владельца 20.10.2026: выбран вариант A — тихий owned PAC без browser restart; см. [BROWSER_SILENT_POLICY.md](BROWSER_SILENT_POLICY.md). Независимый WFP/driver guard ниже — будущий вариант B. Исторические restart-инструкции не относятся к текущему UX.

> 20.10.2026: владелец разрешил этап (в) и запретил пользовательские диалоги/
> перезапуск браузеров. Аудит остановил runtime-реализацию по пункту 4 задания:
> независимого постоянного guard в текущем backend нет. Решение, первичные
> источники, ограничения и acceptance — [BROWSER_NATIVE_GUARD.md](BROWSER_NATIVE_GUARD.md).
> Исторический PAC/restart путь ниже не является выполнением этапа (в) и не
> предлагается как временный UX без отдельного решения владельца.


## Этап (а): регистрация профилей, не активация маршрутов

После первого успешного подключения GUI к службе каталог установленных браузеров
создаёт отсутствующие профили автоматически. Не нужно нажимать «Оптимизировать»
или браузерные кнопки. Chrome получает DIRECT до обычной PAC-активации; Edge —
AUTO с `app_preset=edge-sites-pending`. Это **не** подтверждение готовности AUTO.
Уже существующие профили, режимы, правила, DIRECT+ и полные пути сохраняются.

GUI ничего не записывает в политику браузера в рамках регистрации, не запускает
и не закрывает браузер. Старые кнопки PAC с диалогом/штатным перезапуском пока
сохранены по решению владельца; на этом этапе проверять нужно только регистрацию.
Если служба уже оптимизирует трафик, создание отсутствующего Edge откладывается
(`DEFERRED / ACTIVE_CAPTURE_PENDING_EDGE`): pending AUTO иначе немедленно блокировал
бы его новые внешние соединения. После выключения оптимизации регистрация повторяется.
Отказ дополнительного IPC не очищает подтверждённую таблицу приложений. Повторная
проверка после отказа выполняется не чаще раза в 10 с; после успеха — один раз за запуск GUI.

В «Диагностике» есть сводка регистрации. Ограниченный отчёт без секретов:
`%LOCALAPPDATA%\VELIQ\browser-startup.json`. В нём время начала/окончания,
длительность, браузер, полный путь, профиль, режим, состояние и безопасный код отказа.
Содержимое ошибки IPC, токены, сертификаты и HTTPS payload туда не записываются.
Отчёт относится к текущему пользователю; проверяйте время, чтобы отличить старый GUI.

## Короткая проверка этапа (а), VPN OFF

Оставьте Chrome и Edge открытыми. Закройте **только VELIQ через «Выход» в трее**.
Если служба уже из `b358970` или новее и `edge.status.activation_version >= 3`,
обновите только GUI (служба и VPS на этом этапе не менялись), в обычном PowerShell:

```powershell
git switch main
if ($LASTEXITCODE) { throw 'Git switch failed' }
git pull --ff-only origin main
if ($LASTEXITCODE) { throw 'Git pull failed' }
git merge-base --is-ancestor 84793bf HEAD
if ($LASTEXITCODE) { throw 'Expected stage-a code/diagnostics not present' }
& .\tools\windows\build-desktop.ps1
if ($LASTEXITCODE) { throw 'GUI build failed' }
& .\tools\windows\install-desktop.ps1
Start-Process "$env:LOCALAPPDATA\Programs\VELIQ\VELIQ.exe"
```

У старой службы `3fec1ae` Edge capability может быть ниже 3: новый GUI честно покажет
`EDGE_IPC_UNSUPPORTED`, а не создаст нераспознаваемый AUTO. Если служба ещё не обновлялась,
после `git pull` сначала выполните в обычном PowerShell `& .\tools\windows\build-e2e.ps1`,
затем в повышенном PowerShell **под тем же SID владельца**, из того же репозитория:

```powershell
& .\tools\windows\update-service.ps1
$built=(Get-FileHash .\bin\windows-e2e\veliq-service.exe).Hash
$running=(Get-FileHash "$env:ProgramData\VELIQ\veliq-service.exe").Hash
if ($built -ne $running -or (Get-Service VELIQ).Status -ne 'Running') { throw 'Service update verification failed' }
```

После этого выполните GUI-only команды выше в обычном окне. Закрывать браузеры
не требуется; при обновлении службы возможен разрыв сетевых соединений, это не
измерение hot attach. Не запускать setup/install/uninstall/update-vps и не переобучать identity.

На чистой установке с выключенной оптимизацией через несколько секунд должны
появиться обе строки, Edge AUTO pending. **Не удаляйте рабочие профили ради теста.**
Существующий Edge DIRECT не мигрирует автоматически: выбранный ранее режим сохраняется.
Не нажимайте PAC-кнопки для проверки этапа (а): их старый сценарий ещё перезапускает браузер.

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

Диагностика читает профили из IPC, отчёт GUI, PID и creation time текущей Windows-сессии.
Проверяет сохранение уже открытых процессов за интервал диагностики. Её headless
пробы используют отдельные временные профили; это не доказательство подхвата PAC
открытым окном или полноценной работы сайта. PID дочернего renderer может естественно
исчезнуть; это отдельно от перезапуска основного browser process. Не коммитить diag-result.txt.

## Этап (б): новые TCP, owned PAC остаётся crash-guard

`browser.native.enable {profile_id}` готовит IPv4/TCP capture **до** публикации AUTO,
требует существующий service-owned mandatory PAC того же owner SID. Fresh без guard
получает `NATIVE_OWNED_PAC_GUARD_REQUIRED`, без изменения профиля/политики/браузера.
Это решение владельца: после crash службы WinDivert снимает фильтры. Native-only
не может обещать protected fail-closed при crash; устранение зависимости — отдельный этап.

GUI автоматически пробует этот IPC для Chrome AUTO, созданного GUI pending Chrome и
Edge AUTO / DIRECT `edge-sites-pending`, когда включена оптимизация, и перед Optimize.
Ручной MANUAL/DIRECT+/не-pending DIRECT не меняется. Если guard есть, Edge pending становится
AUTO/native без кнопки и browser quit. Неподдерживаемая/старая служба и отказ capture/guard
не очищают таблицу. Повтор ограничен 30 с. Старые PAC-кнопки, диалоги и quit-путь сохранены;
это откат, удаление которого ещё не разрешено (этап в).

Новый native TCP принимается локально, ClientHello/Host читается bounded worker (32 KiB,
2 с); до решения нет upstream данных. Видимый достоверный SNI/Host использует существующий
TLS/certificate/HTTP GET planner, DNS recovery и сетевой/профильный кэш. ECH outer SNI,
неполный ClientHello и отсутствие имени не считаются доменом: только authenticated
RELAY_REQUIRED к исходному адресу, **никакого DIRECT fallback**. DNS/53 остаётся прежним.
Метаданные/IP/shared-IP не заменяют истинное имя. HTTPS не расшифровывается.

Native enable не вызывает reset старых TCP: `ReconfigureNewConnections` сохраняет
TCP-сокеты, но атомарно fences/retires старые UDP mappings выбранного браузера, чтобы
старый DIRECT UDP/443 не переживал публикацию AUTO. Повторный monitor без изменения
профиля UDP не трогает. Уже открытый HTTP/2
может пережить обновление страницы: новый маршрут действует только после появления
нового соединения. Для initial DIRECT silence после отправки данных: через 2 с закрывается
только этот flow, в кэш идёт отказ (YouTube-family сразу TTL 10 мин); никакого replay или
переноса установленного TLS. Браузер может повторить запрос новым соединением. Байт ответа
не очищает verdict и не означает страницу PASS.

`browser.native.status`: capture/Optimize, actual origin/opaque, PID/creation time, policy,
ошибки, actual payload bytes, enable→first upstream open и first bidirectional exchange.
Часы Windows могут иметь одинаковые timestamp: граница активации задаётся flow ID,
а не сравнением времени. Последние метрики — **не HTTP(S)/page PASS**. Учет максимум 512 flows / 128 activation clocks,
ответ до 60 KiB, усечения/lost видны. Общий native+PAC relay usage: active/opened TCP
и минуты по profile/domain, payload bytes без QUIC overhead и origin probes. Opaque
идёт в `<opaque>`, истинный домен не выдумывается. Googlevideo с известным именем —
общий hard limit 8, очередь 32 / до 2 с, затем admission error без мёртвого DIRECT;
разрешение «потом relay» не делает лимит бесконечным. Opaque видео нельзя достоверно
отнести к googlevideo; оно дополнительно ограничено общим relay pool 8×48. VPS не меняется.

Edge при nonce failure не выдаёт PAC READY: native использует реальный bound listener
и owned fail-closed PAC, либо статический guard (ordinary DIRECT, protected закрыты),
если listener не поднимается. Чужая политика не заменяется. Chrome journal/онлайн PAC
не меняются. Старый owner recovery-процесс восстанавливается из имеющегося состояния.
GUI запрашивает `RefreshPolicy(false)` под owner user, не SYSTEM/machine: Windows Chromium
смотрит user GP notifications. API асинхронный; `REQUESTED` **не доказывает** live uptake.
Отчёт: `%LOCALAPPDATA%\VELIQ\browser-native-policy-refresh.txt`. Если уже открытый
Edge держит старый мёртвый PAC, отсутствие actual exchange остаётся видимым отказом;
не утверждаем автоматическое исправление этого случая до Windows-проверки владельца.

IPv6 data routing и UDP/443 политика не меняются. IPv6 guard сохраняет fail-closed,
даже когда new-only исключает native TCP из сброса preexisting flows. Не обещаем
поддержку IPv6/QUIC direct/обход coalescing на уровне домена без достоверного имени.

### Обновление и короткая проверка без закрытия Chrome/Edge

Закройте **только GUI** через «Выход» в трее. Сохраните уже установленные owned PAC,
не удаляйте профили или реестр. Обновление службы само разрывает принадлежащие ей sockets;
это отличается от native enable при уже работающей службе и не доказывает continuity.
Из elevated PowerShell **того же SID владельца установки**, в `C:\VELIQ`:

```powershell
$ErrorActionPreference='Stop'
git switch main
if ($LASTEXITCODE) { throw 'git switch failed' }
git pull --ff-only origin main
if ($LASTEXITCODE) { throw 'git pull failed' }
& .\tools\windows\build-e2e.ps1
& .\tools\windows\build-desktop.ps1
& .\tools\windows\update-service.ps1 -NativeTcpFirewall
if ((Get-FileHash .\bin\windows-e2e\veliq-service.exe).Hash -ne (Get-FileHash "$env:ProgramData\VELIQ\veliq-service.exe").Hash) { throw 'Service hash mismatch' }
Get-Service VELIQ | Select-Object Status
```

Далее обычный owner PowerShell: `& .\tools\windows\install-desktop.ps1`, открыть
`%LOCALAPPDATA%\Programs\VELIQ\VELIQ.exe`, нажать Optimize без PAC-кнопок/закрытия
браузеров. В открытом окне обновить обычную страницу, YouTube и ChatGPT; затем:

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

Скрипт 2026-10-19.5 сохраняет PID/creation time до/после, native decisions/timing,
relay usage и отдельно headless controls. Не путать headless успех со старым окном.
Существующий PAC может обслуживать запросы без native-record: это совместимый PAC путь,
не native interception PASS. Прислать отчет, **не коммитить diag-result.txt**.

Локально .NET/Windows отсутствуют: C#/WPF, реальный Chrome с owned policy и unchanged
PID/creation проверяются CI, native deferred TCP — Windows socket/mTLS/race burst.
Это не Internet PASS и не доказательство живого policy refresh на ПК владельца.

## PAC и native: раздельные доказательства (19.10.2026)

Online PAC намеренно направляет все домены в CONNECT с раздельными proxy origins:
это защищает attribution/ECH и HTTP/2 coalescing. Пока браузер использует такой
PAC, у него нет внешнего TCP SYN к сайту: он подключается к loopback. Поэтому
`first_tunnel_opened_at` native = отсутствует / `enable_to_first_open_ms=-1`
в старой версии не доказывает неисправность PAC. `LIVE_UPTAKE_NOT_OBSERVED` в файле
refresh — результат асинхронного запроса GP в прошлом, не текущий статус транспорта.

| Метка | Что действительно наблюдалось |
|---|---|
| `PAC_CONNECT` | Browser owner/SID прошёл CONNECT, frontend принял upstream/handoff. Не подтверждает внешний TLS/HTTP |
| `PAC_RECOVERY` | Запрос пришёл через отдельно авторизованный owner recovery helper |
| `PAC_NATIVE_UPSTREAM` | Только точный новый service-owned upstream делегирован в WinDivert; native worker действительно открыл выбранный DIRECT/DIRECT+/authenticated RELAY; завершённый handoff подтверждают байты в обе стороны |
| `NATIVE_TCP` | Внешнее новое TCP-соединение самого браузера принято прозрачным native capture; SNI/Host или opaque relay |

Один запрос может иметь **две связанные части**: PAC ingress и native upstream.
Их нельзя суммировать как два запроса или выдавать за native без PAC. Соответствие:
profile, PID/creation time, domain и source/destination в bounded evidence. Старые
HTTP/2/TCP не переносятся: они могут продолжать PAC-only до штатного закрытия.
Обновление страницы не гарантирует новое TCP: браузер вправе повторно использовать H2.

Для профиля с `browser_transport=native` новые PAC upstream делегируются через уже
существующий exact-tuple механизм WinDivert. До SYN регистрируется ограниченная
alias-запись; actual service socket owner проверяется, обычные sockets службы не
перехватываются повторно. Сохраняются admission/state bounds. CONNECT authority
остаётся метаданными **этого** проверенного владельца: ECH outer SNI не заменяет его.
Без CONNECT metadata прежние неоднозначные native потоки — только REQUIRED relay.
Не добавлены MITM, TLS exceptions, DIRECT fallback защищённых доменов или replay
application data. Игры, UDP, фильтры и общий default route не менялись.

`browser.status` / `edge.status`: `path_metrics` — cumulative PAC counters с момента
старта listener, `listen_to_first_open_ms` и first exchange. Это часы listener,
**не** момент нажатия Optimize. `browser.native.status.profiles` — native counters и
`enable_to_first_open_ms` / exchange с момента activation; -1 означает NOT_OBSERVED.
Нулевые даты не печатаются. Байты в обе стороны — обмен транспортом, не page PASS.
Counters переживают вытеснение отдельных records, но сбрасываются при соответствующем
restart/activation; lost/truncated/cardinality overflow всегда видимы.

Edge после успешной native-публикации получает `app_preset=edge-sites` вместо pending.
`edge.status.transport_mode=NATIVE_ARMED_PAC_GUARD`, readiness отдельно показывает
capture armed / PAC-only observation / upstream OPEN без обмена / actual native tunnel. `pac_nonce_readiness`
остаётся отдельной честной проверкой legacy PAC nonce; native не подделывает READY.
`owned_guard_installed` не равен `rollback_guard_active`: последний означает static
fail-closed PAC, а не работающий online listener, просто сохранённый как guard.
Fresh без owned guard по-прежнему не активируется автоматически; этап (в) не начат.

### Ошибки origin и таймауты

Раньше header, owner/PLAN, DNS/TLS/HTTP probes и OPEN делили deadline 8 с. После
долгого PLAN успешному маршруту могло не остаться времени для OPEN; stall retry
тоже наследовал этот истёкший бюджет. Теперь bounded PLAN и OPEN разделены,
OPEN — максимум 3 с, pre-response stall retry — отдельный bounded budget от lifetime
этого frontend connection. Listener shutdown/client teardown отменяют работу;
установленному сокету не назначается 3-секундный lifetime. Это не увеличение
таймаутов вместо диагностики: причина лишнего исчерпания бюджета устранена.

`failure_details`: profile/domain, стадия PLAN или OPEN, выбранный route, destination,
policy source, стабильный код, count/last_at. Typed relay rejection, upstream dial,
stream/ACK и authorization errors различаются; произвольные OS/server error strings,
URL/headers/токены не публикуются. `plan_duration_ms` / `open_duration_ms` в record
различают длительный поиск и реальный OPEN. Двойной `UPSTREAM_UPSTREAM_` исправлен.
128 агрегатов и 128 профилей bounded; loss и обрезка IPC явно указаны.

Исторические **35 UPSTREAM_OPEN_TIMEOUT / 3 UPSTREAM_OPEN_FAILED** владелец не
сохранил, после рестарта восстановить домены невозможно. Общий счётчик не доказывает,
что все они вызваны одним дефектом. Новая диагностика нужна для следующего короткого
прогона, без обещания Internet PASS.

`mtalk.google.com`, stats и update endpoints могут быть фоновыми запросами браузера.
CONNECTION_FAILED/NETWORK_TIMEOUT в **probe** могут относиться к альтернативному
маршруту и не быть итогом реального CONNECT. Это не «норма DIRECT», не доказательство
блокировки и не причина автоматически считать страницу failed. Ошибка фактического
OPEN/BLOCK, повторяемый отказ нужного ресурса и отсутствие ответа требуют проверки.
GUI пишет «Origin probe; результат страницы не измерен», сохраняет PAC records при
пустом native snapshot и не превращает native BLOCK в успешный RELAY_REQUIRED.

### Короткий ретест без закрытия браузеров

Обновить службу и GUI штатным блоком выше, сверить SHA256 службы. Chrome/Edge
оставить открытыми; service update может разорвать принадлежащие службе sockets.
Открыть новые вкладки ChatGPT/Claude/YouTube и обычного сайта, обновить их, затем
обычным PowerShell в `C:\VELIQ`:

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

Версия diag 2026-10-19.5: отдельные PAC/native clocks, ingress labels, counters,
Edge state и origin failures. Если есть только PAC OPEN, это PAC evidence, не native
PASS. Для native нужны запись `PAC_NATIVE_UPSTREAM` или `NATIVE_TCP` и actual OPEN,
затем обмен. Проверка PID/creation time остаётся; transient renderer может исчезнуть
без перезапуска browser main process. Не удалять PAC/профили ради теста, не нажимать
legacy PAC-кнопку, не запускать setup/enroll/VPS scripts и не коммитить diag-result.txt.

### Windows Firewall и native listener

Перехват SYN сам по себе не обходит Windows Firewall. На изолированном Windows CI
он блокировал отражённый SYN к внутреннему listener: upstream OPEN был успешным,
но не было SYN/ACK и байтов. Узкая admission TEST-NET/порт восстановила реальный
handshake; проверка Chrome требует тот же PID/creation, свежий HTTPS nonce и native
bidirectional bytes. Это отдельная причина от медленных network-provider запросов.
Первый эксперимент с program-scoped правилом из временной Go test-директории был
отвергнут Windows API (87), не доказал ничего и заменён контролируемой проверкой.

В обычном обновлении firewall не меняется скрыто. Параметр
`update-service.ps1 -NativeTcpFirewall` явно создаёт/проверяет локальное правило
`VELIQ-native-tcp-v1`: inbound TCP **только для полного пути установленного
veliq-service.exe**, все network profiles, edge traversal Block. Порт у
native listener динамический, поэтому правило привязано к EXE, а не к прежнему
порту. Оно не меняет outbound, UDP, игры, остальные EXE, настройки firewall или VPS.
GUI по-прежнему без elevation; обновление выполняет администратор прежнего owner SID.

Служба по-прежнему отбрасывает физический входящий трафик на внутренний listener;
accept принимает только exact mapping с virtual peer и immutable policy. Правило
не превращает listener в открытый прокси. После остановки службы listener закрыт.
Helper не трогает foreign rule/изменённую scope и проверяет effective ActiveStore;
GPO, запрещающая локальные inbound правила, не обходится. При ошибке обновления
новое owned правило удаляется, старый бинарник/ACL восстанавливаются. Уже имевшееся
проверенное правило сохраняется. Identity, IPC, сертификаты, профили и PAC не меняются.

Это opt-in prerequisite текущей native TCP reflection architecture. Fresh без
owned PAC всё ещё не активируется. Не удалять правило при активном native режиме:
для отката сначала вернуть прежний PAC-путь и бинарник штатным update workflow.
Только после такого отката, elevated owner PowerShell в C:\VELIQ:

```powershell
. .\tools\windows\native-tcp-firewall.ps1
Remove-NativeTcpFirewallAdmission "$env:ProgramData\VELIQ\veliq-service.exe"
```

Удаление тоже проверяет точный EXE и маркер владения; чужую политику не удаляет.
Контролируемые CI origins не являются Internet PASS и не заменяют короткий ретест
у владельца с уже открытыми Chrome/Edge.

## Cold-start retry и граница native-only (19.10.2026, код bc79d6c)

### Почему терялось первое соединение

После DIRECT_STALL CONNECT frontend закрывал kernel TCP socket, но native pipe
делал только half-close actual DIRECT upstream. Если origin молчал даже после FIN,
Engine сохранял ключ исходного потока. Повтор этого же CONNECT через relay получал
ErrFlowExists; новый запрос с новым tuple уже использовал кэш и проходил.
Это локальная ошибка lifecycle, не доказательство отказа VPS/билета/TLS.

Полный Close planned delegation теперь синхронно закрывает actual upstream и
освобождает ключ до relay retry. Проверяется exact generation; чужие, legacy и
уже заменённые потоки не закрываются. CloseWrite и existing TCP route pinning
сохранены. Оставшаяся локальная коллизия получает точный код
LOCAL_FLOW_RESERVATION_IN_USE вместо open_io_failed и не отравляет network cache.

Реальный Windows WinDivert тест воспроизводит старое поведение при уже применённом
production app-scoped firewall: kernel-only Close сохраняет ErrFlowExists.
После исправления пять холодных доменов (youtube/www.youtube/googlevideo/play.google/vk)
получают verified TLS+HTTP nonce через authenticated relay в исходном CONNECT,
без reconnect; следующие запросы relay-first, protected домен не идёт DIRECT.
Это изолированные контролируемые origins, не ISP PASS для перечисленных сайтов.

### Почему hybrid пока обязателен

Online PAC отправляет каждый origin в loopback CONNECT. Для настоящего native-only
браузер должен вместо CONNECT создать внешний TCP SYN, то есть PAC должен разрешить
DIRECT. Но при crash службы WinDivert снимается, а такой PAC останется разрешающим:
он больше не является fail-closed crash-guard. Inbound allow firewall — тоже не deny
guard. Поэтому весь native-only auto mode при единственном PAC guard **не активирован**.
Ни PAC, ни диалоги/legacy recovery не удалены; этап (в) не начат.

Безопасное дальнейшее направление — отдельный устойчивый fail-closed kernel/WFP
барьер для выбранного app+owner, действующий при падении routing worker и при boot,
с проверками crash/recovery/IPv6/QUIC. Неоднозначный ECH/coalesced поток остаётся
relay-only; уже установленные TCP не мигрируют. Простой watchdog, DNS-переключение
PAC или асинхронная запись реестра атомарной защиты не дают. Этот отдельный этап
не реализован и требует отдельного согласования.

### Что показывает diag 2026-10-19.6

- browser.native.status: native_only_state, native_only_auto_mode, отдельные
  native_only_totals / pac_native_upstream_totals и per-profile accepted/opened/failed,
  active, bidirectional_exchanges, bytes, first-open/exchange clocks.
- NATIVE_ONLY_OBSERVED появляется только после actual NATIVE_TCP с двусторонними
  байтами. PAC_NATIVE_UPSTREAM не может создать это доказательство. Для текущего
  hybrid ожидается NATIVE_ONLY_NOT_OBSERVED. Это не отказ работающего CONNECT.
- browser.native.firewall: read-only проверка службой фактического установленного
  EXE, owned PersistentStore/ActiveStore rule и GPO. APPLIED — правило реально
  подходит; ошибка/старый IPC = UNKNOWN, не MISSING и не ложный PASS.
  Диагностика сама ничего не добавляет/удаляет в firewall.
- Firewall помогает reflected SYN/ACK к listener. Если после ClientHello наступил
  DIRECT_STALL, это другая стадия: нельзя автоматически объяснять её отсутствием
  правила. Исправленная коллизия воспроизводилась при APPLIED.

Для повторной проверки оставить Chrome/Edge открытыми, закрыть только GUI и
обновить службу по блоку выше с -NativeTcpFirewall. Затем открыть/обновить вкладки
и в обычном owner PowerShell из C:\VELIQ выполнить:
`& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube`.
Состояние правила отдельно: `. .\tools\windows\common.ps1; Invoke-ServiceIPC 'browser.native.firewall'`.
Перезапуск службы прерывает её sockets; это не тест непрерывности во время enable.

## Relay-first подтверждённых групп и первый байт (19.10.2026)

### Что меняется после ea4afdf

Владелец подтвердил: сайты открываются, но 21 DIRECT_STALL на холодных соединениях
приводит к 21 ожиданию перед успешным relay retry. Исправление full Close убрало
потерю первого запроса, но само по себе не убирало эти ожидания.

- Подтверждение timeout-кэша раньше было в основном exact hostname; только
  googlevideo узлы делили запись. Теперь фиксированная группа `youtube-media`
  включает youtube.com, googlevideo.com, ytimg.com, ggpht.com и явные YouTube
  API/CDN aliases (youtube-nocookie, youtubei/youtube.googleapis, yt3.googleusercontent,
  wide-youtube/youtube-ui/ytimg.l.google.com и другие точные preset aliases).
  Это не wildcard для google.com/googleapis.com/googleusercontent.com вообще.
- Один фактический silent ClientHello в этой группе подтверждает relay-first для
  новых соединений её остальных имён на **той же сети, в том же профиле и порту**.
  Два разных отказавших DIRECT-адреса также сохраняют прежнюю timeout-семантику.
  У обычных сайтов остаётся собственный точный hostname и прежние критерии.
- Кэш проверяется до использования старого learned DIRECT и ещё раз непосредственно
  перед OPEN: устаревший план, подготовленный до stall соседнего имени, не должен
  снова открывать DIRECT. DNS/53, protected fail-closed, opaque relay-only,
  explicit rules и проверенный configured DIRECT+ сохраняются. Расширение relay
  группы не расширяет список доменов локальной DIRECT+ стратегии.
- Relay-first не делает никаких foreground DIRECT dial/probe. После 10 минут
  запускается не более одной фоновой перепроверки на ключ; весь пул probes по-прежнему
  4, собственный бюджет 3 с. Проверяется **отказавшее имя**, а не случайно здоровый
  член группы: свежий DNS, проверка сертификата/SNI и GET. Перед/после проверки
  подтверждается та же сеть/owner/Optimize. Неуверенный результат не разрешает DIRECT.
  Само истечение TTL не снимает verdict: нужен проверенный результат.
- Старые TCP не переводятся на другой egress. Первая неизвестная сеть с действительно
  пустым кэшем ещё требует первого доказательства; обещания «ноль первой задержки
  вообще на любой сети» нет. Автосидирования по ISP/IP и постоянного дискового кэша
  в этой итерации нет. После перезапуска службы volatile evidence собирается снова.

### Нагрузка и границы

Googlevideo: прежние **8** active tunnels на весь ПК (общие для Chrome/Edge),
не больше 32 waiters и не больше 2 с ожидания. По исчерпании — явная admission
ошибка, а не DIRECT bypass или девятый tunnel. Relay bytes/minute, active tunnels,
limit/admission counters по профилю/домену сохранены; session pool не расширен.
Групповое правило не создаёт новых неограниченных probes/workers.

8 на ПК не является глобальным лимитом для 36 ПК. Нагрузка/CPU production VPS
этой работой не измерялась; 1 vCPU остаётся риском при одновременном видео. Байты,
число туннелей и ошибки admission нужно оценивать вместе с коротким ретестом,
не объявлять «VPS выдерживает клуб» по локальным fixture результатам.

### Что измеряет diag 2026-10-19.7

Новые read-only IPC: `browser.first-byte` и `edge.first-byte`. Отдельный bounded
ответ нужен, чтобы optional timing summary не вытеснял routing evidence из
`browser.status`/`edge.status`. Старый IPC/нет samples не становятся нулевой задержкой.

Группировка: network + profile + family/exact host + port + PAC_CONNECT/PAC_RECOVERY
+ начальный режим DIRECT_FIRST / RELAY_FIRST / DIRECT_PLUS. Измеряется время от
accept TCP на frontend до первого **доставленного upstream байта**, включая lookup,
OPEN, admission и возможный начальный stall retry. Это может быть TLS ServerHello;
это не расшифрованный HTTP TTFB, не page-load PASS и не скорость скачивания в Мбит/с.
PAC_NATIVE_UPSTREAM не считается вторым запросом. Отдельного native-only ingress
эта итерация не создаёт; PAC/guard/этап (в) не меняются.

Диагностика показывает число replies, closed_without_reply, avg/min/max/last и
наблюдаемые before_direct_first_avg_ms / after_relay_first_avg_ms. До появления
обеих выборок — NOT_OBSERVED; нет данных старой сборки для выдуманного «до».
Сравнение относится к реально наблюдаемым соединениям, не контролируемому ISP A/B.
Леджер ограничен 128 сочетаниями; dropped samples и omitted rows видны отдельно.
Timeout-кэш показывает group, probe_host, network/profile/port и время recheck.

### Проверка с уже открытыми браузерами

Закрыть только GUI. Тем же owner SID обновить службу штатным блоком выше с
`-NativeTcpFirewall`; GUI в этой итерации не менялся. Chrome/Edge не закрывать,
PAC/профили/identity не удалять. Открыть/обновить YouTube, затем новое видео, и
из обычного owner PowerShell в C:\VELIQ выполнить:

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

При свежем процессе службы допустим один начальный stall для неизвестной группы
каждого профиля; следующие новые CDN-имена должны идти `direct_timeout_cache`
без DIRECT dial. Уже установленные до подтверждения TCP остаются pinned; их
первоначальные решения нельзя задним числом выдавать за relay-first. Смотреть
также googlevideo_active_tunnels<=8, admission failures, relay bytes/minute и
first-byte replies/no_reply. Полностью пустой кэш не означает подтверждённую блокировку.

Автотест с реальным WinDivert/QUIC+mTLS использует пустой кэш и контролируемую
блокировку DIRECT. Он проверяет verified TLS+HTTP nonce для семи имён; YouTube
семейство должно иметь ровно 1 DIRECT_FIRST и 9 RELAY_FIRST ответов, без DIRECT
открытий у новых sibling-имён, без failed retries/локальных коллизий и без утечек
protected. HTTP headers timing логируется отдельно от первого TLS байта.
Это автоматическая isolated acceptance, не доказательство ускорения у провайдера.

## Telegram/Anthropic relay-first и причины no_reply — diag .8 (20.10.2026)

Причина DIRECT_FIRST у `kws2/venus.web.telegram.org` и Claude: браузерные
поддомены попадали в обычный AUTO-подбор, хотя отдельный application preset
Telegram не является политикой каждого браузерного origin. Теперь при активном
browser AUTO точные группы `telegram.org`, `t.me`, `claude.ai`, `anthropic.com`,
`claudeusercontent.com`, `claude.com` (включая поддомены) сразу используют
RELAY_REQUIRED/VPS-01, источник `browser_known_relay_group`, probe
`KNOWN_RELAY_FIRST`. Прямой trial и DIRECT fallback отсутствуют. Learned DIRECT
и старый план нового OPEN не отменяют правило. Похожие имена другого домена
не совпадают. Обычные сайты сохраняют DIRECT_FIRST/быстрый stall retry;
YouTube имеет прежний отдельный learned family verdict. DNS/53 остаётся DIRECT.

На ошибке destination OPEN сохранено существующее bounded DNS recovery:
независимые кандидаты проверяются через authenticated relay, с настоящим SNI,
проверкой сертификата и HTTP GET. Auth/session failures не запускают recovery;
неудачная проверка не разрешает DIRECT. DNS recovery использует собственный
существующий лимит 2 workers/singleflight/cooldown; не занимает четыре обычных
AUTO probe slots. Иначе фоновые запросы Chrome могут заполнить все четыре слота,
и отказ destination OPEN останется без DNS recovery (обнаружено actual Chrome CI).
Это не обещание исправить любой сервер,
который принимает TCP, но выдаёт неверный TLS: приложение не replay-ится после
отправки его данных. TLS/owner-check, PAC, crash-guard и его список protected
origin не менялись; новых гарантий при выключенной оптимизации/crash не добавлено.

`browser.first-byte` / `edge.first-byte` теперь содержат bounded
`no_reply_reasons`, `no_reply_without_request_payload`,
`no_reply_with_request_payload`, `no_reply_origin_payload_seen`.
Причины снимаются **до нашей принудительной очистки**, без чтения TLS-содержимого:

- `CLIENT_CLOSED_BEFORE_REQUEST`: входной EOF без данных после CONNECT;
- `CLIENT_CLOSED_BEFORE_REPLY`: входной EOF после отправки данных;
- `TIMEOUT`: наблюдаемый timeout OPEN/планирования/I/O;
- `UPSTREAM_EOF[_WITHOUT_REQUEST]`, `UPSTREAM_ERROR`: закрытие/ошибка origin;
- `ORIGIN_DNS_FAILED`: планирование не смогло получить проверенный адрес;
- `CLIENT_INPUT_ERROR`, `CLIENT_DELIVERY_ERROR`, `SERVICE_STOP`,
  `LOCAL_CANCELLED_OR_CLOSED`, `GOOGLEVIDEO_ADMISSION`, `POLICY_OR_PLAN_FAILED`;
- `UNCLASSIFIED`: причина не доказана; старые счётчики в diag —
  `UNCLASSIFIED_LEGACY`, без придуманной реконструкции.

EOF может быть half-close, а не полное закрытие вкладки. Отсутствие request
payload — лишь **кандидат на preconnect**, не доказательство его безвредности.
Ответ origin, который не удалось доставить клиенту, выделяется origin_payload_seen.
Ошибки не превращаются в нулевую задержку/PASS. Старые 34 no_reply невозможно
разделить задним числом: нужен свежий короткий прогон. Если соединение ещё активно,
оно ещё не входит в счётчик завершённых без ответа. Измеряется транспортный первый
байт (включая TLS), не успешная загрузка страницы/видео.

Diag `2026-10-19.8` показывает причины и before/after отдельно по telegram,
anthropic, youtube-media, сети, профилю, порту и пути. Нет выборки — NOT_OBSERVED.
Лимит googlevideo 8/32 waiters/2 с, байты в минуту и routing evidence сохранены.
Для сравнения открыть новые вкладки Telegram Web, Claude и видео YouTube при
выключенном VPN, затем обычный owner PowerShell в C:\VELIQ:

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

Internet/ISP PASS, объяснение всех старых no_reply и ускорение у владельца
по CI/изолированным тестам не заявляются. Никаких действий на VPS не требуется.
