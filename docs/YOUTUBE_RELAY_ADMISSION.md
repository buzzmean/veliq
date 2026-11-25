# YouTube: SNI-selective DIRECT и отдельный video admission

## Причина 305e2fd

Shared8 позволял opaque Google занять7мест и оставить1под googlevideo.
Двухсекундная очередь уже существовала: она заканчивалась ошибкой, пока старые
opaque sockets держали permits. Native failure mapper скрывал эту локальную
причину за open_io_failed. TLS www.google.com на том жеIP не опровергает SNI
блокировку www.youtube.com. Данные владельца — доказательство именно этого
провайдера; универсальная блокировка Google не утверждается.

## Новый бюджет на один ПК

| Назначение | Активные | Ожидающие | Максимум ожидания | Idle после I/O |
|---|---:|---:|---:|---:|
| Известный googlevideo | 12 | 24 | 2с | 20с |
| Прочий relay Google/opaque | 4 | 8 | 1с | 10с |

Chrome и Edge используют общий бюджет ПК, но **разные video/other pools**.
Пример исходного расчёта12: две медиадорожки × два параллельных запроса =4,
столько же replacement/preload при перемотке =4, ещё4для разных CDN connections
и startup jitter. HTTP/2 может уложить много запросов в один TCP, поэтому это
запас соединений, не число сегментов и не подтверждённый оптимум плеера. Предел
выбран консервативно; нужен двухминутный ретест, а не обещание Internet PASS.

Для двух ограничиваемых классов максимум16relay-туннелей ПК, очередь32.
Это не общий предел ВСЕГО relay-трафика: protected control/API (YouTube API,
ytimg/ggpht, OpenAI и др.) сохраняют отдельный существующий глобальный bounded
QUIC transport8×48/probe reserve. Их нельзя вытеснять ordinary opaque-потоками.
Ordinary otherGoogle budget относится к AUTO webTCP443, не mtalk/push5228 и не
явному MANUAL browser profile. Lease/mTLS не меняются.
До первого I/O idle3с; затем активность Read/Write продлевает срок. Idle closes
освобождают permits ровно один раз и учитываются отдельно; Read возвращает EOF
для scheduled local idle close, не generic relay session failure. Активный
обмен не закрывается таймером; устаревшие timer callbacks отсечены поколением.

При нормальной очереди ждём слот. При timeout/full protected origin остаётся
fail-closed с GOOGLEVIDEO_RELAY_ADMISSION_CAPACITY. Бесконечно держать очередь
нельзя. Отмены вкладок имеют отдельный canceled counter, не admission_failures.
Обычный AUTO origin при local/stream-capacity OPEN failure получает новый DIRECT
plan **до записи payload**. Реальный маршрут виден в native/PAC evidence как
browser_ordinary_capacity_direct. OpenAI/YouTube/Telegram/Anthropic, knownDoH,
protected DNS ambiguity, explicit RELAY_REQUIRED/BLOCK не могут так откатиться.
Неизвестный hidden domain сохраняет ранее утверждённое DIRECT-default ограничение.
Никакого replay/migration established TCP и никакого скрытого DIRECT под RELAY label.

## Нагрузка VPS (C)

VPS1vCPU/2GB: больший предел не увеличивает CPU/полосу сервера. На36ПК потолок этих двух
классов —576TCP streams; protected API/прочие приложения добавляют свой трафик
в рамках существующего transport cap. Обычное воспроизведение использует меньше.
Например,8Мбит/с видео ×36 =288Мбит/с payload плюс QUIC/TLS overhead; это расчёт,
не измеренная скорость. Одно ядро может стать пределом раньше порта1Гбит/с.
Пилот: сначала1ПК, затем2–3, затем постепенно36; при постоянной загрузке ядра
около85–90%, росте reject/drop или buffering не объявлять пилот успешным и не
поднимать лимиты вслепую. Production не проверялся и не менялся.

PowerShell владельца: следующие команды **только читают** VPS. Запускать во время
видео. Пароль вводится только в SSH; не вставлять в команду/чат.

```powershell
ssh root@2.56.177.4 'top -b -d 2 -n 3 -w 120'
```

```powershell
ssh root@2.56.177.4 'systemctl show neexitlag-relay.service -p ActiveState -p MainPID -p CPUUsageNSec -p MemoryCurrent -p TasksCurrent -p NRestarts'
```

```powershell
ssh root@2.56.177.4 'curl --fail --silent --show-error --max-time 3 http://127.0.0.1:9090/metrics'
```

Нужны neexitlag_active_sessions/active_flows, rx/tx_bytes_total, rejected_flows,
packet_drops/auth_failures. Два снимка bytes за60с показывают реальную payload
скорость; sessions не равны UDP sockets и не равны TCP connections.

```powershell
ssh root@2.56.177.4 'ss -s'
```

```powershell
ssh root@2.56.177.4 'ss -u -a -n sport = :4433'
```

9090 — существующий loopback metrics default; если порт отличается, не менять
конфигурацию/firewall и не выводить содержимое credentials/env. Попросить владельца
указать существующий metrics endpoint. Ни одна команда не перезапускает службы.

## Диагностика клиента

Версия diag-no-vpn.ps1 2026-10-23.2: admission_scope, video12/other4,
video/opaque waiters, failures vs canceled, total/max wait, idle_closed, ordinary
DIRECT fallback attempts, байты/минуту по домену/профилю. Raw opaque admission
failures могут завершиться рабочим DIRECT fallback и не равны video failures.
Counter попыток fallback не доказывает успешный DIRECT — проверять actual flow bytes.
Legacy googlevideo_shared_limit_active теперь video-only compatibility field;
google_admission_total_active показывает сумму, общего shared capacity больше нет.
Старые8и shared описания в предыдущих отчётах — история, не текущая архитектура.

## Проверки и ограничения

Детерминированные fixtures: opaque4полностью занят, video12принимает потоки и
ещё4ждут завершения сегментов, без capacity failure; idle/preconnect reclaim,
повторное Close, отмена, hard cap, активность и stale timer generation; ordinary
Google hints vs shared-IP SNI failures; защищённые/explicit правила не понижаются;
ошибка OPEN до payload возвращает настоящий DIRECT plan обычному origin.
Это не проверка YouTube/player/Windows kernel или нагрузки36клубныхПК.

## D. Обновление и двухминутная приёмка владельца

Из клона main, PowerShell администратора под владельцем установки; Chrome и
Edge оставить открытыми. GUI не менялся — build-desktop/install-desktop не нужны.

```powershell
git pull --ff-only origin main
```

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase baseline
```

Закрывается только старый GUI/recovery helper, не браузеры:

```powershell
& .\tools\windows\Close-VeliqGuiForUpdate.ps1
```

```powershell
& .\tools\windows\build-e2e.ps1 -DriverDirectory "$env:ProgramData\VELIQ\driver"
```

Обязателен WINDIVERT_FILTERS_PASS, далее успешный конец build-e2e. PS5.1 dotted
-test flags теперь quoted; old/partial generated binaries удаляются в начале и
при ошибке. Если сборка не прошла, update-service не запускать. Установленная
служба/identity/config во время сборки не удаляются.

```powershell
& .\tools\windows\update-service.ps1
```

```powershell
(Get-FileHash .\bin\windows-e2e\veliq-service.exe).Hash -eq (Get-FileHash "$env:ProgramData\VELIQ\veliq-service.exe").Hash
```

Ожидается True. Запуск имеющегося GUI:

```powershell
Start-Process "$env:LOCALAPPDATA\Programs\VELIQ\VELIQ.exe"
```

```powershell
. .\tools\windows\common.ps1
```

```powershell
Invoke-ServiceIPC 'status' | Select-Object build,connected,optimizing,capture_active,connection_reason
```

Нужны новый build, True/True/True, READY. Не закрывать браузеры и не менять PAC.

```powershell
& .\tools\windows\test-browser-dns.ps1 -DurationSeconds 120 -RequireGoogleDirect
```

Пока идёт наблюдение120с: в уже открытом Chrome открыть YouTube, воспроизвести
видео2мин и сделать несколько перемоток; также открыть vk.ru, google.com и
chromewebstore.google.com. Не сбрасывать браузер/правила. Требуются:

- Видео действительно играет без чёрного экрана/остановок (наблюдение владельца).
- Известный googlevideo имеет native RELAY_REQUIRED/VPS-01, TLS ServerHello и
  свежие payload bytes; VK и обычный Google имеют DIRECT.
- VIDEO_ADMISSION failures_delta=0; dedicated_limit=12, other_google_limit=4,
  scope=DEDICATED_GOOGLEVIDEO_12_PLUS_OTHER_GOOGLE_4.
- Все три маршрута подтверждаются для одного Chrome profile, не смешением
  записей разных браузеров.
- Основные PID/birth Chrome/Edge и процесс службы не менялись. Старый HTTP/2 не
  мигрирует: скрипт может учитывать свежий обмен уже существующего потока по delta.

Скрипт НЕ управляет плеером и не читает страницу. Его положительный verdict —
TRANSPORT_ROUTES_OBSERVED_PAGE_NOT_VERIFIED, не автоматический playback/Internet
PASS. Старые cumulative bytes, opaque Google,5-byte alert, counter reset или
legacy shared pool не дают ложного подтверждения. Bounded retained records/lost
показаны; полный global no-leak proof по этой выборке не заявляется.

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

После теста при необходимости обычная проверка отключения/выхода:

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase ready
```

Выключить оптимизацию в GUI, открыть новую vk.ru вкладку:

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase disabled
```

«Выход» из трея, снова новая vk.ru вкладка:

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase exit
```

Все ручные действия с браузером — только вкладки/плеер; без restart/policy reload.
Клиентское обновление не требует VPS deployment. На настоящем Windows/PS5.1/ISP
эти изменения не проверены; итог приёмки должен дать владелец.
