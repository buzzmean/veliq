# Скорость видеотуннелей: 23.10.2026

Владелец подтвердил 1bb001f: все запросы Chrome 200/204, admission_failures=0,
но медленный старт и рывки первую минуту; VPS CPU2.5–8%, drops0. Это подтверждает
доступность, но не достаточную скорость доставки сегментов и не скорость декодера.
Старт2–3с и1080p без рывков пока **не подтверждены**. На VPS ничего не запускалось.

## Найдено и исправлено

`core/transport/tls.go`: ранее приём QUIC ограничивался initial64KiB/max256KiB на
stream и initial256KiB/max1MiB на всю сессию. На60msRTT грубый верхний предел
window/RTT —35Мбит/с на поток и140Мбит/с суммарно; фактический ниже из-за RTT
обновления кредита, congestion control, потерь и планирования. CPU может оставаться
низким при ожидании кредита. Это реальное ограничение кода, но **не доказанная
единственная причина** наблюдаемых2fps.

Только клиентский receive config: initial256KiB/max2MiB на stream,
initial1MiB/max8MiB на сессию. Окна растут по потреблению, не выделяются заранее.
Пул максимум8сессий ограничивает авторизованный outstanding stream payload64MiB
на ПК; это не потолок всей памяти процесса/драйвера/метаданных. Server receive
config остался прежним. Лимиты8×48/probe reserve, admission video12/other4,
TLS/mTLS/tickets/30мин lease renewal, QUIC congestion control и UDP не изменены.
**Деплой VPS для изменения download receive credit не нужен.**

Реальный локальный relay с mTLS, TCP-origin и user-space UDP delay bridge:
30ms в каждую сторону, nominal100Mbit/s pacing, без намеренных потерь. Payload
8.4MB/stream, SHA256 обязателен, сначала1, потом4stream на том же QUIC connection.
Контрольный `-race` прогон:

| Метрика | Старый клиент | Новый клиент |
|---|---:|---:|
| Cold mTLS handshake | 87ms | 86ms |
| OPEN одиночного потока | 69ms | 68ms |
| Первый wire byte от OPEN admission | 133ms | 152ms |
| Одиночный download | 23.4Mbit/s,2.87s | 55.0Mbit/s,1.22s |
| Четыре stream суммарно | 65.6Mbit/s | 68.1Mbit/s |

Без race в двух прогонах одиночный старый21–25, новый50–62Mbit/s. Параллельные
результаты сильно колебались (в отдельных прогонах12–18 против88–92Mbit/s).
User-space timers, UDP socket queues, host scheduling и congestion/loss recovery
не дают точного эмулятора сети. Первый unpaced эксперимент также дал деградацию
параллельного нового окна; поэтому стенд получил bounded queues/socket buffers и
pacing. Это не Windows/ISP/YouTube benchmark. Скорость не используется как flaky
PASS-порог CI: проверяется целостность и завершение каждого установленного потока.
Увеличенное окно помогает одиночной передаче; OPEN/TLS RTT оно не устраняет.

## Остальная проверенная цепочка

- `Pool.Warm` уже создаёт reusable QUIC session с mTLS/fresh one-shot ticket.
  Для нового TCP открывается stream, отправляется OPEN, relay делает TCP Dial,
  затем ACK. Новая сессия создаётся только по capacity/замене, не для каждого видео.
- `relay.pool.diagnostics.recent_opens`: `acquire_ms` включает ожидание пула и
  создание/авторизацию новой сессии; `stream_open_ms` включает OPEN round trip и
  upstream TCP connect. `duration_ms` — сумма этапов/локальных накладных расходов,
  `session_id`/`session_age_ms` позволяют увидеть reuse. При retry времена суммируются,
  возраст/ID относятся к последней выбранной сессии. Отдельное VPS TCP время без
  wire/server instrumentation не измеряется; не приписывать весь OPEN сети до origin.
- Relay TCP `io.Copy` и native reflection copy используют32KiB буферы, без
  искусственной sleep/rate limit на TCP; TCP sockets Go используют NoDelay и
  OS auto-tuning. Ограничения UDP packets/s не применяются к TCP media. Не стали
  вслепую фиксировать огромные socket buffers или менять MTU/MSS.
- Admission video12/queue24/wait2s остаётся bounded, отдельно от Google4. Ожидание
  видно по каждому потоку. Нулевые failures сами по себе не доказывают нулевой wait.
- Активный video idle20s, до первого IO3s, other10s сохранены. Они не обрывают
  активно передающий поток. `IDLE_CLOSED` позволяет отличить reclaim preconnect от
  transport failure. Если idle_closed растёт при реальном видео — нужен timeline.
- Уже открытый HTTP/2/TLS туннель переиспользует сам браузер. VELIQ не может
  назначить готовый upstream TCP другому ClientHello: это нарушит TLS и семантику
  соединения. Установленные потоки не мигрируют и не replay.

## Измерения на ПК

`browser.native.status.relay_usage.video_connections`:128bounded записей,
24в ответе с приоритетом живых потоков, `video_connections_omitted` явно считает
непоказанные/вытесненные. Общий native IPC budget60KiB/PAC57KB может дополнительно обрезать ответ.
Это googlevideo TCP native/PAC upstream, не DoH/probes, не HTTPS payload contents.

- `started` — перед video admission, **после** route/domain planning, не момент
  клика по видео/SYN. `admission_ms`, `relay_open_ms`, `first_byte_ms` от этой точки.
- `write_to_first_byte_ms` — от первого фактически завершившегося Write до Read.
- `received_bytes`, `sent_bytes` — только реально переданные байты; TLS включён.
- `average_receive_mbps` — rx/(время от started до snapshot/close), включая idle.
- `receive_span_mbps` — последующие rx/(last_read-first_read), без первой порции,
  с межчтительными паузами. Не peak speed и не HTTP request rate.
- `max_read_gap_ms` может быть нормальным HTTP/2 prefetch idle; сам по себе не
  является buffering. TLS ServerHello тоже первый байт; здесь нет HTTP/segment/FPS proof.
- -1/UNINSTRUMENTED означает отсутствие измерения. Одна TLS alert не видео PASS.

`observe-video-relay.ps1`120s даёт CSV по секундам: interval delta Mbps, средняя
скорость, TTFB, OPEN и паузы каждого видеосоединения. Первый sample — BASELINE
(-1), старые байты не считаются новой скоростью; counter reset выделен, без fake
throughput. Не больше24строк/sample,4320строк,256baseline keys. Скрипт только
читает IPC, не управляет браузером/службой/политиками и не ходит на VPS. CSV
пишется в `bin/diagnostics/video-relay.csv`; не коммитить и не публиковать сырые логи.

Диагностика `.3`, `-Only browser,youtube` дополнительно печатает pool OPEN phases.
Большой `acquire` → pool/ticket/session wait; большой `admission` → video slot;
большой `write_to_first_byte` → origin/relay/TLS initial path; низкий sustained rx
или большой gap → требуется сопоставить с запросами сегментов/плеером. Если сегменты
приходят быстрее потребления, а FPS низкий — транспорт не доказывает проблему
декодера/GPU; HTTP200 и wire Mbps не заменяют эти измерения.

## Обновление владельцем (браузеры оставить открытыми)

PowerShell администратора под владельцем установки, из своего клона репозитория.
GUI не менялся: .NET rebuild/install-desktop не нужен. Команды по одной:

```powershell
git pull --ff-only origin main
```

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase baseline
```

```powershell
& .\tools\windows\Close-VeliqGuiForUpdate.ps1
```

```powershell
& .\tools\windows\build-e2e.ps1 -DriverDirectory "$env:ProgramData\neexitlag\driver"
```

Только после успешной сборки (в том числе WINDIVERT_FILTERS_PASS):

```powershell
& .\tools\windows\update-service.ps1
```

```powershell
(Get-FileHash .\bin\windows-e2e\neexitlag-service.exe).Hash -eq (Get-FileHash "$env:ProgramData\neexitlag\neexitlag-service.exe").Hash
```

Ожидается True. Обновление службы пересоздаёт её транспортные сессии; browser
процессы/окна не закрываются. Изменения receive credit применяются к новым QUIC
sessions; к уже существующей до обновления сессии новые окна не приписываем.

```powershell
Start-Process "$env:LOCALAPPDATA\Programs\VELIQ\VELIQ.exe"
```

```powershell
. .\tools\windows\common.ps1
```

```powershell
Invoke-ServiceIPC 'status' | Select-Object build,connected,optimizing,capture_active,connection_reason
```

Новый build, True/True/True и READY. Начать наблюдение **до открытия нового видео**:

```powershell
& .\tools\windows\observe-video-relay.ps1 -DurationSeconds 120
```

В уже открытом Chrome запустить1080p, измерить фактический старт и проиграть2мин
с перемоткой. После наблюдения:

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

```powershell
Invoke-ServiceIPC 'relay.pool.diagnostics' @{relay_id='VPS-01'} | Select-Object active_sessions,waiting_opens,open_failures,recent_opens | ConvertTo-Json -Depth 6
```

Проверить zero video admission failures и маршруты googlevideo RELAY_REQUIRED,
VK/google.com DIRECT, как в docs/YOUTUBE_RELAY_ADMISSION.md. Для read-only top/
ss/существующих metrics VPS команды остаются в том документе; они не запускались.
Нужны новый CSV и фактическое наблюдение старта/рывков, не только средний rx за минуту.

Дополнительный **read-only** снимок TCP leg VPS→CDN, только если владелец решит
выполнить во время воспроизведения (не выполнялся):

```powershell
ssh root@2.56.177.4 'ss -tinm state established "( dport = :443 )"'
```

Сопоставить peer IP с video destination: Recv-Q/skmem r/rb, bytes_received,
rtt/retrans. Большая очередь при медленном downstream может указывать на
backpressure. TCP cwnd здесь принадлежит исходящему TCP VPS, **не** QUIC к ПК и
**не** удалённому CDN sender; kernel `ss` не показывает congestion state QUIC-go.
VPS packet_drops=0 также не доказывает отсутствие QUIC retransmission/ISP loss.
Никакие sysctl/socket/MTU настройки этой командой не меняются.

## Воспроизводимость

```text
GOMAXPROCS=2 go test -race -p 1 ./core/transport ./tests/integration -run 'Test(DownloadCredit|RelayBulk|PoolBulk)' -v -count=1
```

Работает без VPS/root/network emulation privileges/новых зависимостей. Проверяет
старые server receive defaults против обоих клиентов, mTLS, целостность SHA256,
параллельность и reuse authenticated fresh-ticket pool. Отдельные security/lease/
replay/admission/игровые regression tests остаются в полном Go race suite.
Native Windows/WinDivert/ISP/плеер/1080p/36PC этим прогоном не подтверждены.

PS regression: `tests/windows-tools/video-relay-observer-checks.ps1` выполняет
настоящий10сек цикл/export/StrictMode с fake IPC в изолированной временной папке;
никаких installation/owner process/VPS действий. В Verify добавлен запуск на PS7
и Windows PowerShell5.1. Локально выполнено на PS7; PS5.1 требует Windows runner.

## Состояние проверок

Полные Go race прогоны перед заключительной правкой диагностической классификации
проходили. В поздних повторах есть deadline25s FAIL в существующем
`TestRealDemoHTTPMeasurementsAndFailover`: ожидание primary/backup. Отдельно на новом
коде3/3 PASS. На исходном1bb001f (detached временный checkout, без новых изменений)
`go test -race -p 1 ./tools/demo -count=3` также FAIL: один из3упёрся в общий
context deadline на diagnostics HTTP, остальные2прошли. Поэтому это воспроизводимая
нестабильность baseline demo-фикстуры, не доказательство регресса новых окон;
её тайм-аут/порог/production failover не менялись. Не представлять suite как
безусловно стабильный. Итог последнего полного прогона записан в CURRENT.md.

Новые bulk/window/security, service video metrics/admission/IPC tests с race PASS,
PS7 pure/main-loop fixtures PASS; Linux/Windows vet/build PASS. Девять выбранных
Windows service EXE unit tests PASS под Wine10 — не native Windows kernel/PS5.1.
C#/WPF не менялись и в этой итерации не пересобирались. GitHub Verify на f107204
run39985233531: core/windows failure, steps=[]; выполнение не началось (ранее
владельцем подтверждён account billing gate, новую annotation отдельно не читали).
Это не CI PASS и не ошибка загрузки артефактов.
