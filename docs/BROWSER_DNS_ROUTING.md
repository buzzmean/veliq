# DNS и непрозрачные browser flows

## A. Собственные DNS-сокеты Chrome/Edge

Для выбранного AUTO/native Chrome/Edge IPv4 UDP/TCP к порту 53 (включая
loopback) обслуживает служба. PID/birth/path/SID/profile/network перепроверяются
для каждой транзакции. Другие процессы, DNS Client Windows (`svchost.exe`), игры,
режим DIRECT и выключенная оптимизация сохраняют исходный путь.

Для YouTube/googlevideo/ytimg/ggpht, Telegram, Anthropic и OpenAI запрос идёт
по HTTPS DoH через существующий authenticated VPS transport. Серверу не нужны
новые программы или конфигурация. DNS/53 через VPS не пересылается; проверка
TLS DoH не отключается. Для остальных имён сохраняется исходный DNS-резолвер
и протокол запроса. Не меняются настройки DNS Windows/браузера.

Один IN-вопрос, не AXFR/IXFR/ANY; 8KiB максимальное сообщение; 16 одновременных
UDP-обработчиков и TCP DNS streams; 16 транзакций, без неограниченной очереди;
2с бюджет транзакции. Переполнение/отказ protected DoH даёт SERVFAIL, без DIRECT
DNS fallback. UDP учитывает EDNS (512..1232 байта), большие ответы возвращают
TC для повторения через TCP. TCP ограничен 64 запросами/5с простоя.

Ответ сохраняет A/AAAA/HTTPS/SVCB/DNSSEC; ECH-параметры не удаляются. Проверяются
ID/question/класс/CNAME; HTTP Age вычитается из TTL. Только фактически выданные
A/AAAA дают подсказки (network, profile, IP) с TTL не дольше ответа/5мин.
1024 адреса, до 8 имён на адрес. Совпавшие shared IP остаются неоднозначными;
наличие protected имени разрешает только ужесточить маршрут. Подсказка DNS не
выдаётся за доказанный внутренний ECH SNI. Обновление системного DNS-cache
не стирает browser-scoped ответы.

## Ограничения, которые нельзя скрывать

- Трафик Windows DNS Client нельзя надёжно приписать вызывающему браузеру
  только по PID сокета `svchost`. Он не перенаправляется целиком.
- HTTPS DoH шифрует вопрос и ответ. Без MITM их нельзя прочитать из TCP-потока.
- Скрытый домен на shared IP нельзя доказать по одной принадлежности адреса.
- Уже открытые TCP не переезжают; браузерные соединения и процессы не убиваются.
- IPv6 browser interception остаётся в прежнем режиме ограничений; эта DNS
  реализация обслуживает IPv4 сокеты. Нельзя заявлять полное владение DNS.

## Проверки

Проверяются TLS DoH с правильным/чужим CA, A/AAAA/HTTPS/SVCB, ID и CNAME/TTL,
UDP TC/TCP framing/cancellation, scoped hints и их ограничение, protected без
plaintext fallback, ordinary DNS и disabled/unselected без перехвата.
Windows packetWriter fixture проверяет построение ответа и отказ при saturation.
Все фильтры дополнительно проверены настоящим pinned DLL под Wine. Это не
проверка WinDivert kernel на Windows и не Internet/YouTube PASS.

## B. Secure DNS браузера

Выбран безопасный резерв B: **известные DoH endpoints — RELAY_REQUIRED**, без
DIRECT fallback, без намеренных RST и без подмены DNS-провайдера пользователя.
Тихо и надёжно определить automatic/secure-only режим работающего браузера
по зашифрованному сокету нельзя. Блокировка DoH не гарантирует откат на DNS/53
и способна сломать secure-only. Поэтому откат браузера НЕ объявляется доказанным.
DNS/53, если браузер его использует, обслуживается этапом A; существующие TCP
DoH не мигрируют. Новые известные DoH идут через relay в том же браузере.

Список — адреса/имена провайдеров из Chromium `net/dns/public/doh_provider_entry.cc`,
снимок 23.10.2026, SHA256 `cd0c73995ebe946154fb44ddbff4237bab378ac8329d52e5561f74b45ee689bf`,
и стандартные Cloudflare/NextDNS aliases. Только точные IP и hostname, TCP/443;
не весь CDN/ASN. IPv6 остаётся под существующим selected-browser IPv6 guard,
IPv6 relay support не заявляется. Чужие приложения и выключенная оптимизация
сохраняют обычный путь. Explicit BLOCK сохраняется; DIRECT правило не разрешает
обход этого известного resolver endpoint.

Custom DoH на неизвестном shared IP с ECH нельзя надёжно узнать без расшифровки
или настройки браузера. Ответы транзитного DoH не читаются, их TTL/имена не
выдумываются. Это ограничение явно остаётся; C наблюдает реальные DIRECT failures.

## C. Реальный отказ непрозрачного DIRECT

Старый кэш запоминал только точный (сеть, профиль, IP:порт), поэтому очередной
адрес Google обходил прошлый отказ. Первый TLS alert/даже заголовок в 5 байт
останавливал наблюдение как «ответ». Ошибка первого Write с n=0 не записывала
отказ. Callback публиковался после закрытия, что позволяло reconnect обогнать его.

Теперь TLS-flow ждёт пассивно наблюдаемый полный ServerHello (не TCP ACK).
Silent/incomplete handshake: бюджет 1200мс после успешной записи; ранний
EOF/RST/alert/неверный TLS или Write failure — точный failure_reason. Кэш
публикуется до нашего закрытия. Preconnect без данных, явное закрытие владельцем,
здоровый ServerHello и короткий polling timeout не дают ложного failure.
Запись/ответ не меняются и не воспроизводятся на другом egress.

Для ограниченного каталога Google IPv4 service ranges два разных DIRECT
TCP443 отказа за 10с включают relay-first на 2мин только для той же пары
(network, browser profile). TLS failures и реальные TCP-open failures учитываются;
один IP, UDP/53/5228, DNS/owner errors — не доказательство блокировки всей группы.
Каталог сам по себе не выбирает relay и не доказывает домен. Никакого
переписывания назначения/SNI по принадлежности сети. Максимум 64 scoped groups;
точные endpoint failures остаются отдельно (256 записей). VK/Яндекс не входят.

Opaque Google recovery делит прежние 8 admission slots с известным googlevideo,
32 waiters/2с; очереди не расширяются и DIRECT fallback не добавляется.
`googlevideo_active_tunnels` считает только известные video origins;
`opaque_google_active_tunnels` — неизвестные домены Google;
`googlevideo_shared_limit_active` — их общую загрузку. Ноль известного googlevideo
не доказывает отсутствие видео в opaque relay. Реальная приёмка должна показать
hostname evidence; без него результат по googlevideo — UNKNOWN, не PASS.

## D. DIRECT для обычных сайтов и диагностика

При известных DNS-подсказках VK/Яндекс остаются DIRECT. При неизвестном домене
они также не наследуют Google failure group. Неизбранные процессы и игры,
выключенная оптимизация и DNS чужого процесса не получают browser DNS handler.
Поздний callback закрываемого flow не обучает кэш после выключения или смены сети.

`diag-no-vpn.ps1 -Only browser,youtube`, версия 2026-10-23.1, отдельно показывает:
`browser DNS broker`, пути `AUTHENTICATED_RELAY_DOH`/`SYSTEM_DNS`, типы запросов,
количество выданных подсказок; до16 активных profile/network/IP/domain/expiry
подсказок и число пропущенных строк; реальную причину/состояние Google failures;
раздельные known-googlevideo/opaque-Google admissions и общий прежний предел8.
Старый сервис/отсутствующие поля помечаются UNINSTRUMENTED. Вывод не содержит
содержимого DNS/TLS, токенов или ключей. DNS/bytes не объявляются страницей PASS.

## E. Обновление и приёмка на ПК владельца

Все команды ниже по одной, из своего клона `main`, PowerShell
администратора под тем же пользователем установки. Chrome/Edge оставлять открытыми.
VPS, enroll, CA и сертификаты не обновлять. GUI-код не менялся, его пересборка и
повторная установка для этого исправления не нужны.

1. Получить клиент:

```powershell
git pull --ff-only origin main
```

2. Зафиксировать уже открытые основные процессы Chrome/Edge (PID/birth/path,
без командной строки или содержимого вкладок):

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase baseline
```

3. Закрыть только старый GUI/recovery helper для обновления:

```powershell
& .\tools\windows\Close-VeliqGuiForUpdate.ps1
```

4. Пересобрать службу и тесты; должен быть `WINDIVERT_FILTERS_PASS` от настоящего
pinned DLL. Команда ничего не развёртывает на VPS:

```powershell
& .\tools\windows\build-e2e.ps1 -DriverDirectory "$env:ProgramData\VELIQ\driver"
```

5. Обновить установленную службу с сохранением identity/config/profiles:

```powershell
& .\tools\windows\update-service.ps1
```

6. Проверить копирование бинарника:

```powershell
(Get-FileHash .\bin\windows-e2e\veliq-service.exe).Hash -eq (Get-FileHash "$env:ProgramData\VELIQ\veliq-service.exe").Hash
```

Ожидается `True`. Запустить установленный GUI:

```powershell
Start-Process "$env:LOCALAPPDATA\Programs\VELIQ\VELIQ.exe"
```

7. Подключить read-only IPC:

```powershell
. .\tools\windows\common.ps1
```

```powershell
Invoke-ServiceIPC 'status' | Select-Object build,connected,optimizing,capture_active,connection_reason
```

Нужны актуальный build, `True/True/True`, `READY`. Нажатия технических PAC-кнопок,
policy reload или перезапуска браузеров не требуется.

8. Запустить наблюдение; за эти90с в новых вкладках уже открытых Chrome/Edge
открыть YouTube, проиграть и перемотать видео, открыть vk.ru:

```powershell
& .\tools\windows\test-browser-dns.ps1 -DurationSeconds 90
```

`TRANSPORT_ROUTES_OBSERVED_PAGE_NOT_VERIFIED` означает новые native flows с
именем googlevideo, RELAY_REQUIRED/VPS-01 и ответом ServerHello/bytes, плюс VK
DIRECT, при неизменных основных PID/birth. Это доказательство наблюдённых маршрутов,
не автоматическая проверка страницы/видео и не полный аудит отсутствия утечек:
ledger ограничен, retained_records_lost_delta выводится. Браузер может повторно
использовать старый HTTP/2 stream; существующие TCP остаются PINNED_UNTIL_CLOSED.
Если TLS скрыт и нет DNS hints, `GOOGLEVIDEO_HOSTNAME_EXCHANGE_NOT_OBSERVED` —
честно неподтверждённое имя, а не выдуманный video PASS. Если исходные браузерные
PID изменились, скрипт отказывает. `PROTECTED_DIRECT_OBSERVED` требует расследования.
На фоне shared IP защищённая подсказка только ужесточает маршрут.

9. Собрать подробности (файл диагностики не коммитить и секреты не присылать):

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

Важны browser DNS paths/TTL, `DIRECT_TLS_*`, `opaque Google recovery`, known/opaque
shared admissions и native routes. Диагностический скрипт также делает отдельные
DNS/TLS/headless-контроли; они не доказывают работу уже открытых окон и могут не
повторять их Secure DNS/ECH. Ноль DNS broker queries может означать svchost/DoH,
не отсутствие DNS вообще. Known DoH relay не раскрывает имена DNS-ответов.

10. После успешной проверки native в обоих браузерах сохранить штатный baseline
для выключения/выхода:

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase ready
```

Выключить оптимизацию в GUI и открыть **новую** вкладку vk.ru без policy reload:

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase disabled
```

Затем «Выход» из трея и снова новая вкладка vk.ru:

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase exit
```

Структурные проверки не заменяют результат загрузки страницы у провайдера.
Настройки DNS/PAC/службы приёмочный DNS-скрипт не меняет. Не закрывает браузеры,
не чистит их профиль/кэш и не запускает команды на VPS.

## Итог проверки разработки

Go unit/race fixtures и DLL parsing не доказывают реальный Windows kernel capture,
поведение Secure DNS/ECH конкретной версии Chrome/Edge и доступность YouTube у
провайдера. До приёмки владельца это остаётся **НЕ ПРОВЕРЕНО**. Не обещается полный
контроль DNS Client Windows/custom DoH или распознавание любого hidden/shared origin.

## 23.10.2026: исправление SNI-selective Google (A)

Отказ YouTube на IP Google не доказывает отказ www.google.com на том же IP.
Ordinary DNS/outer hints google.com/gstatic.com/googleapis.com/googleusercontent.com
теперь сохраняют DIRECT, даже при чужом exact-IP/Google-family failure. Все
YouTube aliases (youtubei.googleapis.com, yt3.googleusercontent.com и другие)
исключены из ordinary; protected DNS association/DoH и BLOCK имеют приоритет.
Несколько только ordinary Google DNS names также не вынуждают relay. Это всё
ещё hint, не доказательство inner ECH имени.

Если DIRECT действительно отказал у этого ordinary hint set/IP, learning включает
relay только для того же (network, profile, IP:port, hash hint set), TTL2мин,
максимум256ключей. Чужой SNI/hostname на sharedIP не наследует этот отказ. Existing
TCP не меняется; известные origin timeout rules также сохраняются.

## Актуальное исправление video starvation, 23.10.2026

Shared8 выше — история305e2fd. Сейчас отдельные googlevideo12 и otherGoogle4;
ordinary Google hints не наследуют чужой SNI-failure. Capacity ordinary AUTO
fallback — реальный новый DIRECT plan до payload; protected/DoH/explicitRequired
не ослаблены. Idle/cancel/failure метрики разделены. Расчёт, ограничения, команды
обновления и read-only VPS-наблюдения — docs/YOUTUBE_RELAY_ADMISSION.md.
Двухминутная проверка: test-browser-dns.ps1 -DurationSeconds120 -RequireGoogleDirect.
