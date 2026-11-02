# Нулевой native ingress Chrome/Edge: границы доказательства

> Обновление 02.11.2026: beta #56 использует owner HTTP CONNECT как основной
> источник HTTPS-адресата. Native capture обслуживает LOCAL upstream; raw TLS
> без адресата временно идёт через authenticated RELAY. Чистый SNI не разрешает
> DIRECT/LOCAL для поздних HTTP/2 authority. Новый контракт и lifecycle:
> [BROWSER_AUTHORITY_TRANSPORT.md](BROWSER_AUTHORITY_TRANSPORT.md).
> Ниже сохранено описание native ingress и его отдельных диагностических доказательств.


Сборка владельца d3aad37: engine flows/native runtime были пусты при готовом
backend. Это подтверждает отсутствие зарегистрированного native обмена, но
само по себе не показывает, дошёл ли пакет до NETWORK handle.

## Найдено и исправлено в коде

SOCKET CONNECT dual-stack сокета представлял IPv4 как `::ffff:IPv4`, тогда как
NETWORK SYN использовал IPv4. Ключи ассоциации не совпадали. Регрессия
`TestSocketDualStackChromeOwnerMatchesIPv4SYN` падает до Unmap и проходит после.
Нативная IP Helper owner-table проверка остаётся первой и не ослаблена; исправлена
ассоциация, используемая при гонке появления строки TCP. Не установлено, что
именно эта гонка произошла на ПК владельца.

Native AUTO UDP/443 раньше мог идти отдельным opaque QUIC relay-потоком и не
попадать в TCP native counters. Теперь только выбранные native Chrome/Edge
получают один ICMP port-unreachable на UDP tuple; QUIC данные не отправляются
DIRECT. Затем браузер может открыть TCP, где доступны SNI/Host и существующая
origin policy. ICMP содержит только IP/UDP заголовки, не QUIC payload. Это не
заявление о проверенной скорости fallback Chrome157: настоящий Windows прогон
пока не выполнен. Legacy PAC, игры, остальные приложения и DNS/53 не менялись.

Chromium utility/NetworkService сопоставляется по полному exe пути и собственным
PID/creation time, а не PID главного окна. Для одинакового exe другой PID не
требует отдельного профиля. Native профиль публикуется через
ReconfigureNewConnections; callback Classify читает актуальный registry. Тесты
проверяют публикацию при уже работающем захвате и несколько дочерних PID.
Старые TCP не переводятся на другой egress.

IPv6 не реализован как relay transport: атрибутированные выбранные соединения
блокируются существующим guard, а не объявляются поддержанными. Ошибка владельца
не даёт оснований отключать IPv6-защиту. `!loopback`/`!impostor` остаются:
собственный transport нельзя повторно перехватывать. Наличие внешнего local
proxy/инжектора необходимо сначала подтвердить диагностикой, не угадывать.

## Диагностика без payload, токенов и command line

`browser.native.status.capture_ingress` и `capture.diagnostics.ingress`:

- фактические NETWORK TCP/UDP, SOCKET и IPv6 фильтры;
- lifetime counters TCP, UDP443, IPv6, SOCKET, unknown owner, native SYN,
  reflection accepts (это не site PASS);
- последние 24 метаданных событий: SOCKET_CONNECT, TCP_SYN_CLASSIFY,
  TCP_REFLECTION_ACCEPT, UDP443_NETWORK, IPV6_NETWORK;
- PID/birth/путь, полный tuple, профиль, решение, источник политики,
  owner lookup и конкретная стадия/код ошибки IP Helper;
- ограничение samples и lost явно видны; нулевые samples после переполнения
  не означают отсутствия пакетов. Копии IPC дополнительно ограничены по байтам.

`browser.native.attribution` — отдельный read-only запрос: живые IPv4 TCP sockets
Chrome/Edge из Windows owner table, включая utility child, независимо от packet
ledger и Engine. Классификация показывает текущую политику для нового соединения,
а не фактический маршрут уже существующего. Loopback виден отдельно. IPv6 этот
inventory не перечисляет; для него нужны IPV6_NETWORK и SOCKET counters.

Если SOCKET видит Chrome, но TCP SYN samples отсутствуют, проверять семейство IP,
loopback/внешний proxy, фильтр и injection; не объявлять несовпадение профиля.
Если SYN показывает PROFILE_NOT_MATCHED — проверять полный exe/profile.
NATIVE_DEFERRED_SYN без TCP_REFLECTION_ACCEPT локализует проблему в reflection /
локальной TCP приёмке. После ACCEPT ошибки owner/SID/ClientHello/open находятся
также в capture flow evidence. Нулевой Engine flow не заменяет эти проверки.

GUI подтверждает браузер после наблюдаемого owner CONNECT и двустороннего обмена
текущего AUTO/native профиля при действующем системном прокси и свежей проверке
его владения. Raw native TLS counters и просто armed capture этого не доказывают.
Даже двусторонние байты не доказывают успешную HTTPS/страницу.

## Автоматическая Windows проверка

Старая `TestWindowsNativeBrowserStartsBeforeControllerWithoutPAC` использует
подставной reflection. Её PASS **не является WinDivert PASS**.
Новая `TestWindowsNativeBrowserDriverHotAttach` в отдельном задании
`Chrome policy native / browser-native-driver` требует:

1. Одноразовую Windows VM без установленной службы neexitlag, настоящий Chrome
   и Edge, исходные SHA256 pins и подписанный WinDivert.
2. Браузер и его NetworkService запущены до Controller/capture; PAC не пишется.
3. Production NewWinDivert/фильтр/owner lookup/reflect/accept без packetWriter и
   без loopback capture seam. Профиль публикуется после запуска захвата.
4. TCP к TEST-NET попадает в reflection, затем реальный Controller открывает
   локальный mTLS/QUIC relay со свежими одноразовыми tickets. Контролируемый HTTP
   ответ проверяется по полному телу и исходящему адресу relay.
5. native_only accepted/opened/exchanges положительны, PAC ingress нулевой,
   production native SYN/reflection counters положительны; PID/birth браузера
   неизменны. OFF/host-close проверяются тем же браузером на локальном origin.

TEST-NET и локальный HTTP origin — изоляция теста, **не Internet/HTTPS/ISP PASS**.
Тест не меняет TLS trust, не устанавливает SCM, не читает production identity.
App-scoped firewall rule принадлежит скопированному test EXE и удаляется после
прогона. На установленном пользовательском ПК запускать этот VM-тест нельзя.

В Linux проверена только сборка Windows test EXE. Пока GitHub Windows job не
выполнился и owner не получил положительный native ingress, исправление A/C/F
**не считается принятым**. Ссылки/результаты сохраняются в CURRENT.md.

## Короткая проверка установленного ПК

Корень существующего клона, тот же владелец. Закрыть только GUI через «Выход»;
Chrome и Edge оставить открытыми. Команды по одной, PowerShell администратора
(в режиме UAC-off тот же пользователь):

```powershell
git pull --ff-only origin main
```

```powershell
& .\tools\windows\build-e2e.ps1
```

```powershell
& .\tools\windows\build-desktop.ps1
```

До обновления службы сохранить baseline уже открытых браузеров:

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase baseline
```

```powershell
& .\tools\windows\update-service.ps1
```

```powershell
& .\tools\windows\install-desktop.ps1
```

```powershell
(Get-FileHash .\bin\windows-e2e\neexitlag-service.exe).Hash -eq (Get-FileHash "$env:ProgramData\neexitlag\neexitlag-service.exe").Hash
```

True обязательно. Запустить установленный VELIQ (обычный owner, при UAC-off full-admin):

```powershell
Start-Process "$env:LOCALAPPDATA\Programs\VELIQ\VELIQ.exe"
```

Открыть новые вкладки YouTube, Telegram Web, claude.ai в прежних окнах;
не перезапускать браузер, не перезагружать policy. Затем:

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase ready
```

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

Если ready не прошёл, disabled/exit/stopped явно сообщат READY_NOT_CONFIRMED —
это не ещё одна регрессия остановки. Содержимое diag не коммитить. Ни одна из
команд этого раздела не вызывает SSH, enroll, CA rotation или deployment VPS.
