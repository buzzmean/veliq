# Hostkey P0: отдельная audience и обновление существующей службы

Production не запускался. Команда ниже предназначена только владельцу.
Control plane, activation, CA и клубный код остаются на2.56.177.4; клиентские
сертификаты/identity не перевыпускаются. На146.0.77.98 ставится только relay.

## Важное уточнение к раннему черновику a808ad0

Не разворачивать a808ad0 отдельно: менять адрес VPS-01, оставляя два физических
сервера с одинаковой ticket audience и разными replay caches, неправильно.
Финальный P0 использует **VPS-PRIMARY** на Hostkey и оставляет **VPS-01** на старом
сервере. Билеты каждого сервера имеют собственную audience, свежий signed device
proof и nonce; cross-audience replay отвергается. Root helper запрещает prepare/
commit для старого ID VPS-01. CA/signing ключи старого VPS не меняются и не копируются.

Нужна однократная **замена EXE установленной службы**, выполняемая тем же скриптом.
Это обновление существующей установки, не переустановка: сохраняются конфигурация,
identity, owner SID, ACL, IPC token и сертификаты. Старый клиент сам не понимает
новый primary ID; обещать ему перенос только изменением registry нельзя.

В клиенте VPS-01 остаётся локальным именем policy/provider. Если подписанный config
содержит VPS-PRIMARY, новые relay opens используют его независимый authenticated
pool; недоступный primary/ошибка открытия переключает только НОВЫЙ open на старый
authenticated relay. Ни один из двух путей не возвращает DIRECT. Пулы остаются8×48
с probe reserve; новые сессии получают свежие tickets именно своего server ID и
продлевают lease на нём же. Существующие открытые потоки сохраняют свой provider,
никакого replay/migration established application traffic нет.

Обычное обновление службы кратко закрывает её текущие proxy TCP/UDP, как update-
service.ps1 раньше: приложения переподключаются сами; продолжение уже открытой
загрузки не обещается. Chrome/Edge/игры скрипт не закрывает и не перезапускает.
При необходимости освобождения legacy recovery helper он штатно закрывает только
GUI VELIQ через same-owner/session pipe; GUI может остаться закрытым, служба
продолжает маршрутизацию. Профили/режимы не переписываются.

## Что делает команда

До remote mutation проверяет установленную активированную identity/owner SID,
собирает клиент и проверяет все filters настоящим pinned DLL. На новом сервере
создаёт Ed25519 key/CSR. Старый VPS root-only helper подписывает только server leaf
с IP SAN и ServerAuth; закрытый CA остаётся root-only0600 на старом сервере.
Публичные CA/trust, heartbeat и бинарник передаются по двухсторонне SSH-проверенным
каналам с SHA256. Bash-файлы нормализуются в LF, приватные RPC replies не выводятся.

Установка через relay-install.sh; чужая/изменённая установка отвергается. UFW не
включается/не сбрасывается: только в уже active UFW разрешается4433/udp. Никакие
старые production services, activation, schema migrations или firewall старого
VPS не перезапускаются/не меняются. Новая registry row + signed config публикуются
атомарно, проверяется свежий heartbeat. До финализации — независимый10min timer
и boot recovery, rollback только relay row новой монотонной config version,
без DB/security restore. Затем скрипт обновляет локальную службу и ждёт primary
из signed config. При ошибке клиентского обновления новый узел может оставаться
развёрнутым: это явно отдельная стадия; старый relay сохранён.

Доказательство **с ПК** до publication: fresh-ticket QUIC mTLS /3, authenticated UDP
через существующий echo и настоящий HTTPS GET с проверкой публичного сертификата,
HTTP200 и DNS JSON response. Это не YouTube/1080p/40ПК PASS.

## Команды владельцу

Из чистого checkout main, PowerShell5.1 **администратор под тем же SID**, Git,
Go, Python3, OpenSSH. Действующая activation/manifest обязательны. Root key нового
VPS: `~/.ssh/id_ed25519`; старый VPS может запросить пароль один раз. `accept-new`
принимает первый SSH host key, изменившийся отвергается. Fingerprint первого SSH
подключения можно сверить через консоль провайдера; пароли/коды/ключи в чат не слать.

Сначала read-only (временный helper в /var/tmp, только чтение production state):
```powershell
& .\tools\windows\add-relay-vps.ps1 -Host 146.0.77.98 -Name hostkey-ams -PromotePrimary -Inspect
```
Одна команда: новый relay + обновление существующей службы на этом ПК:
```powershell
& .\tools\windows\add-relay-vps.ps1 -Host 146.0.77.98 -Name hostkey-ams -PromotePrimary
```
Проверка «через какой relay фактически шли новые TCP»:
```powershell
& .\tools\windows\relay-status.ps1
```
`configured_primary` — намерение, не traffic proof. Для реального использования
смотрите `connections.authenticated_relay_id`, `observed_tcp_session_endpoint` и
TX/RX. Пустые counters — ещё не было observed traffic. UDP показывает выбранный
ID; peer endpoint скрыт текущим pool API, поэтому не выдумывается. Полный список
registry берётся из проверенного подписанного cache установленной службы.

Откат registry (клиент сам вернёт новые opens на старый relay после config refresh):
```powershell
& .\tools\windows\add-relay-vps.ps1 -Host 146.0.77.98 -Name hostkey-ams -PromotePrimary -Rollback
```
Root journals `/var/lib/veliq-relay-fleet/` не присылать: private heartbeat/undo.
При ошибке нового узла его owned files/service/key могут остаться установленными;
registry rollback не удаляет их. Повтор поддерживает только эту owned установку.

## Границы P0

Обновляется только ПК запуска команды. Другим уже установленным legacy клиентам
нужно такое же штатное обновление службы/клубного образа; скрытого updater нет.
Балансировка40ПК, RTT/load/hysteresis, отдельные video admission pools на relay,
второй IP и throughput tool — отложенные A–E, не заявляются готовыми.

Новый server leaf на90дней (не дольше CA); его автоматическое продление на этом
отдельном узле пока не установлено. CP/activation/echo остаются зависимостью старого
VPS: продление/перенос до12.11.2026 — отдельная работа. 3ТБ/месяц ≈9.3Мбит/с
непрерывно;1Гбит/с порт не обещает40 одновременных1080p или достаточную квоту.

Локально: Go race tests leaf/scope/provider/unique audience, isolated PostgreSQL17
CAS/publish/DB-error rollback/nonce preservation, Python fault fixtures и PS7 parser/
PS5.1 syntax subset. Native PS5.1/OpenSSH/Ubuntu systemd/UFW/Hostkey Internet/P0
обновление на ПК ещё не проверены. До owner запуска deployment PASS не заявлен.
