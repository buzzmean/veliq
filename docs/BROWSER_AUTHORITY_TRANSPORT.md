# HTTPS-адресаты через owner CONNECT

В beta #56 служба получает адресат нового HTTPS-соединения из HTTP CONNECT.
Это исправляет принципиальный пробел native-only: начальный SNI не показывает
поздние зашифрованные HTTP/2 authority на общем SAN/IP.

Chrome/Edge получают фиксированный HTTP/HTTPS-прокси на IPv4 loopback текущего
владельца установки. В поддерживаемых Chromium при явном HTTP-прокси IP pooling
между разными origin отключён; отдельные CONNECT проходят обычный планировщик
DIRECT → LOCAL → RELAY. Оба порядка общего SAN и подключение уже работающего
браузера проверяются настоящими запросами, телами и адресом выхода.
Это контракт проверяемых Chrome/Edge, не обещание для произвольного HTTP-клиента.

TLS остаётся между браузером и origin. Служба не читает HTTPS-запросы,
не устанавливает MITM CA, не получает ключи TLS и не переносит established TCP.
Raw TLS без CONNECT остаётся явно обозначенным временным authenticated RELAY;
его байты не считаются доказательством origin isolation или успешной страницы.

## Настройки Windows и другие приложения

Windows имеет один пользовательский HTTP proxy. Worker `-owner-system-proxy`
запускается с первичным токеном SID владельца, включая запуск из SYSTEM через
WTS. Он принимает один ограниченный запрос по приватному stdin, не читает
manifest/IPC token/identity, не запускает capture, enrollment или remote RPC.
Системные service SID и чужой первичный токен отвергаются.

Публикуются только `http=127.0.0.1:port;https=127.0.0.1:port`; системный PAC
не используется. WPAD временно выключен, его исходный флаг сохраняется.
Чужой PAC/manual proxy, machine-managed proxy и чужая browser proxy policy
не перезаписываются. Конфликт оставляет честный pending, а не READY.

На каждом принятом socket проверяются реальный PID/birth/exe и owner SID.
Chrome/Edge получают browser origin policy. Остальные приложения проходят свою
существующую политику: unselected/AUTO game DIRECT, явные BLOCK/MANUAL сохраняются.
UDP игр и Discord voice не становятся HTTP proxy traffic. iSCSI/NIC не меняются.

## Владение, OFF, crash и startup

`browser-owner-proxy.json` хранит полный исходный снимок и точное установленное
значение. Журнал записывается и синхронизируется до изменения Windows. При смене
своего значения сохраняется предыдущий снимок, поэтому crash до/после записи
не лишает rollback доказательства владения.

OFF, intentional SCM stop и uninstall восстанавливают исходный снимок только
при точном совпадении своего значения. Поздняя чужая настройка сохраняется.
Проверка перед записью не является атомарной транзакцией с чужими процессами;
ошибка/readback mismatch не превращается в заявление об успешном восстановлении.

После crash owned guard остаётся. Следующий host привязывает тот же порт до
медленной активации/CP. Пока активация ожидается, listener пропускает ordinary
DIRECT и блокирует protected/guarded authority. Фоновое обслуживание не снимает
guard только потому, что новый Controller ещё не включил capture.

При полностью остановленном процессе его listener отсутствует: новые запросы
Windows-proxy клиентов могут ждать SCM recovery; protected не получают DIRECT.
Это не независимый WFP/driver guard и не обещание нулевой паузы при crash.
На ПК проверяются автоматический возврат без ручного ремонта и повтор того же
failed authority. Intentional OFF возвращает обычные настройки до закрытия host.

Подготовленный freeze-образ сохраняют после OFF/cleanup: нельзя запечатать
действующий loopback proxy и затем удалить его журнал отдельно от HKCU.

## Readiness и доказательства

`browser.native.status.authority_transport` содержит только агрегаты: состояние,
`system_proxy_applied`, свежесть проверки и requests/exchanges по profile ID.
Текущий PID, сеть и время activation ограничивают наблюдение. Старые записи,
raw native TLS bytes, registry value и один TCP ACK не создают READY.

Capture-only outage не запрещает обычный DIRECT и authenticated RELAY, уже
имеющие CONNECT-адресат. LOCAL по-прежнему требует capture и подтверждённую
локальную стратегию. После начала delegated open нет скрытого retry/replay.

`Get-BetaRuntimeEvidence.ps1` сохраняет эти агрегаты по локальному owner IPC.
Он проверяет binary/helper hashes, не экспортирует tokens, SID, domains, URLs,
policy values или identity и не выставляет ручные проверки в PASS.

## Проверки

- Настоящие Chrome и Edge: fixed CONNECT, общий SAN/IP, оба порядка LOCAL/
  REQUIRED, живой браузер до включения и неизменный PID/birth.
- Raw native TLS: protected и ordinary остаются на явно обозначенном временном
  RELAY; отдельные fixed CONNECT cases доказывают сохранение обычного DIRECT.
- SYSTEM → owner worker: настоящий первичный SID, WinINET round-trip и полный
  restore; другой SID и system user proxy отвергаются.
- Другие приложения: полный DIRECT body, соблюдение BLOCK, сохранение поздней
  чужой настройки; Controller.Start и startup guard проверяются отдельно от
  настоящего Chromium/driver. В Controller lifecycle capture capability — fixture.
- Старые mandatory PAC: сохранение listener, capture/listener/relay/compound
  outages и same-authority retry. Availability fallback без CONNECT теперь может
  оставить ordinary на временном raw RELAY; established flow не переносится назад.

Первый fixed CONNECT proof: 1569fda/run41386845694. Его три сценария прошли на
настоящем Chrome. SYSTEM owner proof также получен на 893ceb2/run41386577765.
Финальный exact-SHA прогон и kit проверяются по CI текущего кандидата.

Отклонённый вариант: live GPO notification не был доказан; системный optional PAC
не дал нужной гарантии при ошибке движка. Он не является штатным transport.
Существующий cached legacy V1 не считается обновлённым по одной записи registry:
нужно наблюдать новый owner CONNECT. Пока его нет, beta admission остаётся pending.

Windows/ISP, действительная экономия CDN, голос, античиты, freeze и полная SCM
crash recovery на целевых ПК остаются ручной приёмкой по BETA_ACCEPTANCE.md.
