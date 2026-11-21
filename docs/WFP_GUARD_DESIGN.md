# E2: независимый WFP-барьер — оценка варианта B

21.10.2026. Только проект и оценка: новый драйвер, filters, WDK, зависимости,
сертификаты и production не устанавливались. Для реализации нужно отдельное
решение владельца. Технический аудит исходного backend и первичные источники:
[BROWSER_NATIVE_GUARD.md](BROWSER_NATIVE_GUARD.md).

## От чего отталкиваемся

Выбранный владельцем вариант A — тихий owned PAC, существующий WinDivert и
SYSTEM watchdog; браузеры не закрываются и не перезапускаются. Последующее
решение владельца о доступности допускает DIRECT при отказе локальной
инфраструктуры; это **не** независимый fail-closed барьер для защищённых сайтов.
См. [ACTIVATION_OWNER_RUNBOOK.md](ACTIVATION_OWNER_RUNBOOK.md).
Старые формулировки «PAC гарантирует отсутствие утечек при любом crash» не
описывают эту уступку и не должны переноситься в обещания продукта.

Watchdog обнаруживает неисправность и убирает owned policy/восстанавливает
службу с ненулевой задержкой. Он полезен для доступности, но не может закрыть
окно между смертью user-mode процесса и своим следующим запуском. WinDivert
использует dynamic WFP session, исчезающую с владельцем handle;
`WFPBackend.Start` в проекте пока заглушка. Реализованный kernel barrier нельзя
подменить именем нового watchdog или app-scoped inbound firewall allow.

Вариант B нужен, если владелец хочет более строгую гарантию: **новые** защищённые
и неидентифицированные соединения выбранных браузеров никогда не получают
DIRECT из-за смерти/зависания worker. Цена — временная недоступность при отказе
relay и отдельная разработка, подпись и сопровождение драйвера.

## Предлагаемая архитектура

1. Небольшой подписанный WFP callout driver: ALE connect/redirect для выбранных
   PID+birth/app identity+SID, IPv4/IPv6, TCP и UDP. Persistent policy и boot-time
   защита устанавливаются транзакционно SYSTEM broker. Правила должны сохранять
   deny и при отсутствии user-mode worker; динамическая session для этого не
   подходит. Проверить поведение unregistered callout, BFE restart и boot-time
   handoff отдельно, а не полагаться на имя флага.
2. SYSTEM broker отделён от routing worker. Owner-authenticated IPC, ACL,
   protocol version и policy generation проверяются до ARM. GUI остаётся без
   elevation и без права писать WFP. ActivationOnly не вооружает browser scope.
3. Worker получает новые соединения через проверяемую redirection/transparent
   ingress. Отдельный transport-owner открывает исходящие sockets; его identity,
   redirect record и generation защищают от рекурсивного захвата и impersonation.
   Самостоятельно указанный пользователем PID/port не даёт исключение из guard.
4. Kernel допускает DIRECT только по авторизации для конкретного нового flow
   текущей generation; default для selected app — bounded pending, затем deny.
   Неограниченная очередь и бесконечные ожидания недопустимы. Ресурсные лимиты и
   fairness по приложению задаются до прототипа и проверяются под насыщением.
5. Worker heartbeat с monotonic deadline. При просрочке/разрыве IPC новые
   авторизации DIRECT не выдаются. Независимый recovery agent перезапускает
   worker с backoff; kernel deny не снимается на время восстановления.
   Падение самого recovery agent не открывает сеть.
6. Существующие TCP не мигрируют и не воспроизводятся. Подтверждённые прежние
   flows закрепляются по generation/endpoint identity, а не одному reused tuple.
   Их потеря при смерти owning socket возможна; приложение может открыть новое
   соединение, но guard не отправляет HTTP POST повторно. TCP reauthorization
   WFP и отсутствие disruption unrelated apps — отдельный обязательный gate.
7. UDP mappings имеют bounded lifetime и собственное решение. Нельзя назвать
   весь старый UDP endpoint «прежним потоком» и разрешить DIRECT новым remote
   адресам. QUIC connection migration/reused tuple учитываются в threat model.
8. DNS/53 не отправляется через relay; default route, системный DNS и proxy
   Windows не меняются. Нет MITM, подмены сертификатов, TLS downgrade или чтения
   памяти браузера. mTLS, one-shot tickets, lease/revocation остаются прежними.

Если IPv6 transport пока отсутствует, selected-app IPv6 должен явно блокироваться
с проверенным IPv4 fallback; это не IPv6 support и не глобальное отключение IPv6.
Игры/Steam/неизвестные приложения не включаются в browser guard; их AUTO остаётся
DIRECT. Anti-cheat совместимость не обещается по одному успешному запуску GUI.

## Домен нельзя узнать только по WFP connect

На ALE connect есть app и IP/port, а SNI/Host появляется позже. DNS cache и IP
shared CDN не доказывают domain. ECH скрывает origin, HTTP/2/3 coalescing позволяет
нескольким сайтам пользоваться одним connection. Guard сам этого не решает.

Консервативное правило: неподтверждённый новый browser flow — authenticated RELAY,
без DIRECT fallback. DIRECT/DIRECT+ разрешать только после достаточных metadata
и проверенных ограничений coalescing. Если это фактически отправляет существенную
часть обычных сайтов через relay, нужно прямо согласовать нагрузку/политику с
владельцем; нельзя скрыть это под названием «маршрутизация по сайтам».
Разрешение отдельного IP по одному DNS-ответу не принимается. Обязательное
расширение, глобальный proxy или MITM не добавляются без нового решения.

## Миграция с A и аварийный откат

Сначала установить и проверить driver/boot policy без изменения маршрутов,
затем ARM на выбранном тестовом профиле. Снятие owned PAC допускается только
после readback effective guard и controlled failure injection. Chrome/Edge могут
ещё пользоваться ранее прочитанным PAC: сохранить compatibility CONNECT ingress
и отдельный PAC_COMPAT evidence, пока он нужен. Чужие политики не менять.
Новый fresh режим не должен писать PAC и должен доказывать NATIVE_ONLY.

Нельзя одновременно заявить fail-closed и при сломанном драйвере «на всякий
случай всё разрешить». Режим аварийного восстановления/отключения защиты — явное
административное действие, не скрытый автоматический fallback. Откат обновления
должен восстановить согласованную пару driver/broker и прежнюю policy generation;
удаление драйвера с сохранённым deny способно отрезать сеть. До выпуска нужна
проверенная offline/recovery-console процедура и хранение подписанного предыдущего
пакета. Локальный администратор остаётся вне модели защиты от злонамеренного
вмешательства; код/identity других пользователей по-прежнему защищены ACL.

## Подпись, среда и стоимость

Нужны WDK/совместимый Visual Studio toolchain в отдельной Windows build VM,
учётная запись организации в Microsoft Hardware Developer Program и выбранный
допустимый путь production kernel signing (attestation либо HLK/WHCP с учётом
целевых Windows и политики распространения). Проверить актуальные требования
Microsoft до покупки сертификата; user-mode Authenticode и подпись WinDivert
не подписывают новый SYS. Test-signing допустим только в изолированной VM.
У клиента нельзя выключать Secure Boot/HVCI/антивирус ради установки.

Владелец решает: организация/подписант, бюджет сертификата и signing service,
целевые Windows 10/11 x64/HVCI/Secure Boot, ресурсы native тестов и строгий deny
при outage. Стоимость сертификата/сервиса обычно сотни USD в год, точная цена
только по предложению поставщика; HLK и сопровождение требуют отдельного времени.
Driver vulnerability/BSOD — более высокий риск, чем сбой GUI. Нужны ревью всех
kernel buffers/IRQL/cancellation/refcounts, bounded memory, stress и Driver Verifier
в одноразовой VM. Матрица EAC/BattlEye/VAC/FACEIT — как в GAME_ROUTER_DESIGN.md.

## План и ворота выпуска

| Приоритет | Объём и ориентир для одного опытного инженера | Что завершает этап |
|---|---|---|
| P0 | 1–2 недели: threat model, WFP layer/filter arbitration, BFE/boot prototype spec, signing/OS scope | Владелец утвердил поведение отказа и бюджет; ревью безопасности, measurable acceptance |
| P1 | 4–8 недель: изолированный driver/broker prototype, bounded admission/redirect, independent deny/recovery | VM test-signing; ни одного protected DIRECT packet при kill/hang; app scope и pinned TCP доказаны |
| P2 | ещё 3–6 недель: production signing, installer/rollback, HVCI/Verifier/нагрузка/браузеры/anti-cheat | Подписанный пакет на чистой Windows и реальном ПК, boot/freeze/upgrade/uninstall gates |

Это оценка нового проекта, не срок обещанного релиза; сертификация и отказы
совместимости могут существенно увеличить объём. До отдельного «да» владельца
P1/WDK dependencies/драйвер в репозиторий не добавляются.

Acceptance должна включать Chrome/Edge, заранее открытые с неизменными PID/birth;
новые HTTPS/ECH/DoH/H2/H3, kill/hang worker в каждом состоянии, смерть broker и
watchdog, сетевой outage, relay saturation, boot/BFE/freeze, IPv6 и PID reuse.
Внешний контролируемый origin/packet observer доказывает no DIRECT leaks, не
счётчик GUI. Evidence incremental, evidence_lost=false. Отдельно существующие
TCP PINNED_UNTIL_CLOSED; первые native open/byte, deny latency, recovery p95/p99,
queue/memory bounds и CS2 RTT/control DIRECT. Проектные SLO ≤3с new open, ≤2с
admission failure, ≤10с worker recovery требуют измерения и пока не PASS.

## Что выполнено сейчас

Только этот проект и сопоставление с текущим вариантом A. Kernel code, filters,
подпись/driver install и failure injection **не выполнялись**. Боевой VPS,
credentials, CA, PR #8 и маршрутизация не менялись. Текущий клиент по этому
документу обновлять не нужно; вариант A остаётся до нового решения владельца.
