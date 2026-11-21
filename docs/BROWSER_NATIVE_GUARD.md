# Этап (в): браузеры без PAC и перезапуска — security blocker

> Актуальное решение владельца 20.10.2026: выбран вариант A — тихий owned PAC без browser restart; см. [BROWSER_SILENT_POLICY.md](BROWSER_SILENT_POLICY.md). Независимый WFP/driver guard ниже — будущий вариант B. Исторические restart-инструкции не относятся к текущему UX.

> Оценка E2 от 21.10.2026: [WFP_GUARD_DESIGN.md](WFP_GUARD_DESIGN.md).
> Текущий вариант A позднее получил owner-authorized DIRECT при отказе инфраструктуры;
> приведённый ниже строгий барьер остаётся будущим вариантом B, не свойством A.

Дата: 20.10.2026. Аудит базы `2c4f75f`, ветка `main`.
**Статус: BLOCKED_CURRENT_BACKEND. Это архитектура, не реализованный guard.**

## Решение по требованию владельца

Обязательный продуктовый сценарий: уже открытые Chrome/Edge, одна кнопка
«Оптимизировать» или автозапуск, никаких диалогов, закрытия окон, `chrome://quit`,
`edge://quit`, ручного reconnect или PowerShell. Новые TCP работают по политике;
доказанно существовавшие TCP остаются `PINNED_UNTIL_CLOSED`.

В текущем стеке безопасное выполнение всех этих условий не подтверждается.
Применён **пункт 4 задания владельца**: остановить runtime-реализацию и описать
ограничение. Не удаляем PAC guard, не снимаем проверки owned guard и не рисуем
READY. Код GUI/bootstrap/службы/захвата в этом изменении не меняется.

**Существующий legacy путь с диалогом/перезапуском не принимается как решение
этапа (в) и не предлагается владельцу для проверки этого этапа.** Его сохранение
в старом коде означает только отсутствие опасного runtime-изменения до готовности
нового барьера. Это не одобрение «временного UX» и не выполненное требование.

Это не утверждение, что Windows принципиально не умеет такой сценарий.
Нужна реализация независимого kernel/WFP enforcement и проверка её на Windows.
В репозитории её нет; готовность потребует подписанного драйвера, WDK build и
нативных испытаний. Подмена этого этапа user-mode watchdog недопустима.

## Что подтверждено исходниками

| Место | Факт | Следствие |
|---|---|---|
| `platform/windows/capture_windows.go`, `divertDLL.openHandle`, `Start` | NETWORK/FLOW/SOCKET handles открывает routing service. SOCKET — `1|4` (SNIFF/RECV_ONLY), а не redirect barrier | При смерти процесса его handles не остаются независимым guard |
| `platform/windows/tcp_capture_windows.go`, `startTCP` | NETWORK IPv4 TCP reflector; отдельный local listener, `!impostor`; `stop` закрывает handle | Это не постоянная per-app авторизация connect |
| `platform/windows/boundary.go`, `WFPBackend` | `Start` возвращает «signed driver and WDK implementation required» | WFP redirect/enforcement в продукте пока заглушка |
| `platform/windows/README.md` | IPv6 transport не реализован, у existing/unknown sockets есть fail-open limits | IPv4-only happy path не доказывает browser no-leak |
| `services/client-service/browser_native_compat.go`, `nativeGuardReadyLocked` | Нужен уже owned PAC, иначе `NATIVE_OWNED_PAC_GUARD_REQUIRED` | Проверку нельзя удалить без замены guard |
| `services/client-service/browser_native.go`, `nativeSnapshot` | `NOT_AVAILABLE_WITH_PAC_AS_ONLY_CRASH_GUARD`, existing TCP pinning | Текущая диагностика честно не обещает независимый native-only |
| `tools/windows/native-tcp-firewall.ps1` и `platform/windows/native_firewall_probe.ps1` | App-scoped **inbound allow** для service TCP reflection | Это не outbound browser kill switch |

Проверен именно исходник закреплённого WinDivert **2.2.2**:

- `sys/windivert.c`, `windivert_create`: WFP session использует
  `FWPM_SESSION_FLAG_DYNAMIC`.
- `windivert_cleanup`: пока пакеты не просрочены, NETWORK queue/work queue
  может пройти через `windivert_reinject_packet` при cleanup. Это важнее простой
  фразы «новые пакеты пойдут DIRECT»: нельзя считать уже удержанные пакеты
  гарантированно уничтоженными после смерти service.
- `windivert_destroy`: `windivert_uninstall_callouts` и `FwpmEngineClose0`.
- NETWORK не предоставляет `processId`; SOCKET предоставляет PID, может
  блокировать события, но **не может инжектировать изменённый socket/connect**.
  FLOW/SOCKET не восстанавливают события, случившиеся до открытия handle.

## Почему простые варианты не выполняют требование

| Вариант | Контрпример / ограничение |
|---|---|
| SCM restart или watchdog, который после crash включает deny | Сначала исчез handle/реинжектируется очередь, затем обнаружен crash. Между событиями может уйти SYN/данные. Интервал polling хоть 1 мс не делает операцию атомарной |
| Вторая WinDivert-служба / продублированный handle | Может пережить смерть одного worker, но не решает lifetime последнего handle, boot gap и crash самого guard. Нужны доказанный порядок teardown и самостоятельный постоянный enforcement; этого нет. Это не утверждение, что нельзя использовать второй процесс вообще |
| Постоянный outbound block приложения через Windows Firewall | Запрещает исходный connect, но не перенаправляет его в локальный reflector. Существующий NETWORK backend не получает разрешённый внешний SYN для обычной обработки. Получается запрет браузера, не работающий native routing |
| Permit-фильтр только пока жив worker | Между удалением WinDivert callout и исчезновением permit нет общей атомарной транзакции. Порядок cleanup независимых handles не доказан; при hang permit остаётся |
| Динамические deny по PID/портам после SOCKET event | Асинхронный event/PID/tuple lookup не является постоянным per-app барьером; старт нового network subprocess, повторное использование PID/порта и старые UDP endpoints требуют отдельного решения |
| WinDivert SOCKET DROP | Можно запретить connect, нельзя переделать и отправить его в user-space proxy; при закрытии handle persistent deny не появляется |
| PAC выдаёт DIRECT, WinDivert «успеет поймать» | При crash разрешение PAC остаётся, а перехват исчезает: protected DIRECT leak |
| IP-блоклист / DNS-переключение / URLBlocklist | Shared CDN, ECH, DoH, H2 coalescing и подресурсы не дают полной связи «IP = домен». Предыдущий security blocker остаётся |
| Автоматический registry refresh вместо перезапуска | Успешный refresh request не доказывает uptake уже работающим браузером; не заменяет независимый kernel guard |

Наличие WFP API управления фильтрами в user mode само по себе не требует нового
драйвера. **Постоянный BLOCK технически доступен.** Не хватает именно согласованного
с ним transparent redirect/admission механизма. Вариант «поставить block и объявить
защиту готовой» оставляет браузер неработоспособным.

Контрпример watchdog без постоянного барьера:

1. Время T0: worker держит WinDivert; native PAC bypass разрешён.
2. T1: `TerminateProcess(worker)`; ядро закрывает handles, очередь может быть
   reinjected, callouts удаляются.
3. T2: Chrome делает новый connect к protected/неоднозначному назначению.
4. T3: watchdog замечает смерть и ставит block/restart.

Если T1 < T2 < T3, требование уже нарушено. Сокращение T3–T1 не устраняет этот
порядок событий. Симуляция watchdog не является Windows acceptance.

## Рекомендуемая архитектура следующей реализации

**Минимальный подписанный WFP callout + постоянные правила + независимый broker/
watchdog.** Routing/scoring, authenticated relay, tickets и lease не переписывать.
Новый драйвер и signing/build инфраструктура — отдельная область работ, не готовый
компонент этого commit. ADR-001 уже выбирает WFP для production.

1. Enforcement по полному app identity и owner SID для выбранных Chrome/Edge,
   IPv4 **и** IPv6, TCP и UDP. Не только изменяемый PID. Games/Steam/standalone
   ChatGPT/Codex/Claude не попадают в эту область; их existing policy остаётся.
2. ALE connect redirect новых TCP в owned local ingress **до внешнего SYN**.
   Оригинальное назначение передаётся через проверяемый WFP redirect context;
   `FwpsQueryConnectionRedirectState`/redirect records предотвращают цикл.
   Это прозрачный TCP stream, не обязательный browser CONNECT/PAC.
3. Независимые постоянные deny/callout rules не исчезают вместе с GUI/routing
   service. Не использовать `PERMIT_IF_CALLOUT_UNREGISTERED`. Boot-time и persistent
   filters имеют разные lifetimes и не устанавливаются одним совмещённым флагом;
   переход до/после BFE должен быть отдельно спроектирован и проверен.
4. Broker держит ingress и не доверяет только SCM=Running. Worker публикует
   аутентифицированный generation/heartbeat и способность принять **новую** flow.
   Kernel/broker admission не превращает stale heartbeat в внешний DIRECT permit.
   Не выдавать пропуск по одному PID, `impostor` или широкому localhost allow.
5. При crash/hang/отказе открытия: protected/unknown не выходят DIRECT. Новые
   соединения bounded pend либо получают быстрый reset/reject; независимый
   watchdog восстанавливает worker. Тайм-ауты должны быть ограниченными, а не
   многоминутной чёрной дырой. Диагностировать recovery/backoff/exhaustion.
6. Очереди, число pending connect, память и IPC bounded, с per-app fairness.
   Нельзя реализовать «восстановление» бесконечной очередью или рестартом браузера.
   До прототипа не назначать выдуманный SLO/PASS: будущая acceptance ниже фиксирует
   измеряемые пороги и требует их подтверждения.
7. Существующие TCP не перенаправлять. Политика WFP может вызвать reauthorization:
   надо доказать grandfathering именно уже существовавших flow/endpoint generation,
   а не разрешить новый flow с повторно использованным tuple. Установка driver/
   добавление filters не должны массово обрывать TCP.
8. Самостоятельно созданные relay/service sockets исключать по проверяемой
   service identity/redirect records, сохранив owner SID/ACL, mTLS/tickets/lease.
   GUI не получает права менять WFP; только owner-authenticated IPC в SYSTEM broker.
9. Системный DNS/53 не уходит в relay, default route и системный proxy не меняются.
   Existing browser UDP/QUIC не получает безусловный DIRECT grandfathering:
   старые UDP endpoints и connection migration требуют отдельной проверки.
10. Если IPv6 relay пока отсутствует — явный per-selected-app fail-closed IPv6
    barrier и проверенный IPv4 fallback, а не глобальное отключение IPv6 и не
    нынешний unknown/existing IPv6 fail-open. QUIC либо реальный relay UDP/443,
    либо явная ошибка с автоматической TCP-попыткой браузера, доказанной тестом.

При действительном отказе сети/relay protected fail-closed означает отказ запроса,
а не гарантированную доступность сайта. Watchdog может восстановить инфраструктуру,
но не имеет права воспроизводить уже отправленный HTTP POST или мигрировать TLS
stream. После смерти owning transport старый сокет может закрыться; это не
перезапуск процесса. Автоматическое восстановление **новых** запросов проверять
реальным браузером, не считать restart worker доказательством восстановления страницы.

## Отдельное ограничение: имя сайта не всегда доступно

WFP решает enforcement и перенаправление; он не расшифровывает ECH/HTTP/2/HTTP/3.
SNI/Host читаются только из доступных handshake/HTTP metadata без MITM. DNS/IP не
считать доверенным доказательством hostname, особенно для shared CDN и poisoned DNS.
Неоднозначное новое соединение — только authenticated RELAY_REQUIRED, без DIRECT
fallback, как уже согласовано владельцем.

H2/H3 coalescing может поместить другой origin в уже существующее TLS-соединение.
Решение по SYN/SNI не является автоматическим доказательством политики каждого
HTTP-запроса. Нужны реальные coalescing/ECH/DoH тесты и безопасное правило допуска
DIRECT, не основанное на предположении о неизменных CDN/certificate SAN.
Если этого доказать нельзя, нужно явно согласовать более консервативную маршрутизацию
неоднозначных соединений или источник browser metadata. Не включать скрыто
обязательное расширение, MITM, TLS downgrade или полный RELAY всего браузера.

Исключение для старых TCP должно быть видно отдельно: «no DIRECT leak» доказывается
для новых flows после activation barrier. Нельзя приписать прямые байты старого
pinned TCP новой разрешающей политике или скрыть их из отчёта.

## Миграция существующего owned PAC — тоже gate

Fresh без PAC после установки настоящего guard не должен писать browser policy,
запускать recovery browser, спрашивать подтверждение или ждать выхода процессов.
Update/repair должны принять открытые браузеры с неизменными PID/creation time.

У уже активного браузера может оставаться прочитанный старый PAC. Даже после
удаления owned registry value браузер способен продолжать CONNECT на старый
loopback endpoint. Поэтому нельзя сразу закрывать старый listener/recovery.
Нужен silent compatibility ingress на прежнем порту под новым guard, пока
наблюдаются legacy CONNECT, с отдельным `PAC_COMPAT` evidence. Fresh с нулевой
policy обязан показать `NATIVE_ONLY`, а upgrade может честно показать compatibility.
Только свои policy/journals; чужую политику не удалять. Никакого `chrome://quit`,
диалога или «сначала вручную закройте браузер» в новом продукте.

Пока guard не реализован, существующий runtime **не мигрируется**. Нет разрешения
снять PAC, автоматически запустить старый restart repair или объявить stage (в)
готовым. Для продолжения нужно решение владельца о новом WFP driver/signing scope
и ресурсах нативной Windows-проверки; простой запрос «разрешить утечки на polling»
не является предлагаемым вариантом.

## Диагностика и acceptance, которые обязательны до выпуска

Ниже — **проект** новых полей/кодов, не текущий IPC и не данные с ПК:

- guard: `NOT_INSTALLED`, `ARMED`, `WORKER_UNAVAILABLE`, `RECOVERING`, `RECOVERY_FAILED`;
  driver version/signature, effective per-app v4/v6 rules, policy generation,
  last authenticated heartbeat, blocked/pending/rejected counts, queue high-water.
- flow ingress: `NATIVE_TCP`, `NATIVE_UDP`, `PAC_COMPAT`; PID/birth/exe/SID attribution,
  destination, route, reason, relay bytes, activation generation, pinned preexisting.
- clocks: optimize request → barrier effective → first native open → first byte;
  service death → deny effective (deny обязан предшествовать release) → recovery.
- ошибки: `NATIVE_GUARD_NOT_INSTALLED`, `NATIVE_GUARD_NOT_EFFECTIVE`,
  `NATIVE_GUARD_WORKER_STALE`, `NATIVE_GUARD_ADMISSION_TIMEOUT`,
  `NATIVE_GUARD_RECOVERY_FAILED`, `NATIVE_DOMAIN_AMBIGUOUS_RELAY_REQUIRED`.
- Нет raw PAC, nonce, сертификатов, private keys, токенов или содержимого страниц.

| Испытание на реальной Windows | Обязательное доказательство |
|---|---|
| Fresh: браузеры заранее открыты, policy отсутствует | Одна кнопка/автостарт; ноль dialogs/quit/новых user browser profiles; PID/birth неизменны; новые controlled HTTPS requests проходят native |
| Cold start / включение-выключение / обычный update и repair | Новые потоки корректны, старые TCP pinned, нет browser restart и ручных reconnect |
| Kill worker в разных точках OPEN/ClientHello/активной передачи | Внешний packet observer/контролируемый origin не видит ни одного protected DIRECT SYN/datagram/byte; только BLOCK/RST либо authenticated relay |
| Hang worker, IPC отвечает или не отвечает | Generation/heartbeat проверяются независимо; bounded admission; восстановление без действий пользователя |
| Kill watchdog, broker, GUI; затем worker | Постоянный deny сохраняется; никакой зависимости безопасности от одного user-mode процесса |
| Boot/BFE stop-start/driver missing/SCM restart | Нет окна до ARM; missing/unregistered callout не даёт permit; критерии grandfathering не обрывают unrelated TCP |
| IPv6, DoH/ECH, H2 coalescing, UDP/443/QUIC, reused PID/tuple | Нет молчаливого обхода и неверной атрибуции; opaque только relay; неподдерживаемое явно blocked |
| Games/CS2/Steam, ChatGPT/Codex/Claude одновременно | Игровой AUTO DIRECT и RTT без существенного добавления, существующие desktop policies работают; app scope guard не расширен |
| Насыщение очередей, relay pool и рестарты | Ограниченные ресурсы, нет необоснованного DIRECT, чужие flows не затронуты |

Целевые пороги для прототипа: новое открытие при здоровом worker начинает
маршрутизироваться за ≤3 с; одиночный отказ admission завершается явным результатом
за ≤2 с; controlled recovery после kill/hang — ≤10 с. Это **критерии приёмки**, не
обещанные измерения. Отдельно измерять p95/p99 задержки, не только среднее.
Evidence должен быть полным/incremental, `evidence_lost=false`. Один HTTP success,
счётчик relay или fake heartbeat не заменяет packet/no-leak доказательство.

## Проверено в этом аудите / не проверено

Проверены перечисленные исходники проекта, официальный WinDivert 2.2.2 и
документация Microsoft по ALE/redirection/filter lifetimes. В этом commit только
документы; нет установки filters/driver, watchdog, новых diagnostics, failure
injection или обещания рабочего stage (в). Runtime tests для отсутствующего guard
не запускались. Боевой VPS, сертификаты, credentials, PR #8 и игровые маршруты
не менялись. Текущую сборку по этому документу переустанавливать не нужно.

## Первичные источники

- [WinDivert 2.2.2: layers, flags, priorities, processId](https://github.com/basil00/WinDivert/blob/v2.2.2/doc/windivert.html).
- [WinDivert 2.2.2: dynamic session, cleanup, destroy](https://github.com/basil00/WinDivert/blob/v2.2.2/sys/windivert.c).
- [Microsoft: ALE layers](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/FWP/ale-layers.md).
- [Microsoft: connect/bind redirection requires callout](https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/network/using-bind-or-connect-redirection.md).
- [Microsoft: FWPM_FILTER0 persistent/boot-time/unregistered flags](https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/fwpmtypes/ns-fwpmtypes-fwpm_filter0.md).
- [Microsoft: filter arbitration, отсутствие cross-layer arbitration](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/FWP/filter-arbitration.md).
- [ADR-001 проекта](ADR-001-windows-networking.md).
