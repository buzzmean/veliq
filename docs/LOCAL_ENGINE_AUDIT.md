# LOCAL: проверяемый путь пакетов (24.10.2026)

Приёмка владельца f0e181a: relay2160p работает; LOCAL не подтверждён,7фоновых
проверок/6отказов,0CDN trials. Это не доказательство конкретной неисправности TTL
или отсутствия инъекции: прежняя причина объединяла несколько разных отказов.

## Физический путь

`browserOpenUnobserved` → `WinDivertBackend.OpenBrowserLocalTCP` →
`tcpRedirect.dialDelegatedFrom`: служба резервирует точный upstream tuple ДО connect,
связывает его с владельцем/стратегией. NETWORK WinDivert перехватывает SYN/SYNACK и
ClientHello этого собственного сокета по явной delegation; остальные собственные
соединения не становятся LOCAL. `LocalTCPBuffer` собирает bounded ClientHello;
`SendLocal`/buffer deliver отправляют изменённые IPv4/TCP через `t.send`/WinDivertSend.
Это НЕ только socket Write segmentation. Raw TTL/seq/options действительно доступны;
новый драйвер/внешний winws для этого не нужен. Неинъецированный план не является
успехом: counters commit появляются после успешной отправки всего плана.

## Исправления исполнения TCP443

Старый compiler исполнял13 уникальных планов и навязывал old-sequence даже чистым
TS/MD5 стратегиям. Теперь все64 Flowseal TCP443 rules из22 general*.bat имеют
типизированный исполняемый рецепт: fake, multisplit/multidisorder, fakedsplit,
fakeddisorder, hostfakesplit/altorder, SYN-data и их комбинации. Дедупликация всего
каталога даёт44 плана;49 HTTP/QUIC/прочих rules остаются явно unsupported.
С9 legacy кандидатами это53 варианта, помещающихся в64-битную маску подбора.

Raw injection выполняет собственный WinDivertSend; сохраняются реальные байты
TLS, ACK/window/options и относительные sequence original-потока. Fake packet
помечается отдельно, включая interleaved fake/real, с корректными checksum.
Параметры repeats, cutoff1, split markers, zero IP ID, fake list order,
badseq(-10000/override) и badack(-66000), TS delta(-600000), MD5 option19 и seqovl
обрабатываются собственным кодом. При отсутствии исходного TTL/autottl в правиле
не добавляем скрытый TTL2: native fake сохраняет TTL original. Legacy autoTTL
по SYN/ACK остаётся отдельным кандидатом. Это адаптация параметров, не побитовая
копия winws: TLS/STUN/zero модели свои, upstream fake binaries не копируются.

TS/MD5 больше не означают скрытый badseq: fake может иметь текущий sequence;
защита от принятия peer зависит от реально согласованных TS/PAWS либо TCP MD5.
Чистый TS без timestamp option → TIMESTAMP_OPTION_REQUIRED, fake не отправляется.
Только собственный LOCAL socket перед connect включает Winsock TCP_TIMESTAMPS=10;
неподдерживаемая ОС → LOCAL_SOCKET_OPTION_FAILED/TCP_TIMESTAMPS_UNAVAILABLE.
Никаких netsh/global/browser настроек. И это не обещает, что peer примет LOCAL:
истинный TLS/HTTP или WSS probe всё ещё обязателен. SYN-data применяется только
к новому пустому SYN без TFO,16 своих нулевых байт, original sequence; established
потоки не изменяются. MD5 не добавляется, если options не помещаются в TCP header.

LSO first-flight ранее >1500B обходил buffer без transform. Native recipe теперь
принимает bounded ClientHello до MaxHelloBytes, делит оригинальный stream на
≤1500B IP packets, резервирует MD5 header и сохраняет точные wire offsets.
SNI, заканчивающийся точно на конце ClientHello, не отвергается hostfakesplit.
Неподходящий план/размер/бюджет не отправляется частично. Только native browser
TCP443 имеет отдельный потолок64 выходных пакета на первый logical flight;
legacy catalog20/input и обычный DIRECT+5 сохранены. Дальше cutoff: pass-through.

## Диагностика первого этапа

`browser.local.probes`: retained128 strategy×host результатов ВСЕХ групп; отдельный
read-only IPC возвращает последние32 в бюджете48KiB, сообщает omitted_retained.
wire application TX/RX (включая origin TLS), HTTP body bytes, commit, phase/detail,
SYN seen/handshake/server TTL и до64 реально отправленных packet headers:
fake/length/TTL/protocol/TCP flags/relative sequence offset. Ни payload, ни абсолютные
sequence numbers, ни приватные TLS значения не экспортируются. Raw fake bytes
в wire application TX не входят: их видит отдельный список реальных sends.
ORIGIN_SILENT/RST/FREEZE_AFTER_N/EOF_AFTER_N/SHORT_RESPONSE/NO_TRANSFORM/OK разделены;
короткий корректный ответ не назван freeze. OK — проверка собственного HTTPS GET,
не гарантия playback. Отсутствие ledger — неизвестное наблюдение, не успешный send.
Неверный публичный протокол имеет отдельный failure, не выдаётся за freeze.

## Проверяемые риски, ещё не доказанная причина на ПК

При первом SYN OS TCP owner table может ещё не вернуть PID. Native delegation
с OpenDeferred удерживает такой SYN; LOCAL delegation старого кода такой защиты
не имеет и может попасть в self/DIRECT с закреплением решения на весь tuple.
Защита добавлена: LOCAL reservation требует тот же owner proof, что native; pending SYN удерживается до подтверждения владельца. Существующие close/retry тесты сохранены. Unit regression воспроизводит старое неверное решение при owner error; что именно это вызвало на ПК владельца, пока не доказано.
Также фактический commit может отсутствовать из-за handshake/TTL/sequence/guard,
а TLS/HTTP отказ возможен уже после правильно отправленного transform.

QUIC: native browser guard отклоняет selected UDP443 для TCP fallback;
это не fake QUIC. RFC9001 Initial с криптографически верными полями здесь не
реализован; PUBG-shaped fake не доказывает пригодность для браузера. Разрешённый
владельцем fallback сохранён: после него TCP проходит общий DIRECT/LOCAL/RELAY
selector и может использовать подтверждённый LOCAL. Unit проверяет именно
решение fallback, не успешный новый Chrome HTTP/3 → TCP на провайдере. IP/GEO группы не становятся LOCAL, VK/Яндекс остаются DIRECT.
Подробный transport proof и Windows/ISP acceptance ещё нужны.

## Что не проверено

Реальная инъекция на Windows/ISP владельца, PS5.1, LOCAL2160p, Discord WebSocket
и нулевой новый googlevideo relay RX. CP/shared learning не включать для проверки.
VPS/CA/activation/коды/PR8 этим этапом не меняются.

## Новый допуск реального CDN trial (решение владельца24.10)
Committed transform на любом YouTube-хосте запоминается ограниченно/TTL по сети,
профилю, стратегии и hint-mode, даже если public TLS/HTTP неуспешен. Для нового
CDN scope такой proof допускает только trial: max1 globally, живой relay sibling,
cooldown>=3мин/subgroup. LOCAL по-прежнему требует3успешных потоков >64KiB с TLS
и committed transform. Нет proof/relay sibling — нет trial; провал→RELAY/backoff.
Ни обычный origin, ни другая сеть/стратегия/профиль не дают CDN proof. Это не
снимает sustained критерии generic non-CDN origin и не включает CP shared flags.

Полный Go race/vet/build Linux+Windows и Windows vet PASS; checksum/filter DLL
подWine PASS. PS7 diagnostic fixtures PASS. Настоящие Windows capture/PS5.1/ISP
и2160p LOCAL НЕ проверены. Все64 Flowseal TCP443 rules проходят исполнение в packet fixtures; это не proof ISP.

## Общие DPI группы, не только YouTube
Один compiler, LOCAL delegation, buffer, счётчики и кеш применяются ко всем DPI
origins. Discord CDN проверяется несколькими credential-free PNG GET по одному
TLS до >64KiB (≤64 запросов/4с/256KiB, signature PNG+200). Gateway — публичный
TLS WSS Upgrade, проверка RFC6455 accept, Hello и3 свежих nonce ping/pong.
Точный discord.gg допускает ожидаемый HTTPS redirect на discord.com. Последние
два критерия помечены OK_CONTROL_NOT_BULK/BACKGROUND_PUBLIC_*_NOT_BULK_PROOF:
они подтверждают контрольный протокол, не >64KiB, логин, приватный WebSocket или
страницу целиком. Это не ослабляет64KiB Googlevideo и не публикуется как bulk
shared proof. Серверные CP/shared flags не включаются.
Telegram/Meta/OpenAI/Anthropic immutable RELAY floors сохранены; VK/Яндекс DIRECT.

## Лаборатория и границы результата
64 Flowseal recipes: actual packet output, split/order/fooling/checksum/cutoff,
точная сборка оригинального1955B TLS,12KiB offload segmentation, MTU/MD5 и scope
(browser443, не игры/iSCSI). Реальные локальные TLS fixtures: >64KiB CDN PNG,
public WSS nonce-подтверждение, отказ неверного nonce/certificate/redirect.
Pinned DLL compiler/evaluator/checksum запускается под Wine, не в ядре Windows.
Первоначальный owner race и LSO gap — конкретные дефекты кода; что именно
вызывало отказ у владельца, без новой таблицы probe evidence не установлено.
Если остаются TIMESTAMP_OPTION_REQUIRED/LOCAL_SOCKET_OPTION_FAILED — чистый TS
на этой ОС/peer недоступен, подбираются другие варианты. Если transform committed,
но ORIGIN_SILENT/FREEZE_AFTER_N — нужен ISP trace/другая стратегия, не фиктивный PASS.
Нет гарантии, что собственные fake templates дадут ту же реакцию ТСПУ, что winws.
На Windows/провайдере владельца LOCAL2160p, Discord, PS5.1 и новый socket option
пока НЕ проверены. Цель relay RX≈0 для новых googlevideo flows ещё не доказана.

## CDN приёмка6df8a42 —24.10.2026
Владелец подтвердил www.youtube.com/discord.com >128KiB на catalog-c0aa53e48f222aca,
но0/4 CDN trials,3после ответа, googlevideo около7KiB и EOF. Это не proof обхода
CDN: публичный хост и sn-подгруппа могут фильтроваться по-разному.

Исправлен выбор: предыдущий код сначала выбирал следующий каталоговый prior,
и только затем искал proof; успешный другой plan оставался без приоритета.
Теперь same network/profile/hint-mode sustained YouTube proof выше transform-only,
с тем же точным ID; локальный неудачный CDN plan исключён из текущего sweep.
Discord proof не переносится на YouTube. Нельзя менять стратегию текущего trial.
Отдельный TrialAfter сохраняет >=3мин и не сбрасывается completeCDNQualification;
max1/live relay/3success/>64KiB/negative cache и отсутствие replay после origin
byte сохранены. Истёкший witness сам себя не продлевает простым выбором.

C: для fooling=ts badseq/badack — неактивные defaults, seq_delta0/1 ожидаем;
TS меняет существующий TSval на-600000. Для fooling=badseq применяются seq-10000
иack-66000 (либо явный override). MD5 — отдельная option19. TTL сохраняется из
original, если source recipe не задаёт TTL/autottl:128 само по себе НЕ ошибка.
Не добавляем скрытый badseq/TTL и не меняем подтверждённую стратегию.
Diag.10 выводит фактические ts_delta/ack_delta/MD5 option, не абсолютные значения.
Legacy old-sequence и проверка полного ClientHello до любого origin byte прежние.

A: причина конкретного EOF владельца пока НЕ доказана. Старое имя объединяло
remote EOF/reset и локальное закрытие. Теперь отдельные IOFailure, capture FIN/RST,
первый terminal packet/TTL, SYNACK TTL, genuine retransmits и payload counters.
Недавние LOCAL closes отдельно выдаёт browser.local.probes в пределах IPC budget,
не теряя их среди активных RELAY flows. CLIENT_PACKET — локальный upstream socket
(служба delegation), не доказательство закрытия браузером; REMOTE_PACKET может
быть подделан middlebox, разница TTL сама по себе не доказывает DPI. Собственный
Close помечается до закрытия socket, чтобы read-unblock не отравлял health-кеш.
Ни packet telemetry, ни ошибка EOF не разрешают replay/migration established TLS.
Нужно получить новый wire trace с ПК; remote7KiB могут быть TLS/маленьким HTTP
ответом/закрытием, не обязательно freeze после16KiB. Без MITM HTTP-код CDN не виден.

D:16обычных небольших PNG суммарно~21KiB, это ошибка размера выборки, не доказанный
отказ стратегии. Теперь ≤64 credential-free GET на одном TLS до >64KiB, прежние
4с/256KiB wire-cleartext budget;1312B asset воспроизводится fixture. При недостатке
данных PUBLIC_PROBE_BUDGET_NOT_SUSTAINED, не сетевой PASS/не bulk proof.
Пустой301 в generic probe больше не CONNECTION_FAILED. Для точного youtube.com
верифицированный canonical HTTPS→www.youtube.com redirect имеет только CONTROL
proof, не >64KiB/видео; follow на другой origin не выполняется. Корректный короткий
EOF этого control потока не отменяет собственную свежую контрольную проверку;
CDN trial по-прежнему провален при short EOF, отрицательный кеш сохраняется.
i.ytimg.com404 остаётся SHORT_RESPONSE, не локальный transport PASS.

## Нейтральное закрытие и admission — после57396ee,24.10.2026
Данные владельца: короткие LOCAL потоки закрываются первым CLIENT FIN+ACK,
без RST/ретрансмитов, peer FIN имеет тот же TTL, что SYN/ACK. Это не доказательство
поломки стратегии. При rx>0 и таком наблюдении результат CLIENT_INITIATED_CLOSE:
не failure, не failed_after_reply, не негативный score/backoff. Без sustained
>64KiB/ServerHello/post-hello write/committed transform это также НЕ success.
trial_inconclusive и client_initiated_trial_closes отдельны; neutral не увеличивает
streak, не удаляет Qualified и не помечает plan как Tried. Старую уже известную
ошибку/таймаут/TLS alert/RST нельзя нейтрализовать последующим клиентским FIN.
REMOTE_RST, REMOTE_EOF_BEFORE_REPLY, REMOTE_EOF_AFTER_REPLY и TIMEOUT различаются.
Один пассивный progress gap (возможно idle/preconnect) больше не портит score;
настоящий WatchMidstream timeout по-прежнему отрицателен. Его callback вызывается
ДО Close: собственный FIN watchdog не маскирует отказ нейтральным завершением.

Терминальный Read с обоими FIN либо reset завершает учёт trial немедленно,
не дожидаясь Close оболочки. TCP с обоими FIN уже не переносит новые данные.
Закрытие учёта идемпотентно и связано с scope+strategy; поздний Close старого
потока не освобождает новый slot. Не закрываем живой idle HTTP/2 ради второго
trial: max1 сохранён. Активная проба показывает возраст/подгруппу/последний RX и
состояние PRECONNECT_NO_CLIENT_BYTES/WAITING_ORIGIN_REPLY/SHORT_REPLY_WAITING_TERMINAL/
SUSTAINED_WAITING_TERMINAL. Если такой socket остаётся жив, slot удерживается честно.

Для реальных новых flows TrialAfter>=3мин остаётся gate; Retry фонового sweep
больше не блокирует уже qualified trial. Каждый check записывает ADMITTED,
GLOBAL_TRIAL_ACTIVE, SUBGROUP_COOLDOWN, NO_QUALIFIED_STRATEGY,
STRATEGY_PROOF_EXPIRED либо LIVE_RELAY_SIBLING_NOT_OBSERVED и счётчики/время.
NO_ELIGIBLE_NEW_FLOW_CHECK означает отсутствие наблюдённого admission check,
а не доказательство отсутствия всего browser traffic. TRIAL_PENDING не создаёт
новое Chrome TCP-соединение: HTTP/2 может пользоваться уже pinned RELAY. Перенос
такого соединения, replay после origin byte и искусственный разрыв рабочего H2
не добавляются. Live sibling прежний: тот же профиль, открыт, >64KiB, lastRX<5с.
Почему на ПК было ровно1trial/12мин, без этих данных пока НЕ установлено;
не назначаем причиной автоматически ни занятый slot, ни отсутствие нового flow.

Diag.11 сравнивает ClientHello→ServerHello avg/max/samples по service/stage/strategy,
показывает TCP open_ms, reassembly_ms, actual transform_send_ms, Hello→первый FIN/RST
и lastRX→первый FIN/RST. Wire observer считает точный byte offset конца ServerHello
даже через TLS records/Read boundaries; RX после него включает TLS handshake и
ciphertext, это НЕ HTTP body. Время первого ClientHello — начало его forwarding
Write, ServerHello — наблюдение завершённого handshake в Read, не timestamp NIC.
TLS type23 — наличие outer application record; TLS1.3 шифрует также handshake/alert.
Нельзя отличить Chrome abort/preconnect/H2 GOAWAY/HTTP-ошибку по этим bytes без
MITM или браузерного NetLog. HalfCloseRequested отмечает клиентское направление
copy→CloseWrite, но не доказывает намерение Chrome. Fake repeats/fooling/TTL не
изменялись; влияние repeats6 и fakedsplit на реальном ПК измеряется новыми полями,
лабораторный speed/Chrome-intent PASS не заявляется. NetLog с приватными URL не
включается автоматически. Без restart/ручного policy reload; VPS/CA/SSH не нужны.


## Running CDN sustained / послеd28dda8,24.10.2026
Владелец доказал реальный LOCAL googlevideo196453980bytes(c0aa53) на одном потоке;
прежний trialDone только при terminal Close держал global slot331s и не считал
успех. Теперь отдельный сильный критерий (>=1MiB после SH и в>=16 завершённых
outer type23 records, RX-span>=3s, freshRX<=3s, fullSH/postSH write/committed)
фиксирует TrialSuccesses/StrongPromotions до закрытия. Не HTTP/playback proof.
TLSWireObserver продолжает считать завершённые records/bytes после восьми
сохранённых headers, память константная, payload не сохраняется/не расшифровывается.
Стратегия и группа те же; ключ network/profile/subgroup/port/hint-mode. Cache
LOCAL10min; max1 применяется к новым неподтверждённым trials; cooldown>=3min.
Established socket не трогается, поздний Close не освобождает чужую новую пробу.
Поздний настоящий failure отзывает scoped LOCAL на будущие opens; отдельный
PostPromotionFailures и FailedAfterReply показывают цену, success не переписывается.

EOF2717bytes с remoteFIN без reset/retransmits/alert — недостаточно доказательств
отказа: REMOTE_SMALL_EOF_INCONCLUSIVE, не failure/score/Tried/потеря qualification,
не success. ClientFIN-first по-прежнему нейтрален. Малый TLS1.3 encrypted alert
может выглядеть так же — намерение Google не установлено; neutral не гарантирует
исправность. RemoteEOF0/invalidTLS/plaintextalert/RST/timeout отрицательны.
Diag.12: strong_promotions/post_promotion_failures/small_eof_inconclusive;
trial_result SUCCESS_RUNNING/SUCCESS_CLOSED/SUCCESS_REVOKED_AFTER_FAILURE;
completed application records/bytes/span. Последние8 LOCAL failures из отдельной
истории32: точные tx/rx, bytes после SH, Hello/SH→failure и lastRX→failure,
причина и факт предыдущей promotion (даже когда record вытеснен RELAY-потоками).

MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED — service WatchMidstream: был ответ,
потом исходящая запись без входящего прогресса6с; callback фиксирует timeout
перед Close. Это закрывает текущий socket; player может повторить сегмент и
дать рывок/буферизацию. Никакого replay после origin byte. Без MITM нельзя
доказать, что именно запись ждала HTTP-ответ (например H2 control); порог/сам
watchdog в этой задаче не менялся. Пассивная idle pause не failure. Новые timing
поля показывают масштаб и время до остановки; это не имитация успеха.

Ordinary/akashi.vk-portal.net: DIRECT_ADDRESS_FAILED — отрицательный per-IP
TCP dial,10мин; family relay-first отдельно требует2 IP. Но localLadderEligible
в browser_origin_ladder.go при одном per-IP failure вовлекает общую лестницу,
которая без LOCAL proof выбирает RELAY прежде browser admission второго IP.
Это отдельное policy coupling: один сбой адреса может отправить ordinary на
relay вместо проверки другого DIRECT адреса. Правила в этой задаче не менялись;
реальная причина TCP-отказа akashi без свежей трассы НЕ установлена. Записано
отдельно, не расширяем вывод до IP/DPI блокировки всей группы VK.

P0 typed-nil test: fixture не задавала PID/path/applicationID, поэтому engine
по своему контракту игнорировал pinned relay и проверял DIRECT1.1.1.1:443.
Доступный endpoint=>ложный FAIL; недоступный=>случайный PASS. На57396ee только
замена адреса на loopback (идентичность всё ещё отсутствует) воспроизвела FAIL10/10
Linux race и Windows EXE/Wine10/10. Productionrouting не менялся. Исправление
задаёт настоящую fixture identity+loopback sentinel и проверяет отсутствие
DIRECT accept: PASS20/20 Linux race и Windows EXE/Wine20/20, Go1.25.3.
Это дефект старого теста с зависимостью от сети, не доказанная регрессия движка.
Native Windows/Go1.27 здесь не запускались; нельзя объявлять их PASS.

Контролируемый TLS GET с проверкой certificate передаёт1.25MiB за3.4s, получает
running promotion/slot release, допускает другую подгруппу и выполняет второй
GET по тому же TLS (opens=1). Transform в portable seam, не raw ISP proof.
Owner новый зачёт/TTL/revoke/multi-subgroup и2160p нужно подтвердить на ПК;
старые196MB владельца — факт дляd28, не приёмка нового кода. VPS/CA/SSH/коды/
CP flags/фильтры/пакетные рецепты/игры не менялись, внешние winws не применялись.


## Riot launcher /24.10.2026
Отсутствовал built-in профиль, потому RiotClientServices TCP443 шёл DIRECT без
общего native deferred origin planner. Добавлен riot-client AUTO и LOCAL preset
riotgames.com/riotcdn.net/pvp.net. Только четыре launcher exe внутри Riot Games/
Riot Client (включая UX-подкаталог); не цепочка всех потомков. VALORANT, League of
Legends, vgc/vgk/драйверы и guard Vanguard/FACEIT не получают этот профиль.
Установочные диски могут быть любыми; имя и родительский каталог проверяются.
Реальные installed files/подписи на ПК здесь не проверены — названия allowlisted,
несовпавшее имя не захватывается. Профиль доступен без установки игры и ничего
не делает, если таких процессов нет. Пользовательский DIRECT override сохранён.

Riot TCP443 использует ту же WinDivert new-TCP reflection/owner SID/birth check,
SNI и DNS-подсказки; PAC не устанавливает. Для известного Riot hostname сначала
до двух public IPv4 адресов из DNS, bounded TCP+TLS first-flight; при молчании
полный ClientHello можно повторить на второй адрес, но после любого origin byte
(даже alert) нельзя. Negative key сеть/profile/hostname/port/IP,10мин, по expiry
повторная проверка. Другие имена/IP/сеть не заимствуют отказ. TCP ACK не success.
После отказа адресов включается общая LOCAL selection: cached verified LOCAL
предпочтителен; пока proof нет — authenticated RELAY и фоновый TLS/certificate/
GET подбор. Auth/clientconfig/CDN с рабочим DIRECT не вовлекаются в relay.
Одного silent SNI недостаточно для вывода о Cloudflare: subnet verdict не вводим.
Diag.13 -Only riot сравнивает actualSNI/example.com по<=2 A на9 основных хостах;
certificate validation сохраняется, foreign cert mismatch = ANSWERED, не PASS;
45с общий soft budget (DNS системный API может длиться дольше), без cookies/URL
авторизации/токенов. Одинаковое молчание двух SNI — endpoint evidence, не доказано
для всей подсети. Никаких постоянных IP-пинов и подключения к VPS по SSH.

riot.status — отдельный readonly handler, club allowlist, <=48KiB; последние
native записи и stage bytes LOCAL/RELAY. Riot никогда не засчитывается как
Chrome/Edge readiness. При изменении egress только новые TCP; stream policy
после безопасного zero-origin first-flight retry виден через PlanReporter.
Лабораторный TLS/certificate+HTTP: первый A silent, второй200; cache изолирован,
TTL ограничен; alert не replay. Эти фикстуры не ISP acceptance и не тест patch
manifest/login. На ПК проверить запуск Riot без winws и diag -Only riot,browser;
Vanguard/игры должны оставаться DIRECT. VPS/CA/SSH/activation не менялись.

Дополнение кRiot: внешний first-flight wrapper теперь получает policy от каждого
фактического OPEN вложенной LOCAL ladder. Без этого поздний безопасный переход
LOCAL→RELAY мог оставлять в riot.status старую LOCAL-policy. TLS regression с
silent LOCAL и работающим authenticated-route seam проверяет актуальный reporter;
без replay после ответа, пакеты/route selection не переписываются.


## Small CDN EOF / recent sibling, послеcb4ee13,24.10.2026
Root по коду: noteSmallEOF и noteClientClose отказывали в neutral при любом
Client/RemoteRetransmits. local_tcp_trace считает serial overlap, не доказывает
application/TLS failure. Fixture с теми же диапазонами tx/rx и RTX воспроизводит
старые failure counters; точный RTX trace конкретного owner flow не приложен,
поэтому не утверждаем, что сеть/Chrome intent того flow установлены полностью.
Hard veto оставлены: known failure, reset, plaintextalert/invalidTLS и отсутствие
полногоSH. RTX-only neutral, shortEOF не success; настоящие failure after reply
считаются. Late data не снимают зафиксированный LOCAL failure.

Sibling раньше требовал still-open+lastRX<5с и не имел network binding. Теперь
network/profile/HTTPS443/googlevideo,>64KiB иlastRX<=30с, включая недавно закрытый
stream из bounded128media history. Prefer same subgroup, затем CDN class.
Недавний RX не доказывает буфер плеера; max1 exposure и>=3min сохраняются.
Waits/checks/denials/reason/age не обнуляются от warm LOCAL confirmation.
Trials=exposures, DataTrials=postSH/transform+>=64KiB completed type23 bytes;
тип rrN/ожидаемый размер HTTP не видны, не blacklist rr5. Positive strong proof
по1MiB/16records/3s сохранён; HTTP/decoder/playback PASS не заявляется.
См. docs/YOUTUBE_LOCAL_FIRST.md. Diag.14 сохраняет Riot.32recent trial records,
RPC latest8 с host/close/timing/neutral-result/sibling-age; native/probe IPC
budget tests покрывают рост metadata. Новые RPC, payload capture не добавлялись.

Freeze: TestSilentPACBootFreezeReapplyAndForeignPolicy baseline Linux race30/30
PASS, Windows EXE/Wine Edge20/20 FAIL (Chrome PASS), rename Access denied.
loadEdgeTransport держал os.Open через defer f.Close до reapplySilentLocked,
который saveEdge/rename заменял тот же target. Windows read handle не имеет
FILE_SHARE_DELETE, Linux rename допускает открытый target. Строка существует
с91d78c79(18.10), это не новая cb4 regression и не только дефект fixture.
Close теперь до reapply, bounded read/parse/ACL/owner/foreign policy сохранены.
С исправлением Windows EXE/Wine freeze20/20 PASS; native Windows здесь нет.
Нет retry/delete workaround и ослабления ACL. VPS/CA/SSH/коды/пакетные recipes/
фильтры/iSCSI/game/lease invariants не менялись. Только owner ISP-тест подтвердит
стоимость проб, реальный CDN success и sustained LOCAL после этого исправления.

Дополнительные regression guards: hard read error не скрывается старым healthy;
известный reset после terminal neutral — PostTrialFailures+FailedAfterReply,
с отзывом будущего LOCAL. Завершение синхронизировано с failure, без двойного
учёта. Admission sibling snapshot неизменяем для trial (соседний check может
обновлять cache, но не историю уже принятой пробы). C# иWPF не менялись.


## 24.10.2026 — ordinary: проверить DNS peer перед RELAY
Старый `localLadderEligible` считал один `DIRECT_ADDRESS_FAILED` достаточным
поводом передать ordinary в openYoutubeLadder. Неподтверждённый cache выбирал
RELAY и очищал DirectCandidates, поэтому живой второй A не проверялся.
Тест с akashi.vk-portal.net и отрицательным первым IP воспроизвёл RELAY первым
OPEN до исправления. Из агрегата9failures нельзя восстановить остальные хосты.

Теперь failed ordinary AUTO обрабатывается до общей LOCAL-лестницы: максимум
два публичных IPv4 из DNS/текущего browser destination, 900ms первые flights
в общем3s бюджете; для native без списка — bounded500ms системный lookup.
Используется уже тестированный address stepper лаунчера без изменения Riot
профиля/кода: per-network/profile/host/IP negative TTL10min, без подсетей.
Полный ClientHello (+допустимый CCS) повторяется только до ЛЮБОГО origin-байта.
TLS alert/частичный ответ не выбрасывается: текущий flow не replay, negative
подсказывает новый. ServerHello не объявляется HTTP/page успехом и не снимает
отрицательный verdict без прежней bounded TLS/HTTP background revalidation.

Только после проверенных/кэшированных отрицательных адресов включается общая
LOCAL/RELAY-лестница; пригодный scoped LOCAL сохраняется. Успешный второй DIRECT
остаётся DIRECT в PlanReporter/native records; established TLS не мигрирует.
Холодные HTTPS443 ordinary AUTO сразу DIRECT: предварительный speculative
relay GET больше не нужен для разрешения незаблокированного сайта. DNS candidates
сохраняются planner. Protected/DPI группы, DoH resolvers, ambiguous origins,
явные правила, частные адреса и configured DIRECT+ обходом не переопределяются.
Игры/античит guards/профиль Riot/GUI не менялись.

Diag.15 в существующем browser.local.probes: последние16 из32 ordinary retry
flows, host/profile, DIRECT/LOCAL/RELAY ипричина, DNS source, максимум4 адресных
observations (до2DIRECT иLOCAL/RELAY), TCP/TLS first flight/TX/RX. Poll timeout
не считается доказанным отказом без negative verdict stepper; TLS ServerHello
не доказывает HTTP. Retained/omitted различают пустую историю иусечение; JSON
bounded<48KB. Payload/URL/cookies/tokens не сохраняются/не выводятся.
Лабораторный verified TLS/HTTP с молчащим первым иработающим вторым IP прошёл,
сохранены no-replay послеalert/первого байта иscope TTL/сеть/profile.
Реальный Windows/ISP результат akashi ивсе прежние9хостов требуют новой diag.


## 25.10.2026 — ordinary .15: потерянная таблица и неверно понятый счётчик
Найдены и воспроизведены две точные причины отсутствия диагностических данных:
1. JSON budget в browser.local.probes сначала выбрасывал ordinary rows, а уже
   потом большие probe/packet traces. На заполненном буфере исчезали все rows.
2. Скрипт печатал NONE_RECORDED даже при ordinary_retained>0/omitted>0.
Теперь сначала сокращаются тяжёлые traces; отсутствие/усечение различаются.
Есть компактный ordinary_ladder с фактическими host/IP/profile/stage/reason/
TX/RX из существующих записей лестницы. Это список сохранённых соединений,
не весь накопленный aggregate; после restart старую историю восстановить нельзя.

ordinary_direct_fallback_attempts из .15 — alias счётчика relay capacity fallback,
а не DNS second-address attempts! В .16 он переименован в capacity counter,
отдельно показаны ordinary_dns_direct_attempts иscope_denials. Отрицательная
метка DIRECT_ADDRESS_FAILED принадлежит адресу/сети/profile и включает Riot;
она не означает, что этот host был одним из12 ordinary RELAY failures.
При отказе admission явно пишутся AMBIGUOUS_DOMAIN_NO_DNS_RETARGET,
NOT_TLS_REQUEST/NOT_HTTPS443, EXPLICIT_RULE_RETAINED идругие scope reasons.
Нельзя адресовать второй DNS IP по угаданному inner-domain в ECH: scope guards
не ослаблены ради прохождения теста. Рабочий второй адрес по точному host всё
так же проверяется DIRECT; ни IP/subnet pin, ни особое правило дляVK не добавлены.
TLS silence/RST не позволяют различить IP/гео/DPI без дополнительных измерений;
их причина остаётся UNPROVEN. Агрегат12 failures сам по себе не содержит host list.
Новая диагностическая проекция позволяет проверить фактический dispatch иотказы,
а owner block перед обновлением печатает ещё сохранившиеся ordinary records.
