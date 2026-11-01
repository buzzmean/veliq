# YouTube LOCAL-first: реализация и приёмка

## Аудит старого relay-first (23.10.2026)

`git blame browser_transport.go:356–371`: явный `youtube_relay_first` появился в
79dfaaa8/ad3c69ce (18.10), family grouping —432899d3 (19.10). Он закрывал реальный
DIRECT_STALL на всех8 DNS адресах, повторные холодные таймауты, SNI-блокировку и
отсутствие подтверждённой рабочей LOCAL стратегии. Ранее relay-first ускорял
страницы по сравнению с повторными DIRECT ожиданиями; это не доказательство,
что провайдер требует relay. Владелец теперь подтвердил локальный обход другим
инструментом; предпочтение relay-first отменено новым решением.

`browserScopedLocal` требовал вручную выбранный LocalStrategyID, global Enabled и
verified baseline именно на этой сети. Автоматический native профиль их не имел;
ветка youtube_relay_first к тому же возвращалась до общих AUTO trials. Наличие
пресета youtube само по себе не включало его для браузера.

Собственный Windows TCP backend умеет bounded ClientHello buffering (32KiB/32
captured segments), split/multisplit, disorder и fake TLS с фиксированным TTL2–16.
Fake лежит целиком в старом TCP sequence space (old-sequence fooling), исключая
попадание fake в настоящий TLS stream даже при достаточном TTL. Handshake/ACK/
sequence/checksum проверяются. Payload fake свой, example.org, без заимствованных
файлов. Существующий preset —7 кандидатов, cutoff1 логического ClientHello.
Это исторический аудит исходного движка. С24.10 все64 TCP443 Flowseal rules
имеют native recipes (fakedsplit/hostfakesplit/SYN-data/TS/MD5 и др.); HTTP/QUIC
остаются unsupported, fake templates свои. Полная эквивалентность winws не заявляется. Новые browser-only кандидаты добавляют2 old-sequence
fake +3 настоящих сегмента с disorder, сохраняя потолок5 пакетов на входной.
Сохранённые пресеты и их версия не изменяются.

QUIC в localstrategy — ограниченный drop распознанных Initial для TCP fallback,
а native браузеры уже отклоняют выбранный UDP443 с bounded ICMP. Fake QUIC для
браузеров не добавляется: UDP payload PUBG не доказывает совместимость с QUIC/TLS.
При TCP fallback новая лестница пытается LOCAL перед RELAY. Игровой UDP/guard,
Vanguard/FACEIT, WinDivert filters и private iSCSI3260 не меняются.

## Контракт новой лестницы

Только browser AUTO, youtube-media, HTTPS443/IPv4. OpenAI/Anthropic/Telegram,
явные пользовательские правила, private destinations, DNS53, disabled и другие
приложения остаются вне неё. Обычный Google/VK остаётся DIRECT.

С 24.10.2026 неподтверждённая подгруппа идёт сразу через authenticated RELAY:
foreground не ждёт нерабочую DIRECT/LOCAL попытку. Подбор выполняется в фоне,
один worker на ПК, max12s на кандидат, не чаще cooldown подгруппы. Worker
проверяет живого owner/текущий профиль/сеть/отсутствие конфликтов, останавливается
при shutdown. Очередь наблюдаемых подгрупп ограничена64, кеш256, plans<=57,
score2048. Независимый тик15s продолжает подбор при долгом RELAY HTTP/2 потоке,
без необходимости нового клиентского handshake. Pause30s→1m→2m→4m→5m max,
после полного sweep продолжается следующий, без permanent RELAY/сброса к первому.

Подгруппы разделены: точный account/page/image host; CDN по sn-пулу googlevideo,
profile/network/port/hint-only остаются в ключе. Этот ключ НЕ меняет общий
DIRECT timeout cache.44 catalog plans +9 legacy кандидатов подключены к AUTO;
порядок по измеренным исходам этой сети/подгруппы. Истёкшие данные не являются
подтверждённым LOCAL. Signed catalog остаётся данными, не удалённой командой.

Фоновый GET с полной проверкой TLS/certificate, без cookies/credentials,
читает до128KiB+1 body. 403/404/204, TCP ACK, certificate/handshake bytes,
частичный body и заморозка16KiB НЕ проходят критерий >64KiB body. Для CDN с24.10 разрешена также ограниченная real-flow проба, когда та же стратегия
уже имеет реальный committed transform на любом YouTube-хосте той же сети/profile/
hint-mode, даже если публичный HTTP body не прошёл >64KiB. Это допуск пробы, не
успех CDN: max1 globally, живой получающий RELAY-сосед, >=3мин/subgroup. Проверки
обоих публичных origins >64KiB остаются более сильным сигналом, но не тупиком.
С24.10 (послеd28dda8) сильный running proof засчитывается без Close: полный
ServerHello, подтверждённый transform, последующая запись браузера, >=1MiB RX
после SH и >=1MiB в >=16 завершённых TLS type23 records, >=3с между первым и
последним наблюдённым application RX, свежий RX<=3с. Это sustained transport,
не доказательство playback/HTTP. Простой после быстрого burst не набирает3с.
TrialSuccesses/StrongPromotions увеличиваются один раз, scope сразу LOCAL10мин.
Глобальный слот освобождён для следующей НЕПОДТВЕРЖДЁННОЙ пробы; established
TLS остаётся на том же socket/egress. Max1 unproven/recent RELAY media<=30с (та же сеть/profile/HTTPS443)/3мин
на повторные пробы той же подгруппы сохранены. Старый путь из3 более слабых
закрытых sustained потоков (>=64KiB завершённых type23 bytes +postSH write/transform каждый) оставлен как альтернатива.

Реальный RST/TLS/IO/WatchMidstream timeout после running promotion отзывает LOCAL
для будущих flows и учитывается PostPromotionFailures/FailedAfterReply; прошлый
сильный успех не стирается. Это НЕ дополнительная TrialFailure уже завершённой
пробы. Малый EOF с0<rx<64KiB, без известного failure, RST/alert/
invalid TLS нейтрален (RemoteSmallEOFInconclusive), не success и не bad score.
Зашифрованный Google idle/abandon/alert без MITM не различим: нейтральный исход
с3мин cooldown не утверждает исправность. EOF без ответа, reset и таймаут остаются
отрицательными. Холодный CDN больше не обязан ждать6мин+Close, но без подходящего
нового flow/сильного proof срок LOCAL не гарантируется.

Граница повтора прежняя: только полный ClientHello(+dummy CCS)<=64KiB до ЛЮБОГО
origin byte; early-data/application/partial hello и TLS alert не переигрываются.
LOCAL→RELAY при нулевом ответе укладывается в900ms first-flight timeout; после
ServerHello текущий TLS не переносится. Video12/other4 admission не меняется.

Для ECH однозначная DNS association привязывает LOCAL к точному IP, процессу и
порту с TTL; `TrustedOrigin=false`, segmentation по абсолютным offsets. Это
routing hint, не доказательство внутреннего SNI. Смешанные/неоднозначные/protected
подсказки не разрешают LOCAL. Никакого decrypt/MITM, отключения TLS или глобальной
настройки Chrome Secure DNS.

**Нельзя бесшовно перенести установившийся TLS на другой egress.** После любого
байта origin повтор запрещён, в том числе после alert. Реальный unanswered
outbound midstream stall помечает ступень для нового соединения; старый TLS не
переигрывается. Тишина после8–64KiB в течение4с — только hint для следующего
потока, текущий не закрывается этим признаком: без расшифровки невозможно отличить
«HTTP/2 закончил короткий ответ» от зависшей загрузки. Браузер может повторить
запрос сам; гарантировать отсутствие видимой ошибки после midstream failure
нельзя. Existing TCP остаётся pinned; браузеры не закрываются/не перезапускаются.

## Статус проверок

Контролируемые тесты проверяют настоящий TLS с SAN/certificate validation и
GET200/128KiB, три guarded CDN trial и warm LOCAL; холодный foreground сразу
RELAY. Transform и live-relay counters в portable fixture задаются seam: это
не WinDivert injection/ISP proof. Отдельно проверяются оба public prerequisites,
16KiB stall/truncation, short403/404, TTL/isolation/sweeps/ranking/cooldown/max1,
shutdown worker, mixed shared-IP hints до diagnostic truncation, no replay после
origin byte. Native Windows/PS5.1/реальный player/1080p LOCAL не проверены.

## Обновление и короткая приёмка владельца

Достаточно обновления клиента; для LOCAL-first deployment VPS не нужен. Из корня
репозитория, PowerShell администратора под SID владельца. Браузеры оставьте открытыми.
`Close-VeliqGuiForUpdate` закрывает только VELIQ (не браузеры), освобождая старые
recovery helpers, если они есть. На обычном ПК GUI затем запускайте обычным ярлыком,
на уже подтверждённом UAC-off ПК он остаётся full-admin как раньше. Служба после
обновления сама поднимает AUTO; никаких PAC/restart диалогов этот код не добавляет.

```powershell
git switch main
git pull --ff-only origin main
$m=Get-Content -Raw "$env:ProgramData\neexitlag\service.json" | ConvertFrom-Json
& .\tools\windows\build-e2e.ps1 -DriverDirectory $m.driver.directory
& .\tools\windows\Close-VeliqGuiForUpdate.ps1
& .\tools\windows\update-service.ps1
# В уже открытом Chrome/Edge: новая вкладка YouTube, 1080p2мин, перемотать2–3раза.
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

В `YouTube local ladder` сравнить `stage=LOCAL`/имя стратегии, committed transform,
RX и `transport_confirmed`, а также `stage=RELAY` RX до/после. При работающем LOCAL
**новый** video TLS payload через relay должен быть около0; CP/ticket/DNS DoH/echo
трафик и старые pinned relay-сессии в это обещание не входят. Проверить VK/обычный
Google DIRECT, OpenAI RELAY_REQUIRED, затем отключение оптимизации → обычный сайт.
`diag-result.txt` не коммитить. Неподтверждённый transform не выдавать за «точно не
применялся», если ledger потерян; `NOT_CONFIRMED` — отсутствие положительного proof.

Новые release/native Windows CI могут не стартовать из-за известного account
billing gate: `steps=[]` не является выполненными тестами. Доступная проверка
pinned DLL под Wine — компиляция/CRC, не WinDivertOpen/kernel/ISP acceptance.

P0 Hostkey отдельно готовит сервер и автоматически обновляет существующую службу
на ПК запуска (без переустановки/новой identity): docs/RELAY_HOSTKEY_P0.md. Не
запускайте эту remote mutation как обязательный шаг проверки LOCAL-first.

## Общий движок24.10: публичные протоколы Discord
Исправления raw delegation/LSO/native recipes относятся ко всем DPI группам.
Для cdn.discordapp.com — PNG GET по одному TLS до >64KiB; gateway.discord.gg —
публичный WSS Hello+3пары nonce ping/pong; discord.gg — точный HTTPS redirect.
Контрольные проверки явно OK_CONTROL_NOT_BULK, не bulk/page/login PASS.
Googlevideo критерии >64KiB/3success/live sibling не меняются, shared flags OFF.
Telegram/Meta/OpenAI/Anthropic RELAY_REQUIRED и VK/Яндекс DIRECT сохраняются.


## Малые CDN EOF и sibling — послеcb4ee13
Вcb4 retransmit counters были hard veto нейтральности, в том числе после
полного ServerHello. Это воспроизведено rx2717/6579/7109, tx5791, FIN+ACK и
ненулевые Client/RemoteRetransmits: ошибочно TrialFailure/FailedAfterReply.
Serial overlap не отличает потерю/повтор от переупорядочивания; сам по себе не
доказывает отказ. Теперь малый EOF0<rx<64KiB с fullSH, без known failure/RST/
plaintextalert/invalidTLS нейтрален, даже с RTX. Early EOF безSH/байтов, reset,
реальный watchdog timeout/известная ошибка сохраняются отрицательными.
EOF освобождает slot до позднего Close; once остаётся привязан к конкретной
пробе. Late data после зафиксированного failure не восстанавливают LOCAL-кэш.

Guard sibling использует последние128 media records, тот же network/profile,
HTTPS443 и googlevideo class, >64KiB RX с последним чтением<=30с. Открытый поток
не обязателен; same sn-subgroup предпочтительнее class sibling. Это свежая
история приёма, не гарантия живого рабочего сегмента/буфера плеера. После30с,
на другой сети/profile, по page/ordinary Google или HTTP80 — допуска нет.
Max1 unproven/cooldown>=3мин сохранены, историей они не обходятся. Age/reason и
число ожиданий записываются в cache; обычный warm LOCAL не стирает эти счётчики.

Ожидаемый размер ответа и тип HTTP-запроса за TLS неизвестны. rr5 не означает
redirector: он может отдавать большие media segments. Без MITM нельзя заранее
отделить preconnect/control/segment и обещать выбрать только сегментный flow.
Поэтому Trials остаётся числом LOCAL-exposures (цена риска), DataTrials — новым
отдельным числом потоков с fullSH/postSH write/committed и >=64KiB завершённых
outer type23 bytes. Короткий EOF не data trial, не bad score и не success.
Legacy weak success тоже требует этого data-признака; strong promotion по
>=1MiB/16records/3s не менялась. Следующая eligible новая connection может стать
пробой после cooldown. Принудительно разрывать работающий H2 для неё нельзя.

Diag.14 (13 уже занята Riot): последние8 из32 trial observations независимо от
кольца foreground records: exact rrN host, TX/RX, TrialResult, DataTrial,
close-side/FIN/RST/RTX, Hello→close/lastRX→close, sibling reason/age_at_admission.
Недостающая packet trace — NOT_OBSERVED, не выдуманное направление. Размер
expected reply/HTTP status/redirect/playback не объявляются известными.
RPC responses остаются bounded; header-only history без payload/URL/ключей.
Контролируемые TLS/HTTP/race/Wine tests не заменяют ISP приёмку2160p.

Поздний известный RST после уже нейтрального terminal исхода не теряется:
PostTrialFailures/FailedAfterReply учитывают его отдельно, история обновляется
наFAILED иfuture LOCAL отзывается. Исторический inconclusive не стирается.
Hard read I/O после healthy также остаётся failure; обычный EOF после sustained
не приравнивается автоматически к отказу. Outcome/failure синхронизированы,
чтобы не считать один сбой дважды. Sibling row хранит снимок именно допуска,
а не новый deny-check того же cache key, пришедший пока открывался upstream.


### 24.10.2026 — neutral callback и быстрый следующий поток (diag.15)
Старый `failure(...EOF...)` callback первого TLS-flight помечал ответ нейтральным,
но не вызывал finishObservation. Если wrapper возвращал EOF без следующего Read
meter, слот оставался занят до Close, которое могло долго не приходить. Тест
callback без Read/Close воспроизвёл ActiveTrial=true инулевые inconclusive.
Теперь нейтральный callback немедленно финализирует exposure, освобождает слот
и записывает slot_released_at/reason; поздний Close не освобождает новую пробу
даже той же подгруппы/стратегии. Существующий TCP не мигрирует/не replay.

Для 0<rx<64KiB с full ServerHello и нейтральным EOF/клиентским FIN разрешён
следующий НОВЫЙ flow без 3мин ожидания: максимум3 таких коротких подряд на
network/profile/subgroup. После третьего — ALL_SMALL_NO_DATA_LIMIT_COOLDOWN
>=3мин; пустой/неизвестный outcome не получает исключение. Счётчик не означает
успех, HTTP redirect или сегмент. Реальные RST/alert/timeout/post-reply I/O
остаются failure с обычным cooldown/отзывом LOCAL для будущих соединений.
Max1 глобально и прежний eligible recent RELAY media<=30с проверяются при
каждом допуске; исключение не создаёт sibling и не обходит expired proof.
Diag.15: slot_active, время/причина освобождения, neutral_short_attempt,
neutral_short_streak, cooldown_until/wait_ms, admission и прежние bytes/data_trials.
Нативная Windows/PS5.1/ISP экономия не подтверждается лабораторией.


### 25.10.2026 — bulk-qualified admission и идентичность пробы (.16)
Раньше проба выбиралась при OPEN первого нового googlevideo TCP до отправки
ClientHello/HTTP. Его будущий объём неизвестен; rr5/rr6 не классификаторы.
Выбрать маршрут после прикладного TLS-write нельзя: origin уже ответил,
другой egress потребовал бы запрещённый replay/migration established TLS.
Минимальная эвристика теперь требует >1MiB RELAY RX<=30с по тому же host либо
распознанному sn-cluster той же сети/profile/HTTPS443. Unclassified cluster
не переносит proof на другой host. Сохраняются прежний scoped sibling, transform
qualification, max1, cooldown иограниченный neutral retry. Эта эвристика повышает
вероятность сегментного потока, но не раскрывает запрос и не гарантирует его
размер. При отсутствии нового eligible TCP LOCAL-пробы может не быть: старый H2
не разрывается и не переносится. ISP экономия/2160p не объявляются доказанными.

Каждый admission получил монотонный trial_id и отдельный record_id, host/IP,
started_at, active_record_result/matches. Callback/Close/strong promotion
сверяют trial_id: старое закрытие не завершает новую пробу той же группы.
Дополнительно воспроизведено, что hard-failure callback держал слот до Read/Close;
теперь он финализируется сразу, как уже делал neutral EOF. По данным .15 безID
невозможно доказать, что active после старого EOF — stale либо новый trial.

Реальный CDN LOCAL failure по конкретному endpoint теперь имеет negativeTTL10min
по network/profile/subgroup/host/IP/strategy (max256). Сохраняются failures/
failed_after_reply и >=3мин real-failure trial cooldown; не сбрасываются proof,
Tried/общая квалификация стратегии по всей подгруппе. Новый flow плохого host/IP
выбирает RELAY, другая IP/host той же группы может сохранять LOCAL. Этот verdict
не доказывает DPI/IP/гео причину. Guard/capacity без отправки LOCAL по-прежнему
может отключить LOCAL по прежнему правилу. Established поток не replay.

## 01.11.2026 — холодный старт: сохранить допуск после короткого публичного ответа

Воспроизведён дефект цепочки фоновой проверки: `recordLocalProbe` сохранял
свидетельство committed transform, затем `BACKGROUND_NOT_SUSTAINED_OR_NO_TRANSFORM`
помечал эту же стратегию `Tried` для CDN, очищал `Qualified` и выставлял
трёхминутный cooldown. Проверка публичной страницы с настоящим TLS/HTTP 403
воспроизвела это и для видимого SNI, и для DNS hint. Короткий публичный ответ
не является отказом реального googlevideo-потока.

Теперь свежий scoped transform, не отвергнутый реальным CDN-исходом, сохраняет
допуск к существующей ограниченной пробе. Выбор и обновление квалификации
атомарны относительно реального отказа. Фоновая ошибка остаётся в диагностике
и `BackgroundFailures`; она не создаёт success, peer proof или подтверждённый
LOCAL. Действующая media confirmation сохраняет прежний маршрут и срок.
Без committed transform, при чужой сети/profile/hint-mode, истёкшем proof или
реальном отказе прежние ограничения остаются. DNS/guard failures не получают
нового исключения.

Max1, >1MiB recent RELAY того же host/sn-cluster, cooldown реального отказа и
endpoint negative TTL сохранены. После origin bytes нет replay или переноса
TCP; старый RELAY HTTP/2 может продолжать нести видео. Это устранение лишнего
запрета пробы, а не гарантия LOCAL с первого соединения.

Лабораторный тест проверяет настоящие TLS/HTTP 403 и последовательность callbacks;
committed transform задан seam, не драйвером. Затем проверяются допуск нового
flow, max1, bulk guard, реальный failure callback, cooldown и endpoint TTL.
Отдельный `YouTube LOCAL` workflow выполняет Go race/vet/build на Windows и
компиляцию фильтров закреплённой DLL. Установка драйвера и ISP в него не входят.

### Следующая приёмка R1 на Windows/ISP

Предыдущий [замер при сохранённом proof](https://github.com/buzzmean/veliq/pull/13)
сообщал 534 МБ LOCAL / 0 МБ googlevideo RELAY за 3 мин при 2160p после восстановления сети.
Это замер владельца от 25.10, а не проверка данной правки. Proof хранится 24 ч;
на бездисковой машине после отката его может не быть.

1. На отдельном тестовом ПК после холодной загрузки без ранее сохранённого proof
   записать SHA сборки и исходную диагностику. Новый профиль браузера сам по себе
   не очищает proof службы. Не удалять state рабочей установки ради замера.
2. В уже открытом Chrome/Edge открыть новую вкладку, выбрать 2160p и смотреть 10 мин
   с двумя перемотками/автопереходом. Браузер не закрывать; старые TCP не разрывать.
   Сохранить отчёты `& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube` из корня checkout
   до просмотра, через 2 мин и 10 мин.
3. Сопоставить background outcome/committed transform, `Qualified`, trial IDs,
   admission reason, DataTrials/StrongPromotions/BurstPromotions/PeerProvisional
   и дельты LOCAL/RELAY RX. После неуспешного публичного body при committed
   transform следующий подходящий **новый** media TCP должен получить пробу
   без лишнего cooldown от публичной проверки. При отсутствии нового TCP или
   scoped bulk RELAY эта правка не обещает пробу.
4. Отдельно измерить тёплый запуск с сохранённым proof. Googlevideo, страницы
   youtube.com, CP/DNS и старые pinned RELAY flows считать раздельно. Проверить
   обычные сайты DIRECT, protected fail-closed и обычный сайт после OFF.

R1 остаётся открытым до реальной проверки холодного старта/экономии и Discord
LOCAL с собеседником. Никакой результат этого теста не закрывает клубный пилот.

### Сквозная Windows-фикстура холодного старта

`TestWindowsCDNColdFlowThroughBackgroundAndLocalPromotion` проходит полный
служебный путь для SNI и DNS hint: пустой runtime → реальный RELAY HTTPS body
>1MiB → асинхронный публичный TLS/403 → новый guarded LOCAL flow → running
strong promotion → LOCAL для другой sn-подгруппы. Квалификация, sibling RX,
trial outcomes и promotion counters заранее не заполняются.

В фикстуре настоящий Windows PID/birth/path отдельного тестового exe, реальные
TLS/HTTP и QUIC+mTLS с одноразовым ticket. Origin различает RELAY и LOCAL по
source IP. После promotion проверяется ещё один HTTP-запрос по прежнему RELAY
TLS: он сохраняет egress и не создаёт новый relay flow. Подменённый birth
отклоняется службой до открытия upstream.

Границы: процесс — тестовый exe, не Chrome; DNS и сопоставление публичного IP
с loopback заданы фикстурой; committed transform — свидетельство, задаваемое
тестовым backend после фактической записи в точный socket tuple. WinDivert
пакеты не инжектируются. Это проверка связности службы и реального переноса
байтов, не доказательство обхода DPI или экономии у провайдера.

### Смена настроек во время фоновой пробы

Фоновая проверка запоминает сеть и ревизию политики профиля при запуске.
Перед каждым своим DoH/LOCAL открытием она проверяет текущего владельца,
Optimize/Automatic, профиль и свежесть сети, включая VPN/конфликты. Эта проверка
выполняется до совместимого DIRECT для старого PAC: фоновая проба не может
воспользоваться разрешением обычного браузерного запроса после OFF.

После DNS и HTTP результат повторно проверяется перед записью proof/learning.
Устаревшая проба отменяется без BackgroundFailures, Tried и нового cooldown;
её собственная задержка следующего запуска освобождается с причиной
`BACKGROUND_POLICY_CHANGED`. Более новый cooldown от настоящего media failure
сохраняется. Реальные сетевые ошибки при неизменной политике учитываются как
раньше. Существующие пользовательские TCP-потоки остаются на своих маршрутах.

`TestWindowsYouTubeBackgroundPolicyChange*` синхронизирует изменение настроек
с ожиданием DNS и публичного TLS/403. Проверяются OFF, Automatic OFF, DIRECT
профиль, новое правило, смена сети и VPN; неизменный профиль и правка другого
приложения служат положительными контролями. Отдельно проверяются обычный
cached-PAC запрос после OFF и сохранение более нового media failure.
Windows PID/birth/path и TLS настоящие; DNS/relay/transform используются как
изолированные seams, все сокеты ведут на loopback. Это не приёмка на ISP.
