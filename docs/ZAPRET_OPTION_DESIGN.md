# Дополнительный локальный режим zapret: оценка (D2)

Статус: документ, не интеграция/новая зависимость/готовая стратегия. Боевой код,
WinDivert, VPS и текущий рабочий DIRECT+ не меняются. Игры остаются DIRECT.

## На что опирается исследование

Прочитаны текущие core/localstrategy и существующий аудит
[FLOWSEAL_ZAPRET_ANALYSIS.md](FLOWSEAL_ZAPRET_ANALYSIS.md). В нём закреплены
Flowseal eb16c1419057e36b8a36fbe7c959483450e6ac8b и upstream zapret
c4d0b1990129dce2b28095277173ee0d7702d304, просмотренные 14.10.2026.
Это **не проверка актуального upstream HEAD на 21.10** и не доказательство
работы рецептов на ISP владельца. Прежде чем брать код/бинарник, повторить аудит
точной версии/лицензии, проверить происхождение, подпись и hash. Новых файлов
из внешнего проекта сейчас не скачивали/не запускали/не добавляли.

Flowseal — wrapper/списки/сервисные команды, zapret/winws — packet engine.
Широкие фильтры и lifecycle batch-скрипты upstream не являются per-process
маршрутизатором VELIQ и не должны импортироваться как «одна кнопка».
Существующий DIRECT+ уже имеет собственные ограниченные transform/state/evidence.
Дополнительный движок оправдан только измеренным преимуществом над ним.

## Когда он может быть полезен

При DPI-блокировке, где настоящий локальный TCP/UDP transport работает после
разрешённого изменения подачи начальных пакетов: меньше relay bandwidth/CPU,
сохранение исходного egress. Не помогает автоматически при IP/null-route,
недоступном DNS/адресе, ошибке сертификата, origin policy, геоограничении или
отсутствии связности. Нельзя обещать снижение игрового ping.

Решение по домену/сети/профилю: DIRECT → проверенный локальный кандидат → relay,
с отдельными обязательными RELAY_REQUIRED правилами. Protected domain не
понижается в локальный режим без явной авторизации политики. Предыдущий PASS
через включённый внешний VPN не является DIRECT/ISP baseline. Не менять текущие
подтверждённые маршруты YouTube/OpenAI/Discord ради эксперимента.

## Почему не запускать winws рядом с VELIQ по умолчанию

Два NETWORK capture hook могут повторно перехватывать reinjected packets,
менять порядок/ACK/checksum, создавать циклы или задерживать unrelated UDP.
Глобальные upstream IP/port lists могут захватить игру или другой браузер.
Общая DLL/SYS версия/имя сервиса могут конфликтовать; другой driver нельзя
незаметно поставить поверх pinned WinDivert 2.2.2. Широкий UDP/443 не является
доказательством YouTube/Discord. ECH/QUIC/IPv6 нельзя «решить» отключением TLS
проверок, certificates или all-device routing.

Сначала выбрать один backend-владелец пакета. Предпочтительно разбирать нужный
механизм в существующем bounded engine после review, а не импортировать bat.
Если нужен внешний adapter: явный выключенный по умолчанию режим, pinned binary,
строгий список профилей/flows, взаимное исключение capture hooks, отсутствие
нового самостоятельного scanner и системных изменений сторонним wrapper.
Без доказанной per-flow фильтрации такой adapter к release не допускается.

## Безопасный жизненный цикл

- Перед включением проверить конфликтующие VPN/packet filters, owner/SID,
  driver identity, хеш/подпись и права на файлы. Не выключать их молча.
- Обрабатывать только новые разрешённые flows, уже установленные TCP pinned.
  Нет replay прикладных запросов, MITM, чтения содержимого страниц или injection
  кода в браузер/игру. Стратегия — ограниченная обработка сетевых пакетов.
- Нужны bounded conntrack/reassembly, cutoff, max fake/modified bytes/packets,
  idle cleanup, cancellation и reinjection loop protection. Конкретные
  значения и стратегии из памяти не являются production-настройками.
- Probe подтверждает настоящий TLS/HTTP результат; счётчик transform сам по
  себе не успех. NO_TRANSFORM и TRANSFORM_APPLIED_CONNECTION_FAILED различать.
  Записывать SNI/domain/chain/counters/bytes и finite reason, без payload/секретов.
- Нестабильный кандидат получает короткий network/profile/domain cooldown,
  bounded retries. Не переносить результат на другой домен или ISP, не считать
  одиночный ответ sustained health и не устраивать бесконечный подбор на foreground.
- Для разрешённого fallback — authenticated relay. RELAY_REQUIRED остаётся
  fail-closed. Отключение/ошибка режима убирает только собственное состояние,
  не трогает чужие фильтры, системный DNS, сертификаты или default route.

## Проверки и критерии отказа

Лаборатория: raw packet/state tests, fragmented ClientHello, retransmission,
TLS1.2/1.3, GREASE/ECH opaque handling без обещания домена, HTTP2/WebSocket,
QUIC отдельно, IPv4/IPv6 только по фактической поддержке. Одновременные браузеры,
контрольный DIRECT UDP, queue/worker drops, CPU и finite tables. Failure injection
Stop/crash/restart/rollback; чужие policy/state не удаляются.

Короткая ISP-проверка после разрешения владельца: VPN OFF, тот же домен/endpoint,
DNS-кандидаты/сертификат, настоящий ответ/загрузка и before/after latency,
bytes через VPS. Не выдавать TCP ACK, HEAD или TLS alert за рабочую страницу;
C1 address_verified также не является page/video PASS. Воспроизводить cold и
warm cache, контролировать retransmits и новые соединения без рестарта процесса.
При росте DIRECT задержки, leak, malformed traffic, crash или конфликте драйвера
остановить эксперимент, оставить предыдущий рабочий режим.

## Лицензии, объём и решения владельца

Закреплённый аудит указывает MIT для этих upstream revisions; проверять LICENSE
каждой реально поставляемой версии. WinDivert DLL/SYS имеет отдельные подпись,
pins и LGPL distribution/source obligations; наличие MIT wrapper их не отменяет.
Антивирус/античит могут реагировать независимо от лицензии. Не отключать защиту
и не называть режим совместимым со всеми античитами по одному тесту.

Предварительно 1 неделя сравнительного аудита, 2–4 недели изолированного adapter/
engine proof и regression, затем отдельная Windows/ISP/anti-cheat оценка. Это
оценка, а не срок поставки. Решение владельца: нужен ли вообще второй движок,
какие ISP/домены разрешены для trial и кто принимает supply-chain/license review.
До этого — только документ; никакого «рабочего bat» и фонового автозапуска.
