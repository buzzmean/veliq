# NI-2: автоматическое восстановление DNS — план до реализации

Связано с Issue #33. Это согласованный план, не включённая функция NI-1.
Первый функциональный этап и границы: [NI-2](NETWORK_INTELLIGENCE_STAGE2.md).
Код NI-2 должен начаться в отдельной `feat/network-intelligence-stage2-dns` после
согласования этого плана; смешивать его с диагностической веткой нельзя.

## Первый законченный объём

Один атрибутированный native-browser DNS-запрос, который получил проверенный NXDOMAIN,
SERVFAIL либо timeout для разрешённой политикой группы, получает ограниченную попытку
восстановления существующим encrypted recovery. Не объявлять NXDOMAIN доказанной подменой.
Обычные имена, другие приложения и svchost DNS Client остаются прежними.
Глобальные DNS Windows, Secure DNS browser policy, CA и серверные флаги не меняются.

Важное ограничение: `exchangeBrowserDNS` уже отправляет все известные policy-группы через
AUTHENTICATED_RELAY_DOH, поэтому второй identical relay-запрос к тому же provider не является
восстановлением. Сначала fault-injection должен показать конкретный недостающий переход;
если существующий wire broker уже восстанавливает его, достаточно регрессии и диагноза.
Политика добавления новых доменов/приложений требует отдельного подтверждения, не автосписка
из любого NXDOMAIN. Известная доступность DNS не разрешает DIRECT для защищённого сервиса.

## Повторное использование и точки изменения

| Основа | Изменение в NI-2 | Что не создавать |
|---|---|---|
| `browser_dns_wire.go:exchangeBrowserDNS` и `browserDNSDecision` | конечное решение по валидированному qname/qtype, owner PID/birth/path/SID, network generation, enabled и policy revision | второй перехват DNS, новый WinDivert, глобальный resolver |
| `core/browserproxy/dns_wire_doh.go:ExchangeWire` | при доказанном пробеле: перебор следующего существующего фиксированного provider по результату DNS, а не только HTTP/transport; сохранить wire DNSSEC/HTTPS/SVCB/AAAA | новый DoT/DoH стек или сторонние endpoints |
| `browser_dns.go`, `DNSRecovery.Recover` | использовать прежний origin recovery для известного HTTPS-host; сохранять оригинальный SNI/cert и bounded HTTP evidence | новый route cache / ещё один ladder |
| `browser_domain_evidence.go:observeBrowserDNS` | принимать только проверенные подсказки с исходным TTL в прежний network/profile index | глобальные IP→domain пины |
| browser policy / `browserProfile` | заново проверить owner/scope после ожидания, при OFF/сети/профиле отменить результат | требование PAC refresh/перезапуска браузера |
| shared learning | прежняя подписанная cohort/TTL подсказка — только кандидат; обязательна локальная проверка | публикация запросов, сырых DNS/истории, доверие shared как route authorization |

`DNSRecovery` хранит доказательство HTTPS-origin, а не сырой DNS-ответ: его нельзя выдавать
как полноценный wire cache или синтезировать из него AAAA/HTTPS/DNSSEC.
Если понадобятся coalescing/cooldown для wire-запросов, расширить текущий browserDNSRuntime
bounded pending-state (network/profile/revision/qname/qtype/class), без второго постоянного
положительного cache; transaction ID каждого ожидающего восстановить отдельно.

## Последовательность одного запроса

1. Проверить DNS question и текущую process identity/owner. Захват остаётся только текущим
   поддерживаемым IPv4 UDP/TCP53 браузера; неподтверждённые svchost, ECH/DoH, IPv6 не приписывать ему.
2. Выполнить прежний выбранный transport. Проверить ID/question/размер/источник до классификации NI-1.
   TC требует штатного TCP-повтора, NODATA не означает NXDOMAIN; AAAA NODATA не ломает рабочий A.
   Неверный ID/question не становится основанием переключения или DNS hint.
3. Для явно разрешённого случая проверить существующие per-provider попытки и бюджет.
   Восстановление только если остался другой доверенный кандидат, а не повтор того же ответа.
   Системный обычный DNS/53 никогда не туннелируется через relay. TLS/mTLS не ослаблять.
4. Передать fallback в существующий DoH ExchangeWire с общим deadline, отменяемым OFF/сменой scope.
   Предлагаемый первый бюджет — не больше существующих 2с recovery; provider до 1с с разделением
   оставшегося времени, без добавления нового последовательного 2с на каждую ступень.
   Сохранить 16 wire slots/streams и 2 origin-recovery slots; saturation даёт явный capacity state.
5. Валидный альтернативный ответ имеет собственные qtype/TTL/HTTP Age; нулевой TTL не кешировать.
   Два отрицательных ответа не доказывают блокировку. При исчерпании сохранить корректный
   первоначальный ответ/предусмотренную transport-ошибку; не сочинять A и не кэшировать timeout как NXDOMAIN.
6. Повторно проверить owner/network/revision/оптимизацию перед доставкой и добавлением hints.
   Никакой hint от старой сети или отменённого запроса не публикуется.
7. Адрес не равен готовому маршруту: DIRECT → подтверждённый LOCAL → RELAY управляются существующим
   origin ladder, а immutable protected floors сохраняются. DNS recovery не переводит ordinary
   на RELAY и не снимает защищённый floor. Ни handshake, ни CDN403 не доказывают страницу/видео.
   Existing TCP остаётся на прежнем пути; после первого origin-байта replay запрещён.

Отказы восстановления ограничить прежним scope и коротким cooldown (ориентир текущие 30с),
не host-subnet/global ban. После TTL/смены сети возможность обычного пути проверяется заново.
Новые настройки и зависимости не нужны; если потребуется rollout-флаг, локальный opt-in
по умолчанию выключен, без server deployment и без подключения новых IPC без dispatcher-теста.

## Диагностика и критерии приёмки

В существующем DNS record: исходный/итоговый finite status, причина попытки/отказа,
provider index, длительность/бюджет, число coalesced waiters, TTL, scope и результат повторной
проверки owner. Без wire, URL query, nonce, токенов и произвольного stderr.
DNS recovered, origin address verified, sustained HTTP и playback — разные состояния.
Новые независимые counters/cache для лестницы не нужны; соблюсти IPC headroom.

Порядок реализации и проверки в отдельной ветке:

1. Детерминированные fixture: NXDOMAIN/SERVFAIL/timeout, второй provider healthy, оба negative,
   cancellation, capacity, неверный ID/question, TC, A/AAAA NODATA, HTTPS/SVCB/DNSSEC и HTTP Age.
   Зафиксировать, какие уже PASS без изменений; править только воспроизведённый пробел.
2. Сквозной UDP/TCP53 запрос через настоящий broker → проверенный ответ → scoped hint → существующий
   planner. Параллельные разные ID, смена сети/profile/owner/OFF, TTL expiry, invalid/private address,
   отсутствие relay-DNS53, protected fail-closed и отсутствие replay/нового route authority.
3. Go race/vet/build Linux+Windows, PS5.1/PS7 diagnostic fixtures, pinned DLL compilation;
   Windows CI с настоящим существующим capture-путём в изолированной фикстуре, без global DNS.
4. На тестовом Windows: запущенные Chrome/Edge, broken attributed DNS, успешная новая вкладка
   и реальные данные после recovery; VK/Яндекс DIRECT, защищённые сервисы по policy, OFF/выход,
   freeze/network switch. Отдельно показать неподдерживаемый system-owned DNS и encrypted DoH;
   не выдавать отсутствие наблюдения за успешное восстановление.

NI-2 не реализуется до этой границы проектирования. Живая ISP/Windows приёмка NI-1 остаётся
NOT TESTED; CI-блокеры main #35/#36/#37 не исправляются DNS-этапом.
