# Native Chrome/Edge: ECH и экономный маршрут

Решение владельца 22.10.2026: неизвестный native browser origin по умолчанию
DIRECT; неизвестность больше не отправляет весь браузер на VPS. Это изменение
контракта только native Chrome/Edge, не desktop-приложений, игр или legacy PAC.

Причина 29fdeb5: presence ECH extension (включая GREASE) обнуляла имя и выбирала
OPAQUE_AUTHENTICATED_RELAY_ONLY. GREASE и настоящий ECH нельзя достоверно отличить
по открытому ClientHello. Внутренний SNI не расшифровываем.

Источники метаданных:

- SNI/HTTP Host конкретного TCP: существующий доменный планировщик.
- ECH outer: только подсказка. Известный protected/relay-first outer может усилить
  маршрут до RELAY_REQUIRED и включить TLS/IP recovery; обычный outer не является
  доказательством внутреннего имени.
- Read-only Get-DnsClientCache: до 256 A/AAAA записей, остаточный TTL не продлевается
  и ограничен 300 с; снимок каждые 10 с, запрос до 3 с, вне packet worker.
  Только текущая сеть; при ошибке снимок очищается. Один IP → несколько имён:
  имя не выбирается наугад; protected association ограничивает общий IP relay-only.
  Известный protected outer конкретного потока может выбрать одноимённый DNS
  кандидат среди нескольких aliases только для relay/recovery, без DIRECT.
  Он по-прежнему обозначается как outer hint, а не inner SNI.
  CNAME без A/AAAA, HTTPS/SVCB и приватный DoH-кэш браузера не раскрывают нам inner SNI.
- Без имени/ассоциации: DIRECT к исходному IP. TCP OPEN failure вызывает bounded
  relay retry до отправки app payload; отсутствие первого ответа после отправки
  помечает этот IP для следующих новых соединений (профиль/сеть/IP/порт, TTL 2 мин,
  максимум 256 записей). Установленный TCP не переносится. DNS/53 остаётся DIRECT.

`browser.native.status.records[].domain_evidence` показывает источник, outer,
кандидатов, неоднозначность и confidence. Это подсказки, не браузерная аттестация.
`domain_cache` сообщает доступность системного снимка. Диагностика .4 выводит их.

## Честное ограничение безопасности

Нельзя одновременно гарантировать DIRECT для любого непрозрачного обычного сайта
и отсутствие DIRECT для скрытого protected inner SNI при ECH+DoH на общем CDN IP.
Ни DNS-кэш, ни PTR, ни HTTPS/SVCB не доказывают принадлежность конкретного сокета.
Распознанные protected имена/ассоциации/правила остаются fail-closed. Для полностью
скрытого protected назначения без наблюдаемых связей гарантия недостижима при
запрошенном DIRECT default. Это явно видно в `unknown_policy`; не заявляем no-leak
для такого случая. Строгий вариант потребовал бы relay всех opaque или отдельного
надёжного domain transport/интеграции браузера. Системный DNS/настройки TLS не меняем.

Проверка владельца: обновить только клиент, браузеры оставить открытыми; открыть
VK/Google, YouTube/claude.ai/Telegram Web в новых вкладках и выполнить
`& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube`.
Сравнивать `domain_evidence`, route, origin_attempts и реальные страницы; rx>0 сам
по себе не означает TLS/HTTP PASS. Windows/ISP и влияние ECH/DoH требуют ретеста.

## Telegram и TLS/IP recovery

Для Telegram/Anthropic/OpenAI с relay-first DNS/outer подсказкой native путь перед передачей
браузерного ClientHello выбирает адрес через существующий ограниченный
DNSRecovery: независимый DoH через authenticated relay, полноценный TLS с
проверкой сертификата/SNI и HTTP GET. Два кандидата, единый бюджет до 2 с,
2 параллельных recovery, singleflight, TTL DNS <=5 мин, negative cooldown 30 с.
Постоянного IP-пина нет. Это может добавить bounded проверку первой загрузке;
обычные/неизвестные сайты и YouTube CDN её не выполняют. Для YouTube сохраняется
существующий origin health/retry без дополнительных предварительных GET. При отказе проверки исходный relay-only
маршрут сохраняется, ошибка не является разрешением DIRECT.

Проверочный TLS — отдельное соединение службы. Затем оригинальный ClientHello
браузера передаётся выбранному адресу без изменений. Уже полученные от origin
байты не стираются; retry после ANY origin byte запрещён, включая пятибайтовый
неполный alert. `origin_preflight` показывает проверенный IP и TTL,
`origin_attempts` — дальнейшие реальные попытки приложения. При отсутствии
достоверного имени (несколько DNS имён/скрытый DoH без outer) адрес не перебирается
по предположению о Telegram. Работоспособность Telegram на ISP требует ретеста.
