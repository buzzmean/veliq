# Общая HTTPS-лестница и данные о блокировках

24.10.2026. Цель — DIRECT для работающего обычного сайта, подтверждённый LOCAL
для DPI, authenticated RELAY при IP/гео-блокировке или пока LOCAL не доказан.
Это операторские категории, не заявление о блокировке каждого сайта на каждом ISP.

`core/originpolicy/registry.json` содержит version/date/source и суффиксы групп:
YouTube, Discord, X, rutracker — DPI; OpenAI, Telegram, Anthropic, Meta — RELAY.
Источник текущих категорий — требования/наблюдения владельца 22–24.10.2026.
Они не выдаются за свежий глобальный замер Роскомнадзора/OONI. Обычные Google,
VK, Яндекс и неизвестные домены отсутствуют в списке и остаются DIRECT.
Suffix matching использует границы DNS-меток, не substring; `evilchatgpt.com`
и `chatgpt.com.evil.net` не являются protected. Required-группы сохраняют нижнюю
границу безопасности, включая вложенные домены и явные попытки DIRECT override.

## Что переиспользуется

Тот же runtime/worker/cache/packet catalog/transform witness, что и у YouTube:
без второй реализации лестницы. Точный origin/profile/network/port/hint-mode,
background max1, bounded cooldown/sweeps/ranking, реальный verified TLS/HTTP
body >64KiB. Known DPI сразу начинает подбор; неподтверждённый пользовательский
поток идёт через RELAY. Не заставляем пользователя ждать или видеть ошибку ради
перебора. Обычный сайт получает этот механизм только после прежнего реального
DIRECT failure evidence; результат не переносится на другие домены или сеть.
Подтверждённый LOCAL используется новыми потоками. TCP после любого origin byte
не мигрирует и не replay; цельный ClientHello повторяется только до первого ответа.

Профиль/процесс/owner SID, explicit BLOCK, private IP/DNS53, VPN/foreign interceptor
и anti-cheat guards остаются прежними. HTTP/3 native по-прежнему откатывается на
TCP. ECH/DNS hints не объявляются inner SNI: LOCAL требует допустимой точной
ассоциации. Все known required hints проверяются до truncation даже для новых
подписанных правил. Неизвестный opaque поток сохраняет согласованный владельцем
DIRECT default и существующий failure recovery; гарантии скрытого домена нет.

Отдельная подтверждённая граница: даже при доступном исходном SNI native
маршрутизация привязана к соединению. На контролируемом общем SAN/IP Chromium
передал последующие REQUIRED authority по уже допущенному DIRECT HTTP/2
соединению; первоначальное REQUIRED-соединение при этом могло корректно идти
через relay. Per-authority PAC и его существующая связка с native AUTO
(`PAC_NATIVE_UPSTREAM`, actual WinDivert) в том же сценарии сохранили изоляцию
и DIRECT для разрешённых имён. Подхват owned policy работающим браузером
и строгая readiness ещё не подтверждены этой проверкой.
[Условия, фактический egress и открытый R1 gate](BROWSER_ORIGIN_REUSE.md).
Это не установленная утечка публичных сайтов и не принятие DIRECT+ или ISP.

## Обновление данных

Origin registry — optional `origins` в подписанном local-catalog, с собственной
версией/датой/источником. Security floor required-групп нельзя ослабить обновлением.
Добавочные signed DPI/RELAY правила применяются в planner, actual open, native
metadata и browser DNS broker. Неизвестные имена посещённых сайтов не публикуются
в club learning; только reviewed DPI scopes из текущих данных. Peers подтверждают
shared candidate локально, не исполняют произвольные команды/бинарники.

Добавление registry меняет default signed data release1→2 (schema остаётся1).
Admin publication теперь требует версию выше bundled release и прежнего файла,
то есть минимум3 для нового release2. Нельзя подписывать изменённые данные под
старым номером: anti-equivocation/rollback остаются строгими. Старый клиент,
которому неизвестны новые поля, отвергнет update и сохранит свой reviewed LKG;
старый config/1MiB revocations/ALPN/tickets/mTLS/activation не меняются.
На production CP обновление данных/endpoint не выполнялось; bundled
client registry не требует повторного deploy VPS.

## Честные ограничения

Реализован HTTPS TCP443/IPv4. HTTP80 LOCAL и собственный browser QUIC fake пока
unsupported; текущий QUIC→TCP fallback сохранён. Discord browser TLS/WebSocket
использует общую лестницу, но успешная TCP-проба не доказывает UDP voice. Desktop
Discord adaptive UDP/voice остаётся прежним; принудительно запускать на нём
непроверенный UDP fake было бы регрессией. Поэтому «Discord voice LOCAL» пока
не подтверждён и не реализован этой TCP-итерацией.

Если публичный root возвращает короткий документ/403/404 или не даёт >64KiB,
это не подтверждение LOCAL. Подбор остаётся ограниченным, foreground — RELAY;
для такого origin понадобится подходящий публичный sample. Повторять неизвестный
пользовательский POST/WebSocket/login после origin byte нельзя. Наличие каталога
не гарантирует работу всех его техник на провайдере. Требуется owner ISP проверка.

Диагностика сохраняет старое имя `youtube_local_ladder` для совместимости,
но `stages[].service` и `records[].service` отделяют YouTube/Discord/X/rutracker/
ordinary. Нельзя приписывать Discord bytes экономии YouTube. `local.catalog`
показывает origin data version и число групп. Monthly budget — отдельный этап.
