# Основной и запасной relay

24.10.2026. Минимальная отказоустойчивость, без балансировки нагрузки и без
изменения production. Список/адреса приходят из подписанного control-plane config.
`VPS-PRIMARY` (Hostkey) и `VPS-01` (старый VPS до12.11) имеют разные ticket audience.
Если VPS-01 удалён из registry, standby выбирается детерминированно по другому
подписанному ID (по имени, без load-balancing); новый audience не переименовывается
в старый. Обновление установщика для такой замены не нужно.
Локальное policy имя `VPS-01` может выбирать любой из этих authenticated providers;
переименовывать серверы/переиспользовать один one-shot ticket нельзя.

## Выбор новых потоков

Пока primary доступен, он первый. Нет здоровых QUIC sessions или существующий
authenticated echo detector подтвердил отказ/деградацию пути — новые opens идут
на здоровый standby. Первый OPEN ограничен1.5с, затем можно открыть у второго
provider в пределах общего caller deadline. Это повтор **создания** потока до
передачи приложению, не replay TLS/данных. При отказе обоих RELAY_REQUIRED остаётся
fail-closed, DIRECT этот provider не возвращает.

После перехода на standby минимум30с hold-down. Возврат — после непрерывных30с
здорового primary и свежего положительного authenticated echo quality. Собственный
quality detector дополнительно требует3good rounds/10с после fault. Единственный
успех/устаревшая история/живой, но молчащий QUIC не подтверждают восстановление.
Отказ standby при доступном primary прерывает ожидание ради доступности. После
долгого простоя30с считаются с первого нового наблюдения selector/status, а не с
неизвестного момента восстановления. Физическая блокировка IP определяется по
реальным session/probe failures; отдельного ICMP или искусственного page PASS нет.

Насыщение48flows/session, отсутствие stream capacity, отказ отдельного origin и
смерть одной сессии при живых peers **не** помечают весь VPS неисправным. Aggregate signed `load=1` также не удаляет
primary provider: доступность/ресурсы своего pool проверяются отдельно. Та же
ошибка видна в per-relay `last_failure_class`/pool diagnostics. Успешный выбор
второго relay для одного нового open не означает глобальный отказ первого.
Пулы8×48 и probe reserve не менялись. Video12/other4 client limits не умножаются
на число серверов; это сохраняет прежний потолок нагрузки каждого ПК.

Signed config polls не сбрасывают hold-down для тех же адресов. Изменившийся
endpoint — новая конфигурация; уже открытые TCP/UDP остаются на своих сессиях,
данные никогда не мигрируют и не переигрываются. Если **сам** их сервер/сессия
умерли, восстановить существующий TCP на другом egress нельзя: приложению нужен
новый поток. Автоматическая protected UDP recovery прежнего кода сохраняется.
Удаление relay из подписанного registry по-прежнему явно закрывает его pool.

## Диагностика

```powershell
& .\tools\windows\relay-status.ps1
& .\tools\windows\relay-traffic.ps1
```

Только live owner-IPC. Не требуют SSH, deployment, Go helper или чтения identity.
`preferred_for_new_opens`/`selection_reason`/hold/healthy_since описывают будущий
выбор. `last_opened_authenticated_relay`, `observed_tcp_session_endpoint`, active
и TX/RX — фактически открытые соединения; старые pinned streams могут продолжать
передавать одновременно через другой relay. UDP identity наблюдается, peer socket
endpoint pool API не раскрывает. Число sessions/available capacity отдельно.
`pool_healthy` — наличие живой admission session, `health` дополнительно содержит
probe outcome; RTT актуален только вместе с ненулевым свежим probe timestamp.
Скорость — payload delta за фактический интервал, не пропускная способность VPS.
Reset counters не выдаются за отрицательную/положительную измеренную скорость.
Для NIC/monthly бюджета нужен отдельно разрешённый meter: без него UNKNOWN.

Diag `2026-10-24.6 -Only browser,youtube` включает те же поля. Ошибки удалённого
origin не печатаются сырой строкой, только bounded failure class. После12.11
старый VPS не гарантируется; заменять запасной сервер надо отдельно через registry,
публичный CA/коды/клиентские сертификаты для самого выбора не меняются.

## Доступные проверки

Детерминированные тесты с fake clock: health flap, stable return, stale echo,
config refresh, healthy peer/capacity/origin isolation; настоящая передача через
старый net.Pipe и отдельные UDP mappings после выбора другого provider, fail-closed
при отказе обоих. Это portable tests selector/wrappers, **не** реальная потеря
Hostkey на Windows и не ISP acceptance. Существующие mTLS/ticket/renewal integration
тесты выполняются в общем Go race; production серверы тестами не используются.
PS7 fixture проверяет live status/reset/legacy/allowlist; PS5.1 syntax/CI gate
подготовлен, native PS5.1 здесь не выполнялся.

Режим fleet и порядок настройки нового узла описаны в [Fleet relay admission](RELAY_FLEET.md).
