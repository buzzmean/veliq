# Учёт relay-трафика и бюджет

24.10.2026. Учёт — наблюдение, не разрешение маршрута. Он не меняет TLS,
lease/revocation или fail-closed и не отключает необходимый relay из-за неизвестной
квоты. Подтверждённый LOCAL по-прежнему выбирается общим origin selector.

## Клиент

`traffic.status`: session/UTC day по profile ID, service, subgroup и причине.
Источник — успешные TCP Read/Write и UDP Send/Receive routing engine при фактически
закреплённом relay route; DIRECT/LOCAL не считаются. Callback вызывается вне engine
lock. Причины различают IP_GEO_REQUIRED, RESOLVER_BOOTSTRAP, LOCAL_HEALTH_NOT_CONFIRMED
и конкретную причину провала LOCAL. Browser origins отделены от standalone apps.
`logical_relay=VPS-01` — policy alias; физический server см. `relay.primary.status`.

Это application payload, включая origin TLS, без QUIC/IP/relay-control overhead.
Суточный файл `traffic-usage.json` в прежнем StateDirectory, atomic/inherited ACL,
flush раз в минуту и при shutdown. Disk IO вне packet accounting lock. Не хранит
ключи/токены; внутренний device ID не выводится IPC. Статистика восстанавливается
только для той же device identity: скопированные image counters игнорируются.
Freeze/replacement identity может сбросить локальный day tally; он не является
клубным биллингом.512keys/session и512/day,2дня, overflow учитывается отдельно,
48крупнейших rows в IPC + omitted count, totals включают overflow.

## Сервер / CP

TCP live TX/RX теперь считаются при каждом успешном io.Copy Write, а не после
закрытия долгого потока. Это application counters; они не подменяют NIC/invoice.
Опциональный sampler читает Linux default IPv4 NIC `/sys/class/net/.../tx_bytes`,
boot epoch hash и boot time. Пакеты не перехватывает. Учитываются транспортные
накладные расходы и другие процессы того же NIC (SSH/обновления тоже оплачиваются).

Relay: `-traffic-state-file <собственный-private-StateDirectory>/traffic.json`,
опционально `-traffic-interface ens3`. CP: `-relay-traffic-file <свой-StateDirectory>/relays.json`.
По умолчанию оба **выключены**, никаких production unit/env/path изменений
не выполняется. Нужны отдельные writable state directories с0700/owner конкретной
службы; не использовать общую папку с рекурсивным chown разных service users.
Неисправный необязательный meter не должен останавливать relay; ошибка/нет отчётов
видны как отсутствующее/устаревшее наблюдение, не как свободная квота.

Relay сэмплирует каждые5с, отправляет raw NIC observation каждые30с через прежний
HTTPS control client и свой relay-specific heartbeat token. Новый endpoint
`/api/v1/relays/traffic` проверяет token hash именно для relay ID; не меняет health,
config, БД schema, activation или credentials. CP самостоятельно интегрирует
counter deltas в atomic file, duplicate/old observation не увеличивает usage и
не освежает timestamp. GET подписан отдельным `relay-traffic` domain/TTL, клиент
проверяет подпись/сроки и не принимает регрессию тех же monthly counters.

Период — UTC календарный месяц. При первом отчёте boot внутри месяца позволяет
учесть NIC TX с этого boot, но трафик предыдущих boots неизвестен. Counter reset,
смена интерфейса, пропущенная граница месяца и stale report обозначены явно.
Короткий sampled boundary даёт погрешность до одного интервала; большой gap не
выдаётся за измеренный полный месяц. Прогноз — продолжение наблюдаемого среднего,
не расписание работы клуба и не счёт провайдера. **Дата сброса квоты Hostkey пока
не установлена**: calendar-month estimate нельзя считать invoice/billing-cycle.

Для VPS-PRIMARY бюджет3,000,000,000,000bytes по данным владельца; у старого VPS
лимит неизвестен. При>=80% известных bytes или прогнозе>=лимита — BUDGET_AT_RISK.
Partial/stale/missing всегда показывают неопределённость; нельзя выводить «0 из3ТБ»
или «квоты хватит» из отсутствующих данных. История ограничена64relay/month rows
(текущий/предыдущий месяц), overflow отклоняется явно. Требуемый fail-closed
трафик при предупреждении не переводится напрямую.

## Команда владельца, без SSH/деплоя

Из корня репозитория после обновления клиента:

```powershell
& .\tools\windows\relay-traffic.ps1
```

Она только читает IPC, не требует Go helper или root password. Legacy CP404/503 →
SERVER_TRAFFIC_UNAVAILABLE_OR_UNSIGNED / USAGE_UNKNOWN; локальные session/day
доступны. Серверный monthly meter сейчас **подготовлен, но не активирован**:
понадобится отдельное разрешение на обновление relay/CP и state-dir flags.
Повторная установка клиента/новые коды/ротация CA для счётчиков не нужны.

Read-only нагрузка текущего Hostkey, команды выполняет только владелец:

```powershell
ssh -o StrictHostKeyChecking=accept-new root@146.0.77.98 'pid=$(systemctl show -p MainPID --value neexitlag-relay); top -b -n 1 -p $pid'
ssh -o StrictHostKeyChecking=accept-new root@146.0.77.98 'ss -su'
ssh -o StrictHostKeyChecking=accept-new root@146.0.77.98 'curl -fsS http://127.0.0.1:9090/metrics | grep -e active_sessions -e active_flows -e tx_bytes -e rx_bytes -e interface_month'
```

9090/loopback — текущий Hostkey fleet template. Live TCP byte fix и monthly series
появятся только после разрешённого будущего server update; отсутствие series не
доказательство отсутствия трафика. UDP socket count `ss` не является количеством
QUIC sessions. Код/команды здесь на VPS не выполнялись.

До включения monthly collector можно только read-only снять текущие NIC counters
и boot time (это **since boot**, не полный месяц; интерфейсы не суммировать):

```powershell
ssh -o StrictHostKeyChecking=accept-new root@146.0.77.98 'date -u; ip -o route show default; for f in /sys/class/net/*/statistics/tx_bytes; do printf %s= $f; cat $f; done; grep btime /proc/stat'
```
