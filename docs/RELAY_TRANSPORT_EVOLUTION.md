# Совместимое развитие транспорта: только дизайн, 25.10.2026

Основание: M1/M2 в `research/NETWORK_MEASUREMENTS_2026-10.md`. Фактически при IP-адресе SNI пустой, билетный клиент предлагает neexitlag/3 и /2. Лабораторный пул создаёт сессии последовательно. **Нет измерения, доказывающего блокировку relay по ALPN/SNI/частоте**, поэтому реализация/flags/server changes/deployment сейчас не нужны. Текущие ALPN neexitlag/* и TLS/mTLS/ticket/lease/revocation неизменны. Узнаваемость ≠ установленный отказ; название ALPN не исправляет автоматически TLS/QUIC fingerprint.

## Новая версия и SNI

- Если возникнет доказанный транспортный отказ, новый ALPN вводится **дополнительно**, как новая версия протокола, с явным framing/capability agreement. Конкретное имя и выпуск требуют решения владельца. Не выдавать custom wire за HTTP/3 одним ALPN `h3`: HTTP/3 имеет собственные обязательные SETTINGS/streams.
- Старые /1,/2,/3 не переименовываются и не удаляются из listener, пока нужны старые клиенты. /3 — lease1800s и full revocations; новый транспорт не может откатываться на менее строгую авторизацию ради доступности.
- SNI — только собственное имя владельца с проверенным SAN серверного сертификата, DNS/подписанной привязкой к выбранному relay и нормальной hostname verification. Чужие разрешённые домены не подставляются. До отдельного решения о домене/серверном leaf остаётся нынешняя IP SAN verification. CA и fingerprint клиентов не менять.
- Новый протокол публикуется capability в подписанном CP registry отдельно от адреса/relay audience. На старом CP/relay capability отсутствует — остаётся прежний путь. Флаг клиента по умолчанию OFF; отсутствие negotiated новой версии не разрешает отсутствие mTLS/свежего ticket.

## Возможный TCP+TLS fallback

- Отдельный listener TLS1.3+mTLS, bounded multiplex framing и auth ticket/renewal/lease как у /3. По возможности использовать уже имеющиеся Go stdlib/protocol; новых зависимостей без разрешения нет. Указывать negotiated transport в diagnostics.
- Свежие ключи сеанса/one-shot tickets, тот же signed audience/destination public-only/лимиты сообщений/streams/очередей/revocation. Без 0-RTT, без InsecureSkipVerify и без бесконтрольной общей HTTP-прокси.
- QUIC остаётся основным. Только **новое** соединение до возврата app handle может выбрать альтернативный transport по bounded health/budget; timeout/capacity одного origin не означает, что весь relay заблокирован. После origin byte и для established TCP/UDP — никакого replay/migration, переключение только для будущих flows.
- TCP head-of-line может ухудшить UDP/видео; потоки одного профиля не должны блокировать весь клиент. Размеры buffers, max8 sessions/48flows, video12/other4 и probe-reserve пересматриваются лишь по измеренным данным.
- Обычный DNS53 не отправлять в relay. Обновление CP/relay никогда не требуется для клиентских LOCAL измерений.

## Проверки до разрешения на deployment

Матрица: legacy /1→old/new server; ticket /2→old/new; lease /3→old/new; new-version→new; new-version client с flag OFF/без signed capability→old; неизвестный ALPN→явный отказ без insecure downgrade. Проверить свежие ticket/audience, replay, истечение lease, live revocation, shutdown/cancel, потерю QUIC при живом TCP и обратное, границы сообщений, медленный peer, full revocations<=1MiB, idle rotation и no replay после origin byte. Старые клиенты не должны терять действующие sessions во время развёртывания.

Эта матрица для **будущей реализации**: новых listener/версии пока нет, лабораторный PASS их совместимости не заявляется. Существующие /1,/2,/3 проверяются текущими integration tests.

## Deployment/rollback — только после отдельного разрешения

1. Владелец запускает сначала read-only capability/версии/порты/срок leaf. Бэкап /etc/neexitlag, units, бинарников, leaf и БД в закрытый UTC-каталог; проверить полноту/права, не печатать секреты.
2. Независимый systemd rollback timer до первой мутации, атомарная установка, отдельный capability OFF и старые listener сохранены. Проверки только временной локальной identity, затем её revoke.
3. Включать capability после локальных health/handshake/lease/revocation и владельческого small-client acceptance. Отключить/снять timer после подтверждения commit, проверить отсутствие оставшихся transient units.
4. Ошибка — вернуть units/бинарники/config/leaf, снять новую capability и listener. Сохранять security nonce/revocation-записи при rollback; не делать слепой pg_restore поверх публичных запросов (решение владельца). Для новой схемы нужен отдельно проверенный additive rollback. Итог перечисляет реальные версии/схему/сертификат/services/timers/backup path; не обещает неизменённую БД без before snapshot.

Ни deployment, ни read-only SSH в этой задаче не выполнялись. Автоматически применять этот план или выпускать серверный сертификат нельзя.
