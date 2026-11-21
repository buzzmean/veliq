# Гонка ACK и закрытия отозванной сессии

21.10.2026, локальный Linux, Go race, без VPS/production/установки на ПК.

До изменения выполнено на каждой версии:
`go test -race -count=50 -run '^TestLeaseRenewalReplayAndDeviceBinding$' ./tests/integration`.

| Source | Повторы | FAIL device_revoked | Другие FAIL | PASS |
|---|---:|---:|---:|---:|
| bdbd452, после merge | 50 | 14 | 1 (deadline начального Dial фикстуры) | 35 |
| 83c0c63, до merge | 50 | 21 | 0 | 29 |

Файлы lease_test.go, relay, transport и security совпадают между этими версиями.
Сбой присутствовал до слияний. Разница частот не доказывает различия поведения
версий: это разные расписания горутин. Единственный начальный timeout не принят
за успех и не скрыт; лимиты времени/lease не увеличивались.

`session.renewControl` отправляет отрицательный ACK через QUIC DATAGRAM, а
периодический authorization guard независимо закрывает соединение с
`protocol.RevokedCode` (0xb), `device_revoked`. Постановка DATAGRAM в очередь
не гарантирует доставку до CONNECTION_CLOSE. Старый test helper немедленно
завершал тест при любой ReceiveDatagram ошибке, включая правильный отзыв.

Исправление затрагивает только тест. После публикации отзыва допускается:

- отрицательный ACK с правильным sequence и без продления deadline;
- удалённая QUIC ApplicationError с точным RevokedCode.

В ОБОИХ случаях дополнительно обязательно фактическое закрытие сессии с точным
удалённым RevokedCode; счётчик успешных renewals не увеличивается. Успешный ACK,
EOF, timeout, отмена, иной код и локальное закрытие не являются успехом.
Отдельные негативные тесты проверяют эти варианты, включая timeout с вложенной
ошибкой отзыва. Проверки replay/device key/audience/receipt сохранены.

Второй уже подключённый **production transport.Client** той же идентичности
также обязан закрыться, показать SessionEndReason и Lease.State=device_revoked
и сохранить прежний deadline. После изменения 50/50 повторов прошли вместе
с негативными проверками. В этой приёмке потери причины отзыва у клиента нет;
изменять production protocol/relay/client не потребовалось. Это локальная
интеграционная проверка, не Windows/ISP/production доказательство.

Граница вывода о клиенте: Pool сохраняет RecentSessionEnds/SessionEndReason и
считает device_revoked отдельно от generic SessionFailures. GUI-статус активации
опирается на подписанный конфиг control-plane, опрашиваемый раз в 30 секунд.
Этот тест не доказывает мгновенное обновление GUI после закрытия relay. Transport
причина не теряется, но задержка UI до получения конфигурации остаётся отдельной
границей архитектуры; тестом она не маскируется.

Первый общий прогон с параллельными C#/WPF-сборками прошёл lease-интеграцию, но
получил отдельный TestMidstreamProgressResetsPendingWithoutSocketReplacement /
DIRECT_MIDSTREAM_STALL (60ms). Его код не изменялся; отдельно 20/20 PASS. Ошибка
сохранена в отчёте, таймауты/продуктовый detector не ослаблялись. Выполнен повтор
общего Go gate без параллельных сборок; окончательный результат — CURRENT.md.
