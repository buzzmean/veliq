# Network Intelligence: этап 1 — свидетельства отказа

Ветка `feat/network-intelligence-stage1` создана от `17bae3498da3b0204c6faf83e0657608baa3b968`.
Связано с Issue #33. Это небольшой диагностический этап; полная автоматическая доступность сервисов не заявляется.
Код аккаунтов/подписок, UI PR #34, VPS, глобальные DNS Windows, CA и WinDivert не меняются.

## Аудит и используемая основа

| Существующий механизм | Использование и ограничение |
|---|---|
| `core/browserproxy/dns_recovery.go`, `services/client-service/browser_dns*.go` | Собственные DNS транзакции атрибутированных браузеров, scoped TTL/hints, encrypted recovery и безопасные политики. Новый резолвер не добавлен. NXDOMAIN/SERVFAIL ранее попадали в общий `DNS_RESPONSE` с нулём адресов; теперь различаются в диагностике. Ответ браузеру не переписывается. |
| `core/netdiagnostic/host.go` и `tools/network-check` | Уже измеряют DNS/TCP/TLS/HTTP. Добавлен общий конечный диагноз; ошибка OPEN не выдаётся за доказанный сбой SYN, NXDOMAIN не выдаётся за доказанную подмену. |
| `browser_local_selection.go`, `browser_youtube_local.go`, `browser_origin_ladder.go` | Существующие подтверждения transform/объёма, per-network/profile/origin cache, max1 CDN trial, cooldown и отказ от replay после origin-байта. Новый picker/cache не создаётся. |
| `core/browserproxy/firstflight*`, `midstream.go` | Уже переключают допустимый первый ClientHello до ответа и отбраковывают зависший путь для будущих соединений. Established TLS не мигрирует. Новый тест соединяет настоящий watchdog с существующим scoped LOCAL cache. |
| `browser_shared_learning.go`, `core/locallearning` | Подписанный кандидат с cohort/TTL и обязательной локальной проверкой. Не меняются; диагноз сам по себе не авторизует маршрут и ничего не публикует в shared learning. |
| `browser_probe_evidence.go`, `browser.native.status` | Сохраняют bounded evidence. Добавлен `diagnosis` и network/profile correlation в прежние записи; native сохраняет свой owner PID/birth и flow id. DNS имеет отдельный query id; это не доказательство принадлежности DNS конкретному TCP. |

Полезная идея Zapret 2/«22» — разделять стадии отказа, проверять передачу, а затем ограниченно перебирать стратегии в том же scope.
Использован существующий обзор `docs/research/ZAPRET_WIKI_2026-10.md`. Пороги retransmit/TTL/AS из материалов сообщества не принимаются за доказанный фильтр конкретного ISP;
новые fake-пакеты, внешние бинарники, зависимости и глобальные настройки не добавлялись.

## Реализовано

- DNS: отдельные NXDOMAIN, SERVFAIL, REFUSED, NODATA, truncated, invalid reply, timeout и cancel.
  Неподходящие ID/question не становятся свидетельством отказа имени и не добавляют hints.
  Успешный HTTPS/SVCB/CNAME ответ без IP-подсказок не приравнивается к NXDOMAIN.
- TCP/TLS/HTTP: активная TCP-проба отделена от неоднозначного RELAY_OR_TCP_OPEN;
  проверка сертификата, TLS reset/timeout, HTTP 403 и передача тела получают разные состояния.
- Ошибка закрытого сокета после отмены пробы сохраняет известную причину context, а не общий IO_FAILED.
  Успешные ответы и ошибки проверки сертификатов не переписываются.
- TLS ServerHello и зашифрованные type23-записи не означают работу страницы.
  Только собственная проверенная HTTP-проба может получить `PUBLIC_BODY_TRANSFER_VERIFIED`; это не пользовательская страница или видео.
- Существующий midstream watchdog отображается как `UNANSWERED_REQUEST_STALL_NOT_PLAYBACK_PROOF`.
  Проверены отказ от нерабочего LOCAL для нового соединения, сохранение другой сети и запрет protected LOCAL.
- `diag-no-vpn.ps1` версия `.17` выводит конечные состояния через allowlist полей без payload/токенов.
  IPC-методы не добавлялись: `browser.native.status` и `browser.local.probes` используют прежний диспетчер.
  DNS и остальные записи обрезаются в копии snapshot, чтобы сохранить IPC headroom.

## Что не реализовано этим этапом

- Пассивное наблюдение TLS не знает `video.paused`, `currentTime`, `readyState`, полноту буфера или содержимое H2.
  Пауза/тишина не объявляется остановкой воспроизведения; `page_verified` и `playback_verified` остаются false.
- Не добавлены новый каталог Gemini, пересмотр immutable RELAY floors Meta или UI готовности.
- Порядок маршрутизации не переписан: ordinary остаётся DIRECT, защищённые группы fail-closed.
  В текущей основе известные DPI-группы могут временно идти foreground RELAY до подтверждения LOCAL;
  полное DIRECT-first восстановление этих групп и автоматическое восстановление при NXDOMAIN — дальнейший этап, не заявленный результат этой правки.
- Нет новых глобальных периодических проб и принудительного разрыва браузерных/чужих сокетов.
  Уже существующий watchdog может закрыть свой зависший DIRECT/LOCAL tunnel; соединение с новым egress и replay не выполняются.
- Реальная работа YouTube, Gemini, Instagram, Secure DNS/ECH, IPv6 и ISP не подтверждается лабораторией.

## Проверки и Windows-приёмка

Автотесты: соответствие DNS ID/question, NXDOMAIN/SERVFAIL/NODATA/TC;
настоящие локальные TLS/HTTP 200 с телом >64КиБ, 403, остановка тела после 17КиБ, неверное имя сертификата;
нейтральное закрытие, midstream failure и scoped cache; сохранение IPC лимита; secret allowlist PS5.1/7.
Существующие тесты replay/fail-closed/LOCAL validation/shared learning сохраняются.

Отдельный Windows workflow `Network Intelligence stage1` выполняет целевые race-регрессии, обе версии PowerShell и pinned DLL compiler без открытия драйвера.
Общий Verify остаётся включённым. Сбой старого теста на базе main не превращает целевой PASS в полный PASS и не исправляется переносом PR #32.

На базе `17bae34` уже подтверждены отдельные ошибки: Verify `41265606928`, Python
`test_atomic_update_health_rollback_and_preserving_uninstall` (test_relay_lifecycle.py:142, exit 1),
Windows native UI `Empty visual: actual-RelayChoice`. Они не исправляются в этой ветке и не являются доказательством ошибки NI.
Локально выполнены полный Go race с PostgreSQL17, vet/build Linux+Windows, PS7 три затронутые диагностические фикстуры и 30 повторов целевых race-регрессий.
Проверки PS5.1/pinned DLL/Windows runtime должны оцениваться по новому focused workflow, а реальный ISP — только на ПК.

На отдельном Windows-ПК после проверки CI:

1. Сохранить текущую версию/диагностику и обновить только клиент из этой ветки обычным `build-e2e.ps1` → `update-service.ps1`.
   Не запускать VPS/bootstrap/CA-команды, GUI не пересобирать; браузеры не закрывать.
2. В уже запущенном Chrome и Edge открыть YouTube и воспроизводить 10–20 минут с перемотками.
   Снять `& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube`.
3. В изолированной сетевой фикстуре получить NXDOMAIN, SERVFAIL, TCP reset, неверный TLS сертификат и остановку HTTP-тела.
   Не менять глобальные DNS или production policy ради этих инъекций. Сверить `diagnosis`, network/profile/id, bytes и путь новой TCP-сессии.
4. Проверить, что пауза/полный буфер не создают ложного playback failure, а известный отказ не объявляется «сайт работает».
   Подтвердить фактическое восстановление в новых вкладках отдельно; автоматическое восстановление playback пока не обещается.
5. Проверить DIRECT для VK/Яндекса и неизменный fail-closed для защищённых сервисов; проверить OFF/выход и чужие профили.
   Не считать существующий поток перемещённым на другой egress. Gemini/Instagram — отдельная ещё не закрытая приёмка.
