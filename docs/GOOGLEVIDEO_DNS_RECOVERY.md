# Googlevideo: DNS-адрес и результат HTTP — разные проверки

C1, 21.10.2026. Без production/VPS изменений, без IP-пинов и системного DNS.

Воспроизведён дефект: при ошибке системного resolver DoH давал рабочий адрес,
TLS с исходным googlevideo SNI/проверкой сертификата проходил, полный GET /
возвращал 403/404. DNSRecovery требовал 2xx/3xx и возвращал
DNS_ALTERNATIVE_ORIGIN_UNVERIFIED; верхний слой показывал ORIGIN_DNS_FAILED.
Корень CDN без подписанного URL видеозапроса не обязан отдавать страницу.

Исправление узкое: только googlevideo.com и его настоящие поддомены допускают
полный, успешно разобранный HTTP 403/404 после проверенного TLS как доказательство
адреса. Новое address_verified=true; verified (успешный HTTP probe) остаётся false.
Probe=DNS_RELAY_ADDRESS_VERIFIED. Это **не PASS страницы, авторизации или видео**.
Для остальных доменов, lookalike suffix, 5xx, пустого/оборванного ответа, timeout
и неверного сертификата прежний строгий результат сохранён. Не принимаются TCP
ACK, TLS alert, HEAD или неподтверждённые HTTP заголовки.

Кэш по прежнему network/profile/revision/domain/port/relay, до настоящего DNS TTL,
максимум 5 минут; отрицательный cooldown 30с, singleflight, 2 recovery workers,
максимум 2 кандидата и общий бюджет сохранены. Новые browser connections используют
восстановленный адрес через RELAY_REQUIRED; DIRECT fallback не добавлен, явный
DIRECT+ не переопределяется, текущие TCP не мигрируют. Восьмитуннельный media limit
и accounting не менялись. DoH — существующий authenticated relay HTTPS, не DNS/53.

Диагностика 2026-10-21.1 показывает domain/destination, address_verified,
http_probe_success, http_status, phase/failure и expires. Ответ/URL с токеном,
Cookie и тело не записываются. Старый сервис без новых полей читается безопасно.

Проверки: до исправления контролируемые 403/404 воспроизвели отказ; после —
200/403/404, отказ 500/lookalike/обычного домена, неверный CA, TTL/network scope,
service cached plan RELAY_REQUIRED и сохранение явного DIRECT+ покрыты Go race.
Синтаксис диагностического PowerShell проверен без исполнения самого скрипта.

Не установлено, что все старые ORIGIN_DNS_FAILED владельца имели эту причину:
сохранённого DoH/HTTP результата для них нет. NXDOMAIN временного CDN имени,
недоступность провайдера DoH и сетевой timeout остаются реальными отказами;
несуществующее имя не заменяется случайным IP. ISP/Windows/video PASS не заявлен.

Проверка владельцу после обычного обновления клиента, PowerShell администратора
из корня репозитория; браузеры не закрывать:

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```
