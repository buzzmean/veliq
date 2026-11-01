# NI-2: ограниченное восстановление DNS

Issue #33. Ветка `feat/network-intelligence-stage2-dns`, база
`339d2075688fee8ddf42c5c572e35502268d011a` (NI-1). Это первый функциональный этап
[плана](NETWORK_INTELLIGENCE_STAGE2_DESIGN.md), без изменений production или DNS Windows.

## Воспроизведённый пробел

До изменения `DoHResolver.ExchangeWire` переходил ко второму доверенному provider при
ошибке TLS/HTTP/transport, timeout или неверном DNS ID/question. Но первый **валидный**
NXDOMAIN/SERVFAIL возвращался немедленно. `TestDNSWireRecoveryNegativeThenHealthy` на базе
с добавленной фикстурой упал для A и AAAA: статус DNS_NXDOMAIN/DNS_SERVFAIL, calls=1;
здоровый второй provider не получал запрос. Конкурентные запросы также возвращали первый SERVFAIL.
Это не подмена DNS, доказанная одним отрицательным ответом: это конкретный отсутствующий переход.

Существующие timeout/invalid/certificate fallback и DNSRecovery singleflight/TTL/HTTP-origin
proof покрывались готовыми механизмами. Они не заменены новым resolver/cache/ladder.

## Изменение поведения

- `ExchangeWire` ограниченно пробует следующий **существующий** доверенный DoH provider при
  NXDOMAIN/SERVFAIL. Успешный проверенный ответ реально возвращается вызывающему браузеру,
  а не только отображается в диагностике. Если все провайдеры дали отрицательный ответ,
  сохраняется первый валидный negative response. Если валидного ответа нет — прежняя ошибка.
- Общий бюджет до 2с, до 1с на provider с разделением оставшегося времени; существующие
  16 broker slots/streams и 2 origin recovery slots не менялись. Нет очереди без лимита,
  периодических дополнительных проб, нового persistent cache или постоянного negative pin.
- NODATA, REFUSED, TC не запускают новый semantic retry. UDP budget/TC и TCP framing прежние.
  A/AAAA, HTTPS/SVCB, DNSSEC wire и HTTP Age сохраняются. DNSSEC самостоятельно не валидируется:
  AD/DO/opaque записи передаются, TLS provider проверяется как раньше.
- Из service вызов разрешён только для enabled-профиля и известных browser-origin policy групп.
  Обычные имена, включая VK/Яндекс, сохраняют исходный DNS даже при SERVFAIL;
  обычный DNS/53 не уходит в relay. Shared learning и серверная конфигурация не менялись.
- До I/O, между provider opens и перед доставкой проверяются PID/birth/SID, profile revision,
  сеть и OFF. Устаревший ответ не доставляется и не публикует hints. DNS-open отдельно запрещён
  в DIRECT compatibility при OFF: это не пользовательский cached-PAC CONNECT.
- Полученные hints поступают в прежний network/profile/TTL index; существующий planner сохраняет
  protected RELAY_REQUIRED + Required. DNS-ответ не даёт разрешения ослабить protected floor,
  не доказывает HTTP/playback и не переносит established TCP. Replay после origin byte запрещён.

## Доказательства и границы

| Проверка | Что действительно проверяет |
|---|---|
| `TestDNSWireRecoveryNegativeThenHealthy` | локальные TLS DoH: NXDOMAIN/SERVFAIL → второй provider → A/AAAA; восстановленный wire/ID/TTL |
| `TestDNSWireRecoveryAuthenticatedRelayToHTTPData` | настоящие QUIC+mTLS+ticket/OPEN, два TLS DoH, recovered IP, проверенный TLS original SNI и реальные HTTP-байты; все серверы только loopback |
| `TestDNSWireRecoveryExistingTransportAndValidationFallback` | прежние timeout, неверный ID/question, malformed wire и неверное имя TLS cert уже покрывались до изменения |
| `TestDNSWireRecoveryAllNegativeAndTemporaryFailure` | оба отрицательные; повтор после временного отказа действительно восстанавливает имя, negative не закреплён |
| `TestDNSWireRecoveryBothUnavailableAndParentCancellation` | оба недоступны, parent deadline/cancel, нет ответа или новых попыток после отмены |
| `TestDNSWireRecoveryConcurrentIDs` | 16 параллельных запросов, ID не смешиваются, каждый получает второй ответ |
| `TestDNSWireRecoveryPreservesDNSSECServiceRecordsAndAge` | A/AAAA/HTTPS/SVCB, AD/DO/opaque RRSIG, TTL и Age; не DNSSEC authenticity acceptance |
| `TestBrowserDNSRecoveryScopeChangeDropsReplyAndHints` | deterministic network/OFF/profile/revision/PID/birth/path/cancel при незавершённом запросе; нет ответа и hints |
| `TestBrowserDNSRecoveryReplyFeedsExistingPlannerAndTTL` | broker → прежний index/planner → protected route/fallback, прежний TTL, изоляция другой сети; relay callback здесь тестовый |
| `TestBrowserDNSRecoveryTCPStreamReturnsRecoveredAnswer` | настоящий DNS TCP framing и broker reply |
| `TestBrowserDNSRecoveryCapacityAndCanceledAdmission` | 16 in-flight, 17-й не открывает relay, slots освобождаются |
| `TestBrowserDNSRecoveryWindowsOwnerAndOffNoDirect` | Windows PID/birth/SID на отдельном тестовом exe, отмена scope и запрет DIRECT при OFF; это не настоящий Chrome |
| прежние `TestBrowserDNS...` / `TestDNSRecovery...` | owner hooks, ordinary DIRECT, TTL/capacity, существующий cache/singleflight и authenticated origin recovery |

Локально: Go race полного дерева с одноразовой PostgreSQL17, vet/build Linux+Windows,
Windows test cross-compile и PS7 browser/local/layer fixtures. Первый запуск PG-фикстуры
не прошёл из-за прав Unix socket; после исправления только временного окружения полный race PASS.
Windows-native, PS5.1 и pinned DLL подтверждаются отдельным workflow **Network Intelligence DNS recovery**;
результат cross-build не выдаётся за native PASS. Общие #35/#36/#37 не исправляются этим этапом.

Нативный перехват по-прежнему IPv4 UDP/TCP53. AAAA-ответы сохраняются, но это не добавление
IPv6 WinDivert capture/relay. svchost DNS Client и содержимое browser DoH не приписываются
конкретному браузеру. Ни DNS fallback, ни transfer-тест не доказывают playback YouTube.
Per-provider попытки проверяются тестами/CI; отдельная новая таблица provider traces в IPC не добавлялась.
`DNS_SCOPE_CHANGED` виден в прежней bounded диагностике. Настоящий Windows/ISP — NOT TESTED.

## Реальная приёмка на тестовом ПК

Только отдельный тестовый ПК с уже установленными клиентом/драйвером, тем же owner SID,
PowerShell администратора из корня этой ветки. Не переустанавливать приложение и не трогать VPS/CA.
Сначала проверить CI и сохранить прежний клиент для отката.

```powershell
& {
    $ErrorActionPreference='Stop'
    foreach ($tool in @('git','go')) {
        if (!(Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw ('Install: winget install --id '+@{git='Git.Git';go='GoLang.Go'}[$tool]+' -e')
        }
    }
    & go version
    if ($LASTEXITCODE) { throw 'Go unavailable' }
    $saved=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        & git --version
        if ($LASTEXITCODE) { throw 'Git unavailable' }
        $branch=(& git branch --show-current | Out-String).Trim()
        if ($LASTEXITCODE -or $branch -ne 'feat/network-intelligence-stage2-dns') { throw 'Use the NI-2 test checkout' }
        $tracked=@(& git status --porcelain --untracked-files=no)
        if ($LASTEXITCODE -or $tracked.Count) { throw 'Preserve tracked changes before update' }
        & git pull --ff-only origin feat/network-intelligence-stage2-dns
        if ($LASTEXITCODE) { throw 'git pull failed' }
    } finally { $ErrorActionPreference=$saved }
    & .\tools\windows\build-e2e.ps1
    & .\tools\windows\Close-VeliqGuiForUpdate.ps1
    & .\tools\windows\update-service.ps1
    . .\tools\windows\common.ps1
    Invoke-ServiceIPC 'status' | Select-Object build,connected,optimizing,capture_active
    & .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
}
```

GUI не менялся, пересборка не нужна; браузеры не закрывать. Проверить в новых вкладках
YouTube/Telegram/Claude/OpenAI и VK/Яндекс; снять диагностику, не публикуя секреты.
Fault injection автоматизирован в loopback тестах. Для живого подтверждения recovery нужен
изолированный сетевой стенд, который воспроизводит отказ одного DoH provider и оставляет
другой доступным; не менять глобальные DNS и не блокировать production endpoint ради теста.
Проверить реальные данные после восстановления, OFF/выход, смену сети/freeze.
Нельзя объявлять live recovery доказанным только по окончательному DNS_RESPONSE в IPC.
