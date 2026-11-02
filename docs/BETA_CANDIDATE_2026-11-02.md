# Beta-кандидат VELIQ — 02.11.2026

Собран полный кандидат **Build639**, source
`d20e9575b335ded8ad3bd00eb528b618df45af6c`, [draft #56](https://github.com/buzzmean/veliq/pull/56).
Он включает базу #55; старый Build618 с тремя origin/lifecycle FAIL заменён.
Кандидат предназначен для лабораторной приёмки и имеет **NOT_APPROVED**.
Ручные результаты не выставлены в PASS, rollout/public release не выполнялся.

## Скачать и проверить

[VELIQ-beta-candidate-win-x64-NOT-APPROVED](https://github.com/buzzmean/veliq/actions/runs/41391441230/artifacts/13118018135)
(133271023 bytes, хранение до 2026-11-16T05:13:55Z).
Внутри: Setup, GUI, служба, candidate.json, SHA256SUMS, README с планом,
сборщики binary/runtime evidence и шаблон результатов. SDK на целевых ПК не нужны.

| Файл | SHA256 |
|---|---|
| ZIP (digest GitHub) | `12c48464299edcb9dd157a81dd687b3c16a1568d0dd2751d8c8dba54b1fe14c0` |
| veliq-service.exe | `ccaf4fd349342ca1e4e7aa0307c91a2550fb5295e477aa9cde801a7551c17e24` |
| VELIQ.exe | `073a7e5d95b4a7f53cc0fc01a3b28baf70f7de20f1bc44013b266fa6ef56c712` |
| VELIQ-Setup.exe | `e1fc9a407f3d0d082fd9102b8d50c555a432fd447831019a4d72b0913dae2190` |

ZIP digest получен из GitHub artifact metadata; повторного локального скачивания
этого большого ZIP не было. Binary hashes/source проверены packaging job.
На Windows до запуска Setup сравните скачанный ZIP с опубликованным digest:

```powershell
& {
  $ErrorActionPreference='Stop'
  $expected='12c48464299edcb9dd157a81dd687b3c16a1568d0dd2751d8c8dba54b1fe14c0'
  $actual=(Get-FileHash -LiteralPath '.\VELIQ-beta-candidate-win-x64-NOT-APPROVED.zip' -Algorithm SHA256).Hash.ToLowerInvariant()
  if($actual -cne $expected){throw 'BETA_ZIP_HASH_MISMATCH'}
}
```

Распакуйте совпавший ZIP в новую пустую папку. Если проверенные `.ps1` блокируются
обычной execution policy, в этом же окне PowerShell из распакованной папки можно
разрешить локальные скрипты только для текущего процесса:

```powershell
& {
  $ErrorActionPreference='Stop'
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
  Get-ChildItem -LiteralPath . -Filter '*.ps1' -File | Unblock-File
}
```

Это не меняет CurrentUser/LocalMachine. Если машинная GPO запрещает выполнение,
не обходите её. Setup повышается под тем же SID будущего владельца GUI;
сборщики запускаются обычным пользователем без elevation.

## Что изменилось

Owner HTTP/HTTPS CONNECT без PAC/GPO даёт службе адресат каждого нового туннеля.
В проверенных Chrome/Edge это разделяет разные HTTP/2 origin на общем SAN/IP,
сохраняя обычный DIRECT и подтверждённый LOCAL. Raw TLS без CONNECT явно использует
временный authenticated RELAY. TLS end-to-end; MITM/keys/replay нет.

Отдельный процесс с primary owner token меняет только настройки владельца.
Полный original/installed/previous журнал сохраняется до записи; OFF/stop/uninstall
условно возвращают исходное состояние и сохраняют чужие значения. Другие приложения
сохраняют свои DIRECT/BLOCK/MANUAL rules. Readiness требует реального owner CONNECT.

После crash owned listener возвращается на том же порту до активации CP:
обычный DIRECT работает, protected ждёт закрытым. При полностью мёртвом процессе
proxy clients могут ждать SCM recovery; нулевая пауза и независимый WFP guard
не заявляются. Полный контракт: [BROWSER_AUTHORITY_TRANSPORT.md](BROWSER_AUTHORITY_TRANSPORT.md).

## Автоматическая проверка этого source

| Workflow | Доказательство | Результат |
|---|---|---|
| Verify | [run41391441214](https://github.com/buzzmean/veliq/actions/runs/41391441214) | PASS |
| Browser HTTP2 origin reuse | [run41391441202](https://github.com/buzzmean/veliq/actions/runs/41391441202) | PASS |
| Chrome policy native | [run41391441241](https://github.com/buzzmean/veliq/actions/runs/41391441241) | PASS |
| Edge policy acceptance | [run41391441225](https://github.com/buzzmean/veliq/actions/runs/41391441225) | PASS |
| Game UDP | [run41391441256](https://github.com/buzzmean/veliq/actions/runs/41391441256) | PASS |
| Relay release and route test | [run41391441167](https://github.com/buzzmean/veliq/actions/runs/41391441167) | PASS |
| Isolated production upgrade | [run41391441168](https://github.com/buzzmean/veliq/actions/runs/41391441168) | PASS |
| YouTube LOCAL | [run41391441174](https://github.com/buzzmean/veliq/actions/runs/41391441174) | PASS |
| Beta candidate kit (no deployment) | [run41391441230](https://github.com/buzzmean/veliq/actions/runs/41391441230) | PASS |
| Owner browser authority probe (isolated) | [run41391437126](https://github.com/buzzmean/veliq/actions/runs/41391437126) | PASS |

Origin matrix: **19/19**. Owner matrix: **13 runtime jobs**, Chrome и Edge,
оба порядка common-SAN H2, уже работающий браузер, safe raw RELAY, отказ capture,
SYSTEM→owner/полный restore, другие приложения, Controller.Start/guard/OFF.
Исторические GPO/PAC diagnostic jobs выключены в штатном прогоне; они не являются
пропущенными shipping gates. Controller lifecycle использует fixture capture
capability; настоящий Chromium/WinDivert проверен отдельными сценариями.

Полные Go race/vet/build Linux и Windows, PostgreSQL17, pinned DLL filters,
Python104 + branding3, C#218/WPF/desktop, 27CDN policy/cold/resume/RST, GameUDP,
relay, isolated upgrade. Actual Inno install/update/uninstall и negative exit1/noSCM
исполнены в PS5.1/PS7 с disposable loopback CA. Shipping Setup с тем же прежним
публичным CA v0.3.577 только собран, к production CI не подключался.

Не все дублирующие CI runs зелёные: push Edge
[41391437151/job125103507322](https://github.com/buzzmean/veliq/actions/runs/41391437151/job/125103507322)
упал по CDP socket read timeout5s на initial active visit старого continuity fixture,
до disable/OFF. Независимый PR Edge этого source прошёл; повторов ради поиска PASS
не запускали. Причина timeout не установлена, исправление по зелёному run не заявляется.
Прежние intermittent reflection HTTP_BODY_NOT_OBSERVED/startup CDP также не считаются
объяснёнными. Это не измеренная утечка origin и не доказанная проблема ISP.

## Утренняя приёмка

Подробный порядок и критерии: [BETA_ACCEPTANCE.md](BETA_ACCEPTANCE.md),
та же основа находится в README внутри kit. Все physical checks остаются NOT_RUN.

1. PC01 clean install, PC02 update+rollback, при возможности PC03 другой Windows/
   adapter/античит. Сверить installed hashes; GUI без elevation, owner/foreign SID.
2. Уже открытые Chrome/Edge → Optimize без restart/policy page → ordinary DIRECT,
   защищённые сайты, actual CONNECT для каждого профиля.
3. Холодный YouTube2160p≥2мин, seek/autoplay и LOCAL/media accounting; двусторонний
   Discord voice LOCAL10мин с собеседником; полные PUBG/Valorant/FACEIT матчи.
4. OFF/исходный proxy/обычное приложение, SCM crash recovery≤30с и тот же failed
   authority без browser restart/cache reset; overlays/разные identity/2reboots;
   rollback≤10мин. На diskless NIC/LAN/iSCSI не отключать.
5. Проверить реальные activation places, certificates, server availability и
   code hygiene; записать evidence без секретов. Любой FAIL/NOT_RUN блокирует
   расширение. После PASS:3ПК30–60мин →5–6ПКсмена → неделяR6.

Неделя R6 и R7/~40ПК не закрываются этим кандидатом.7ноября без экспериментов;
backup со сроком12ноября и production renewal требуют отдельного решения.
VPS/БД/CA/коды/пользовательские ПК/main/merge в этой подготовке не менялись.
Финальные документы могут находиться в более позднем docs-only commit;
бинарный source и контрольные суммы выше остаются неизменными.
