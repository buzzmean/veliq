# VELIQ Build643: аккаунты и подключение без ручных кодов

Исходный код `9392a96efde86edda8ebf25ed1b49add5f33c482`, [draft #57](https://github.com/buzzmean/veliq/pull/57)
поверх сетевой базы #56. **NOT_APPROVED: сервер аккаунтов не развёрнут,
реальный SMTP/inbox и физическая приёмка ещё не подтверждены.**
Старый Build639 был сетевой сборкой без аккаунтов и не подходит для полного теста.

Дополнение03.11: в текущем исходнике сайта адрес поддержки изменён на
`support@veliqapp.ru`; отправитель писем входа — `no-reply@veliqapp.ru` через
Timeweb Cloud. Старый серверный ZIP ниже содержит прежний адрес поддержки:
при подготовке публикации использовать актуальный каталог `website/`.
Бинарники Build643 не изменены, SMTP и публикация сайта не выполнены.

## Что реализовано

- Регистрация и вход по email; шестизначный код из письма подтверждает почту.
  Ручной код активации ПК в основном сценарии больше не нужен.
- ЛК: тип «Пользователь / Клуб», имя, подписки, занятые места, список ПК,
  освобождение устройств и платежи. Автопродление не предлагается до поддержки провайдером.
- Кнопка в приложении открывает настоящий браузер. Владелец выбирает свою
  действующую подписку и подтверждает ПК; служба получает сертификат для своего ключа.
- Чистый `/CLUBIMAGE=1` без файла кода: одно подтверждение образа в ЛК,
  отдельное отзывное разрешение клуба, автоматическое подключение при старте overlay.
  На шаблоне нет ключа ПК; аппаратный слот стабилен, ключи устройств различаются.
- Legacy identity/коды/IPC совместимы. Новые аккаунты всегда требуют оплаченный
  период/grace; ручной OFF сохраняется после оплаты. Гостевой режим read-only.

Полный контракт и серверная настройка: [ACCOUNT_ONBOARDING.md](ACCOUNT_ONBOARDING.md).

## Пакеты из одного source

[Windows Setup и kit](https://github.com/buzzmean/veliq/actions/runs/41406096891/artifacts/13124196520) — 133360514 bytes,
хранение до 2026-11-16T07:37:01Z. Внутри Setup, GUI, служба, candidate.json,
SHA256SUMS, план приёмки и безопасные сборщики evidence. SDK на ПК не нужны.

[Control-plane и сайт](https://github.com/buzzmean/veliq/actions/runs/41406096897/artifacts/13123516905) — 8452230 bytes,
**NOT_DEPLOYED**, schema5. В пакете нет ключей/credentials или готовой production-настройки.

| Файл | SHA256 |
|---|---|
| Windows ZIP, опубликованный digest GitHub | `180d570351eaa1f8ca30ec39168bfa063f8bc04591e0b04de3c5c490363b3620` |
| veliq-service.exe | `c9ee89659f3e058c740d18d807f74cca5f601fdd2dc4389445e483dbc6aabd55` |
| VELIQ.exe | `082b754ec9c8264213222a72d6a5f4c283b46ada0c2c90d8eacba5ef10152773` |
| VELIQ-Setup.exe | `a71e52f1169d33ad7828284363f0f02555c790957c6665ff7c3efe9828c19af2` |
| Server ZIP, проверен локально | `06335eaba8e1f5b30be75c37bf6efb19aba6e219caf3983e5e75784eb585611c` |
| control-plane Linux amd64 | `81ecb2efd50b80043062557569a0c9f97c600764e07763d557d87f8205fcf5ec` |

Серверный ZIP скачан, ZIP CRC и все46 SHA256 manifest проверены локально.
Windows ZIP больше32MiB: его digest взят из metadata GitHub, binary hashes —
из успешного packaging job. Локальная повторная проверка клиентского ZIP и
сравнение установленных файлов остаются обязательными, в PASS не выставлены.

Перед распаковкой Windows ZIP, обычный PowerShell в папке загрузки:

```powershell
& {
  $ErrorActionPreference='Stop'
  $expected='180d570351eaa1f8ca30ec39168bfa063f8bc04591e0b04de3c5c490363b3620'
  $actual=(Get-FileHash -LiteralPath '.\VELIQ-beta-candidate-win-x64-NOT-APPROVED.zip' -Algorithm SHA256).Hash.ToLowerInvariant()
  if($actual -cne $expected){throw 'BETA_ZIP_HASH_MISMATCH'}
}
```

## Проверка точного source

| Workflow | Доказательство | Результат |
|---|---|---|
| Chrome policy native | [run41406096927](https://github.com/buzzmean/veliq/actions/runs/41406096927) | PASS |
| Relay release and route test | [run41406096914](https://github.com/buzzmean/veliq/actions/runs/41406096914) | PASS |
| Account onboarding without activation codes | [run41406096897](https://github.com/buzzmean/veliq/actions/runs/41406096897) | PASS |
| Isolated production upgrade | [run41406096904](https://github.com/buzzmean/veliq/actions/runs/41406096904) | PASS |
| Game UDP | [run41406096870](https://github.com/buzzmean/veliq/actions/runs/41406096870) | PASS |
| Edge policy acceptance | [run41406096877](https://github.com/buzzmean/veliq/actions/runs/41406096877) | PASS |
| YouTube LOCAL | [run41406096919](https://github.com/buzzmean/veliq/actions/runs/41406096919) | PASS |
| Browser HTTP2 origin reuse | [run41406096947](https://github.com/buzzmean/veliq/actions/runs/41406096947) | PASS |
| Beta candidate kit (no deployment) | [run41406096891](https://github.com/buzzmean/veliq/actions/runs/41406096891) | PASS |
| Verify | [run41406096955](https://github.com/buzzmean/veliq/actions/runs/41406096955) | PASS |
| Owner browser authority probe (isolated) | [run41406090338](https://github.com/buzzmean/veliq/actions/runs/41406090338) | PASS |

Полные Linux/Windows race/vet/build, PostgreSQL17, Python107 + branding3,
C#232/WPF/desktop, pinned WinDivert DLL, Chrome actual driver/Edge,
19/19 origin scenarios,13 owner runtime jobs,27CDN policy/cold/resume/RST,
GameUDP, relay и isolated upgrade. Выключенные исторические GPO/PAC diagnostic
jobs не являются shipping gates; Controller lifecycle использует fixture capture.

Настоящий Chrome+HTTPS: регистрация обоих типов → подтверждение ПК → сертификат
в настоящем клиентском activation path → список ПК → logout. SQL-проверки
включают чужую подписку, CSR/secret substitution, expiry, seat limit, повторы,
отзыв образа и отказ неоплаченному аккаунту. Почта и зачисление в этом тесте —
исключительно fixture; в production-бинарнике этих endpoint нет.

Actual Inno install/update/uninstall и новый no-code image preparation проходят
PS5.1/PS7: настоящий owner IPC, SYSTEM boot task, отсутствие identity до approval.
Эти установки используют disposable loopback CA. Shipping Setup собран с тем же
public CA v0.3.577/DER `622db56fba69041b108fc31b5b3cf81a5ed722faa3110ef2b896b8fac42abd85`;
CA/production не менялись, этот Setup здесь к боевому серверу не подключался.

Исторический Edge CDP timeout предыдущей сетевой базы остаётся необъяснённым
наблюдением; новый PASS не доказывает устранение его причины. Cancelled runs
и проверки других source не заменяют указанные положительные проверки.

## До клубного теста

1. Подключить согласованный HTTPS origin сайта/API, SMTP и действующую подписку
   на5–6мест; сохранить прежний CA и устройства, иметь backup/rollback БД/CP.
   Настоящий inbox, `account_ready=true` и вход из приложения проверить до выезда.
   В текущей среде нет настроенных SMTP/серверных credentials; live-этап не выполнен.
2. После готовности сервера пройти [BETA_ACCEPTANCE.md](BETA_ACCEPTANCE.md):
   PC01 clean, PC02 update/rollback, затем чистый отдельный образ и2–3overlay.
   Чужой SID, WinDivert/ISP, voice, полные матчи, freeze, SCM recovery и rollback
   ещё NOT_RUN. Не клонировать активированный обычный ПК; diskless LAN/iSCSI не отключать.
3. Только после всех gates PASS:3ПК30–60мин →5–6ПКсмена →недельный R6.
   Merge, production rollout, публичный release и автообновление не выполнялись.
