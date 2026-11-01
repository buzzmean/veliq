# NI-1: сравнение с main

Проверка 2026-11-01; Issue #33. Исходная база main —
`17bae3498da3b0204c6faf83e0657608baa3b968`, диагностический код NI-1 —
`81f340d17a1c689cc0f880e4075b66a5ccd35ac7`.
Коммит сравнения `9c067b0` не меняет продукт: отдельный workflow проверяет оба immutable SHA.
Не переносились изменения открытых PR #32/#34; main и production не изменялись.

## Парный эксперимент

[NI-1 baseline comparison, 41296717566](https://github.com/buzzmean/veliq/actions/runs/41296717566).
Матрица fail-fast=false, каждый тест запускается в отдельной VM; ошибки остаются ошибками CI,
нет continue-on-error, условного пропуска assertions или исправления checkout перед тестом.
Команды, runner labels и версии SDK одинаковы для обеих ревизий.
Ubuntu image одинаковый: Ubuntu 26.04.1, `20261025.179.1`.
Windows — Server 2025 / windows-2025-vs2026: оба Edge и NI desktop `20261021.278.1`,
main desktop `20261030.294.1`. GitHub выдал разный build образа двум desktop VM;
это ограничение сравнения явно сохраняется. Ошибка desktop также есть в прежнем main Verify.

| Проверка | main job | NI-1 job | Фактический итог обоих |
|---|---:|---:|---|
| Python deployment discovery, 100 тестов | 124819003532 | 124819003304 | FAIL одного `test_atomic_update_health_rollback_and_preserving_uninstall`, строка 142, exit 1 |
| Настоящие WPF native controls, .NET8 | 124819003536 | 124819003420 | FAIL `Empty visual: actual-RelayChoice` |
| Настоящий Edge CONNECT/PAC, Go1.25 | 124819003359 | 124819003230 | FAIL `TestEdgeActualPolicyHTTPSOutageRestart`: `Edge AUTO requires verified Edge CONNECT/PAC; capture unchanged` |
| Edge foreign policy / wrong SID | те же Edge jobs | те же Edge jobs | PASS `TestEdgePolicyRefusesForeignAndWrongOwnerSID` |

### Python: дефект входного release-файла фикстуры — Issue #35

`tests/deployment/test_relay_lifecycle.py:141` передаёт `/bin/true` в update.sh.
На обеих Ubuntu VM read-only metadata показала `/bin/true -> gnutrue`,
`/bin/false -> ../lib/cargo/bin/coreutils/false`.
`deploy/vps/update.sh:6` требует обычный файл и отвергает symlink до обновления;
условие выходит без stderr. Это объясняет локальный Debian PASS и CI Ubuntu FAIL.
Production запрет правильный; закрепление Ubuntu скроет дефект фикстуры.
Отдельная задача: https://github.com/buzzmean/veliq/issues/35 .

### WPF: снимок предусмотренно скрытого контрола — Issue #36

`tests/desktop-native/Program.cs:151-164` создаёт обычные preferences, где
ShowTechnical=false. В `apps/desktop/MainWindow.xaml:91` RelayChoice скрывается
собственным Visibility binding к ShowTechnical. Раскрытие AppAdvanced не меняет binding;
SaveImage корректно отвергает нулевой ActualWidth/ActualHeight.
Это не неисправность relay list и не повод назначать искусственные размеры.
Отдельная задача: https://github.com/buzzmean/veliq/issues/36 .

### Edge: потеря подтверждённой PAC на переходе профиля — Issue #37

`services/client-service/edge_acceptance_windows_test.go:204-214` успешно вызывает
edge.confirm, затем profile.set DIRECT→AUTO и optimize.
`controller.go:584-585` безусловно выполняет deferred CleanupOwnedBrowserPolicies для
browser mutation. `browser_policy_cleanup.go:26-27` инвалидирует readiness и удаляет
owned policy. `edge_transport.go:565-588` после этого требует активную policy и отказывает.
Это существующий production-переход main, не ошибка новой классификации NI.
Сравниваемые controller/cleanup/Edge test/transport, deployment и WPF файлы не изменены NI-1.
Отдельная задача: https://github.com/buzzmean/veliq/issues/37 .
Последующие Edge outage/restart, silent-policy, disable и hot-attach не подтверждены этим прогоном,
поскольку первая acceptance-проверка упала. POLICY_PENDING_BROWSER_REFRESH не доказывает uptake.

## Остальные результаты диагностического SHA

- [Network Intelligence stage1 — PASS](https://github.com/buzzmean/veliq/actions/runs/41295413706):
  реальные Windows targeted race x3, build, PS5.1/PS7 fixtures, pinned DLL компиляция всех фильтров
  без открытия драйвера; это не ISP/browser playback acceptance.
- [Chrome policy native — PASS](https://github.com/buzzmean/veliq/actions/runs/41295413710).
- [Isolated production upgrade — PASS](https://github.com/buzzmean/veliq/actions/runs/41295413679).
- [Verify — FAIL](https://github.com/buzzmean/veliq/actions/runs/41295413698),
  [Relay release — FAIL](https://github.com/buzzmean/veliq/actions/runs/41295413763),
  [Edge acceptance — FAIL](https://github.com/buzzmean/veliq/actions/runs/41295413755): причины выше.
- До этого локально: полный Go race с временной PostgreSQL17, vet/build Linux+Windows,
  целевые race x30 и TLS-phase regression x10, Python100, C#218, три PS7 fixtures.
  Это результаты соответствующего окружения, не замена упавших общих Windows/Ubuntu jobs.

NI-1 завершён как диагностический этап, но не готов к merge с зелёным полным CI.
Подтверждённых NI-1 регрессий из трёх исследованных сбоев нет; новые production-патчи не нужны.
Нужны отдельное устранение #35–#37, повтор полного CI и реальная Windows/ISP приёмка из
[описания этапа](NETWORK_INTELLIGENCE_STAGE1.md). CI после создания Draft PR оценивается отдельно
по SHA/событию; результат старого SHA не переносится автоматически на новый запуск.
