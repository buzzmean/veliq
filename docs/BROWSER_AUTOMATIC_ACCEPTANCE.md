# Проверка Chrome/Edge до запуска VELIQ, без перезапуска браузеров

Это короткая приёмка владельца; команды на ПК запускает он сам, на VPS ничего не запускается.
Фактический Chrome157/ISP результат после этих исправлений ещё не получен.
Ниже PowerShell под прежним пользователем; административные команды помечены.
Корень клона, например `$env:USERPROFILE\VELIQ`. Chrome/Edge не закрывать.

## 1. Уже установленный клиент: обновить, не переустанавливать

Закрыть только VELIQ через «Выход». PowerShell администратора, тот же SID:

```powershell
git pull --ff-only origin main
```

```powershell
& .\tools\windows\build-e2e.ps1
```

```powershell
& .\tools\windows\build-desktop.ps1
```

```powershell
& .\tools\windows\update-service.ps1
```

```powershell
& .\tools\windows\install-desktop.ps1
```

```powershell
(Get-FileHash .\bin\windows-e2e\veliq-service.exe).Hash -eq (Get-FileHash "$env:ProgramData\VELIQ\veliq-service.exe").Hash
```

Ожидается True. update теперь по умолчанию проверяет узкое app-scoped inbound
TCP-правило для service reflection; отдельный -NativeTcpFirewall не требуется.
Нет глобального proxy/firewall disable и нет изменений VPS. Чужое правило не
перезаписывается, group policy denial — явная ошибка с откатом updater.

## 2. Только действительно чистый ПК после freeze: ActivationOnly

Если служба существует, использовать раздел1. Не удалять identity ради теста.
Уже установлены Git, Go, SDK .NET8. В корне клона под владельцем выполнить
сначала проверить источник NuGet (идемпотентно, обычный PowerShell):

```powershell
. .\tools\windows\activation-nuget.ps1
```

```powershell
Initialize-ActivationNuGetSource
```

Затем build-e2e, build-desktop из раздела1 и:

```powershell
& .\tools\windows\fetch-windivert.ps1
```

Если .e2e\windivert уже подготовлена, использовать её pins.json, не удалять.
Нужны проверенные ПУБЛИЧНЫЕ ca.pem/cp-ca.pem в .e2e\activation-trust; никаких
старых device key/identity. Если их нет — только владелец скачивает public CA
следующими командами (VPS не изменяется, host key проверяется):

```powershell
New-Item -ItemType Directory -Force .\.e2e\activation-trust | Out-Null
```

```powershell
scp -o StrictHostKeyChecking=yes root@2.56.177.4:/etc/neexitlag/control/ca.pem .\.e2e\activation-trust\ca.pem
```

Не обходить отказ неизвестного host key: сначала сверить его с доверенным ключом.
CA сверяется с заранее известным владельцу DER SHA256, а не с enroll reply:

```powershell
$expectedCA = (Read-Host 'Известный доверенный SHA256 публичного CA').Replace(':','').Replace(' ','').ToLowerInvariant()
```

```powershell
$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 ((Resolve-Path .\.e2e\activation-trust\ca.pem).Path); $sha=[Security.Cryptography.SHA256]::Create(); try { if($expectedCA -notmatch '^[0-9a-f]{64}$' -or ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant() -cne $expectedCA){throw 'CA_PIN_MISMATCH; stop before installation'} } finally {$sha.Dispose();$cert.Dispose()}
```

```powershell
Copy-Item .\.e2e\activation-trust\ca.pem .\.e2e\activation-trust\cp-ca.pem
```

Совпадение обоих CA допустимо для текущего deployment с общей CA. Для других
развёртываний нужны их настоящие публичные CA. Не скачивать private CA/admin.token.
Установка — PowerShell администратора под тем же пользователем:

```powershell
$ownerSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

```powershell
$pins=Get-Content .\.e2e\windivert\pins.json -Raw | ConvertFrom-Json
```

```powershell
& .\tools\windows\install.ps1 -ActivationOnly -ServiceExecutable .\bin\windows-e2e\veliq-service.exe -OwnerSid $ownerSid -TrustDirectory .\.e2e\activation-trust -DriverDirectory .\.e2e\windivert -DllSha256 $pins.dll_sha256 -DriverSha256 $pins.driver_sha256 -ControlPlaneUrl https://2.56.177.4:8443 -ProbeTarget 2.56.177.4:40000 -TCPProbeTarget 2.56.177.4:40000
```

```powershell
& .\tools\windows\install-desktop.ps1
```

Открыть VELIQ обычным ярлыком (без elevation при UAC-on), ввести прежний клубный
код в закрытое поле активации. Не выводить код в terminal/chat/transcript.
До ACTIVATED service не включает capture/policy. После активации профиль/путь
готовятся автоматически; дополнительные кнопки для браузеров не нужны.
Для строгой проверки «браузер раньше GUI» после активации выйти только из VELIQ
и выполнить раздел3. Для freeze повторить после reboot; hardware-slot не менять.

## 3. Проверка уже открытых окон: только новые вкладки

VPN выключен. VELIQ GUI закрыт; открыть Chrome и Edge обычным способом и оставить
окна открытыми. Обычный PowerShell того же пользователя, корень клона:

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase baseline
```

Запустить VELIQ обычным ярлыком. Automatic включён по умолчанию; если владелец
явно выключил его ранее, разрешена одна кнопка «Оптимизировать». Не добавлять
браузер вручную. В тех же окнах открыть новые вкладки YouTube, Telegram Web,
claude.ai; проверить настоящую загрузку/работу. Не Reload policies/не restart.

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase ready
```

Helper ждёт до20с: оба профиля native AUTO, relay/capture ready, native-only
bidirectional exchange каждого браузера с измеренным временем. Проверяет
неизменность PID/creation/path от baseline. PAC bytes не принимаются за native.
Это NATIVE_TRANSPORT_ONLY_NOT_PAGE_PASS: HTTP/TLS/работу сайта подтверждает
реальная страница; encrypted bytes не дают такого доказательства.
NO_NATIVE_EXCHANGE не скрывается успехом: старая HTTP/2/QUIC сессия может
переиспользоваться и остаётся pinned до закрытия. Скрипт её не сбрасывает.

Выключить оптимизацию одной кнопкой и сразу открыть новую vk.ru в обоих окнах:

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase disabled
```

Включить оптимизацию, затем «Выход» в трее; сразу новая vk.ru:

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase exit
```

Не перезапускать VELIQ между Exit и этой проверкой. При новом запуске GUI с
Automatic=true он должен включить маршрутизацию один раз; OFF в текущем окне
остаётся OFF, опрос его не отменяет.

Необязательная проверка SCM, PowerShell администратора после нового запуска GUI:

```powershell
Stop-Service VELIQ
```

```powershell
& .\tools\windows\test-browser-startup.ps1 -Phase stopped
```

```powershell
Start-Service VELIQ
```

Сбор безопасной диагностики без изменений настроек:

```powershell
& .\tools\windows\diag-no-vpn.ps1 -Only browser,youtube
```

Не коммитить diag-result/cs-diag/observe-result. В этой приёмке нет операций
с VPS/кодами/сертификатами, кроме отдельного owner read-only public CA download
для действительно пустой установки в разделе2. Полные ограничения —
BROWSER_AUTOMATIC_START.md, в том числе отсутствие независимого kernel guard.
