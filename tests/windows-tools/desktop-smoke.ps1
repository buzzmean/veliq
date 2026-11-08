# Windows-only published-process onboarding smoke on the fresh CI runner.
# Main-window navigation and tray lifecycle are covered by desktop-native tests.
# Does not claim real account/code/network acceptance.
[CmdletBinding()]
param([string]$Executable=(Join-Path $PSScriptRoot '..\..\bin\release\VELIQ.exe'))
$ErrorActionPreference='Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$Executable=(Resolve-Path $Executable).Path
$first=$null;$second=$null
# Published-process smoke explicitly exercises ordinary close, independent of
# the user's persisted tray preference. Restore the original bytes in finally.
$preferencesPath=Join-Path $env:LOCALAPPDATA 'VELIQ\desktop.json'
$hadPreferences=Test-Path -LiteralPath $preferencesPath
$previousPreferences=$null
if($hadPreferences){$previousPreferences=[IO.File]::ReadAllBytes($preferencesPath)}
try {
 [void][IO.Directory]::CreateDirectory((Split-Path $preferencesPath))
 [IO.File]::WriteAllText($preferencesPath,'{"StartMinimized":false,"MinimizeToTray":false}')
 $first=Start-Process $Executable -PassThru
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 do {$first.Refresh();if($first.HasExited){throw 'Нативное приложение завершилось при запуске'};if($first.MainWindowHandle -ne 0){break};Start-Sleep -Milliseconds 200}while([DateTime]::UtcNow -lt $deadline)
 if($first.MainWindowHandle -eq 0 -or $first.MainWindowTitle -ne 'VELIQ — подключение'){throw 'Нативное окно VELIQ не открылось'}
 $window=[Windows.Automation.AutomationElement]::FromHandle($first.MainWindowHandle)
 $deadline=[DateTime]::UtcNow.AddSeconds(15)
 do {
  $names=@($window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)|ForEach-Object {$_.Current.Name})
  $missing=@(@('Личный компьютер','Клубный компьютер','Электронная почта','Получить код','Создать аккаунт')|Where-Object {$_ -notin $names})
  if(!$missing.Count){break};Start-Sleep -Milliseconds 200
 }while([DateTime]::UtcNow -lt $deadline)
 if($missing.Count){throw ('Отсутствуют русские элементы окна: '+($missing -join ', '))}
 if(@($names|Where-Object {$_ -in @('Главная','Сервисы','Игры','Диагностика','Настройки','О программе')}).Count){throw 'Неактивированный ПК открыл управление маршрутизацией'}
 if(@($names|Where-Object {$_ -in @('Home','Applications','Routes','Statistics','Diagnostics','Settings')}).Count){throw 'Обнаружены английские элементы интерфейса'}
 # The NeExitLag.exe alias was removed by the Windows rebrand (owner's decision).
 if(Test-Path -LiteralPath (Join-Path (Split-Path $Executable) 'NeExitLag.exe')){throw 'Legacy NeExitLag.exe alias must not be built'}
 $second=Start-Process $Executable -PassThru
 if(!$second.WaitForExit(10000)){throw 'Второй экземпляр не передал активацию первому'}
 $first.Refresh();if($first.HasExited){throw 'Первый экземпляр завершился при активации'}
 Write-Output 'PASS: опубликованный EXE, русский стартовый экран без доступа к маршрутизации и единственный экземпляр'
 if(!(Get-Service VELIQ -ErrorAction SilentlyContinue)) {
  $deadline=[DateTime]::UtcNow.AddSeconds(15)
  do {$names=@($window.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)|ForEach-Object {$_.Current.Name});if('Служба VELIQ недоступна. Повторите проверку.' -in $names){break};Start-Sleep -Milliseconds 200}while([DateTime]::UtcNow -lt $deadline)
  if('Служба VELIQ недоступна. Повторите проверку.' -notin $names){throw 'Отсутствующая служба не отображена по-русски'}
  Write-Output 'PASS: отсутствие службы без падения'
 }
 [void]$first.CloseMainWindow();if(!$first.WaitForExit(10000)){throw 'X не завершил опубликованный GUI при MinimizeToTray OFF'}
 Write-Output 'PASS: published EXE X closes GUI with MinimizeToTray OFF'
} finally {
 try {
  foreach($process in @($first,$second)){if($null -ne $process){$process.Refresh();if(!$process.HasExited){Stop-Process -Id $process.Id -Force};$process.Dispose()}}
 } finally {
  if($hadPreferences){[IO.File]::WriteAllBytes($preferencesPath,$previousPreferences)}else{Remove-Item -LiteralPath $preferencesPath -Force -ErrorAction SilentlyContinue}
 }
}
