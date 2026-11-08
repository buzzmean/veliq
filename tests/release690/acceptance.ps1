[CmdletBinding()]
param()
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -or $env:VELIQ_RELEASE_ACCEPTANCE -cne 'DISPOSABLE_ACTIONS_690'){throw 'DISPOSABLE_ACTIONS_REQUIRED'}
$root=Join-Path $env:RUNNER_TEMP 'release690'
[void][IO.Directory]::CreateDirectory($root)
$serviceRoot=Join-Path $env:ProgramData 'VELIQ';$app=Join-Path $env:ProgramFiles 'VELIQ'
if((Get-Service VELIQ -ErrorAction SilentlyContinue) -or (Test-Path $serviceRoot) -or (Test-Path $app)){throw 'EXISTING_INSTALLATION_PRESERVED'}
$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$zip=Join-Path $root 'candidate.zip'
Invoke-WebRequest -Uri 'https://api.github.com/repos/buzzmean/veliq/actions/artifacts/13620261387/zip' -Headers @{Authorization=('Bearer '+$env:GH_ARTIFACT_TOKEN);Accept='application/vnd.github+json'} -OutFile $zip
if((Get-FileHash $zip).Hash -cne '07B744EED0F3CE2F3F454E534ED972EC0EAAF0FBB40FD042D62035998CF26DC8'){throw 'CANDIDATE_ZIP_HASH_MISMATCH'}
Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $root 'kit')
$setup=Get-ChildItem (Join-Path $root 'kit') -Recurse -File -Filter 'VELIQ-Setup.exe'|Select-Object -First 1
if(!$setup -or (Get-FileHash $setup.FullName).Hash -cne '1552BD2BCFC4E25E546116EE16C93387F334AB4DC1D787D7A5B6F63A381BEA8E'){throw 'CANDIDATE_EXE_HASH_MISMATCH'}
$fixture=Join-Path $root 'fixture';[void][IO.Directory]::CreateDirectory($fixture)
Copy-Item -LiteralPath $setup.FullName -Destination (Join-Path $fixture 'VELIQ-Setup.exe')
Copy-Item -LiteralPath 'tests/release690/veliq-release.json' -Destination $fixture
$old=Join-Path $root 'VELIQ-Setup-682.exe'
Invoke-WebRequest -Uri 'https://github.com/buzzmean/veliq/releases/download/v0.3.682/VELIQ-Setup.exe' -OutFile $old
if((Get-FileHash $old).Hash -cne '15E3AA9D5DE3543A845CC408C7D126DEA515659CC0493A72C01AB12E630BD37A'){throw 'PUBLISHED_682_HASH_MISMATCH'}
$p=Start-Process -FilePath $old -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NOCLOSEAPPLICATIONS','/RESTARTEXITCODE=3010',('/LOG="'+(Join-Path $root 'old-install.log')+'"')) -WindowStyle Hidden -Wait -PassThru
if($p.ExitCode -ne 0){throw ('PUBLISHED_682_INSTALL_EXIT_'+$p.ExitCode)}
$package=Get-Content -Raw (Join-Path $app 'package.json')|ConvertFrom-Json
if($package.commit -cne 'a6e8ad27344b75ffb2fd50d9be47e50a80391f09' -or (Get-Service VELIQ).Status -ne 'Running'){throw 'PUBLISHED_682_NOT_RUNNING'}
$protected=@('service.json','ipc.token','identity.json','device.pem','trust.json')
$before=@{};foreach($name in $protected){$path=Join-Path $serviceRoot $name;$before[$name]=if(Test-Path $path){(Get-FileHash $path).Hash}else{'ABSENT'}}
$owner=(Get-Content -Raw (Join-Path $serviceRoot 'service.json')|ConvertFrom-Json).owner_sid
$gui=Start-Process -FilePath (Join-Path $app 'VELIQ.exe') -PassThru
Start-Sleep -Seconds 8
if($gui.HasExited){throw 'PUBLISHED_682_GUI_EXITED'}
$oldGuiPid=$gui.Id;$session=$gui.SessionId
Write-Output 'RELEASE_690_BASELINE_PASS real_published_682 service_running gui_running'
& go test -c -o (Join-Path $root 'updater.test.exe') ./services/client-service
if($LASTEXITCODE){throw 'UPDATER_TEST_BUILD_FAILED'}
$worker=Join-Path $root 'system-worker.ps1';$workerLog=Join-Path $root 'system-worker.log'
$workerText='$ErrorActionPreference=''Stop''; $env:VELIQ_RELEASE_ACCEPTANCE=''DISPOSABLE_ACTIONS_690''; $env:VELIQ_RELEASE_FIXTURE='''+$fixture.Replace("'","''")+'''; & '''+(Join-Path $root 'updater.test.exe').Replace("'","''")+''' ''-test.run=^TestRelease690SystemUpdater$'' ''-test.v'' *> '''+$workerLog.Replace("'","''")+'''; exit $LASTEXITCODE'
[IO.File]::WriteAllText($worker,$workerText,[Text.UTF8Encoding]::new($false))
$action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe') -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$worker+'"')
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$task='VELIQ-Release690-System-Updater'
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Force|Out-Null
Start-ScheduledTask -TaskName $task
$deadline=[DateTime]::UtcNow.AddMinutes(5);$passed=$false
do{
 Start-Sleep -Seconds 3
 $state=(Get-ScheduledTask -TaskName $task).State;$info=Get-ScheduledTaskInfo -TaskName $task
 if($state -ne 'Running' -and $info.LastRunTime.Year -gt 2000 -and $info.LastTaskResult -ne 0){if(Test-Path $workerLog){Get-Content $workerLog};throw ('SYSTEM_UPDATER_EXIT_'+$info.LastTaskResult)}
 $current=if(Test-Path (Join-Path $app 'package.json')){Get-Content -Raw (Join-Path $app 'package.json')|ConvertFrom-Json}else{$null}
 $running=Get-Service VELIQ -ErrorAction SilentlyContinue
 if($state -ne 'Running' -and $info.LastTaskResult -eq 0 -and $current -and $current.commit -ceq 'caa04648af00d0027f3441067f9febbd31f9b19d' -and $running -and $running.Status -eq 'Running' -and (Test-Path (Join-Path $app 'install-success.json'))){$passed=$true;break}
}while([DateTime]::UtcNow -lt $deadline)
if(Test-Path $workerLog){Get-Content $workerLog}
if(!$passed){throw 'REAL_682_TO_690_UPDATER_TIMEOUT'}
$serviceHash=(Get-FileHash (Join-Path $serviceRoot 'veliq-service.exe')).Hash
$guiHash=(Get-FileHash (Join-Path $app 'VELIQ.exe')).Hash
if($serviceHash -cne '0A5228BA208C4D714634722C93292C3B56FFF563AD9EF681147CD0F60E319DA4' -or $guiHash -cne '4584F33E4AC1FB6D01C1E5C92D429C9758DF1DF8B39F83A93F597AFDDAA74A5B'){throw 'UPDATED_BINARY_HASH_MISMATCH'}
foreach($name in $protected){$path=Join-Path $serviceRoot $name;$after=if(Test-Path $path){(Get-FileHash $path).Hash}else{'ABSENT'};if($after -cne $before[$name]){throw ('PROTECTED_FILE_CHANGED_'+$name)}}
if((Get-Content -Raw (Join-Path $serviceRoot 'service.json')|ConvertFrom-Json).owner_sid -cne $owner){throw 'OWNER_CHANGED'}
. ./tools/windows/common.ps1
$status=Invoke-ServiceIPC 'status'
if((Get-CimInstance Win32_OperatingSystem).LastBootUpTime -ne $boot){throw 'UNEXPECTED_OS_REBOOT'}
Write-Output 'RELEASE_690_CROSS_VERSION_UPDATER_PASS signature download detached_SYSTEM real_682_to_690 SCM_IPC binaries config owner token no_reboot'
$guiDeadline=[DateTime]::UtcNow.AddSeconds(45);$resumed=@()
do{$resumed=@(Get-Process VELIQ -ErrorAction SilentlyContinue|Where-Object {$_.Id -ne $oldGuiPid -and $_.SessionId -eq $session});if($resumed.Count){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow -lt $guiDeadline)
if(!$resumed.Count){throw 'GUI_RESUME_NOT_OBSERVED'}
Write-Output 'RELEASE_690_GUI_RESUME_PASS previous_GUI_closed new_GUI_same_session'
