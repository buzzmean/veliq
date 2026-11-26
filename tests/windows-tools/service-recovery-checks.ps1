# Isolated execution of the actual crash-fixture guards; never accesses Windows SCM or processes.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'service-recovery-native.ps1'),[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'RECOVERY_FIXTURE_PARSE_FAILED'}
foreach($name in @('Assert-OwnedRecoveryFixture','Assert-OwnedCrashRecovery')){
 $definitions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
 if($definitions.Count -ne 1){throw 'RECOVERY_FIXTURE_FUNCTION_MISSING'}
 . ([scriptblock]::Create($definitions[0].Extent.Text))
}
function Get-CimInstance {
 param($ClassName,$Filter,$OperationTimeoutSec)
 if($ClassName -cne 'Win32_Service' -or $Filter -cne "Name='VELIQ'"){throw 'RECOVERY_MOCK_SCM_SCOPE'}
 $script:reads++
 $id=21;$state='Running'
 if($script:stopped){if($script:mode -ceq 'NO_RESTART'){$id=0;$state='Stopped'}else{$id=22}}
 if(!$script:stopped -and $script:mode -ceq 'PID_CHANGED' -and $script:reads -gt 1){$id=23}
 $path='"'+$script:target+'" -config "'+(Join-Path $script:installed 'service.json')+'"'
 if($script:mode -ceq 'FOREIGN_SCM'){$path='"foreign.exe" -config "foreign.json"'}
 return [pscustomobject]@{PathName=$path;State=$state;StartMode='Auto';ProcessId=$id}
}
function Get-Process {
 param($Id,$ErrorAction)
 if($Id -notin @(21,22)){throw 'RECOVERY_MOCK_PROCESS_SCOPE'}
 $path=$script:target
 if($script:mode -ceq 'FOREIGN_PROCESS'){$path=Join-Path $script:installed 'foreign.exe'}
 $birth=$script:birth
 if($Id -eq 21){$birth=$birth.AddMinutes(-1)}
 $value=[pscustomobject]@{Handle=1;StartTime=$birth;Path=$path;HasExited=$false}
 $value|Add-Member -MemberType ScriptMethod -Name Refresh -Value {}
 $value|Add-Member -MemberType ScriptMethod -Name Dispose -Value {}
 return $value
}
function Stop-Process {
 param($Id,[switch]$Force,$ErrorAction)
 if($Id -ne 21 -or !$Force -or $script:stops -ne 0){throw 'RECOVERY_MOCK_STOP_SCOPE'}
 $script:stops++;$script:stopped=$true
 if($script:mode -ceq 'STATE_CHANGED'){[IO.File]::WriteAllText((Join-Path $script:installed 'ipc.token'),'changed-token')}
}
function Start-Service {param($Name) $script:starts++;throw 'RECOVERY_MANUAL_START_FORBIDDEN'}
function Invoke-ServiceIPCOnce {
 param($Method,$Payload,$TokenFile)
 if($Method -cne 'status' -or $TokenFile -cne (Join-Path $script:installed 'ipc.token')){throw 'RECOVERY_MOCK_IPC_SCOPE'}
 $id=21;$build=$script:commit.Substring(0,12)
 if($script:stopped){$id=22;if($script:mode -ceq 'BAD_SOURCE'){$build='wrong-source'};if($script:mode -ceq 'BAD_IPC_PID'){$id=21}}
 return [pscustomobject]@{service_pid=$id;build=$build;backend=[pscustomobject]@{}}
}
function Assert-RecoveryCase([string]$Mode,[string]$Failure,[int]$ExpectedStops){
 $script:mode=$Mode;$script:reads=0;$script:stops=0;$script:starts=0;$script:stopped=$false;$script:birth=[DateTime]::UtcNow
 foreach($name in @('veliq-service.exe','service.json','ipc.token')){[IO.File]::WriteAllText((Join-Path $script:installed $name),'fixture-'+$name)}
 $hashes=@{}
 foreach($name in @('service.json','ipc.token')){$hashes[$name]=(Get-FileHash -LiteralPath (Join-Path $script:installed $name)).Hash}
 $caught='';$value=$null
 try{$value=Assert-OwnedCrashRecovery $script:installed $script:commit (Get-FileHash -LiteralPath $script:target).Hash $hashes -TimeoutSeconds 1}catch{$caught=$_.Exception.Message}
 if($caught -cne $Failure -or $script:stops -ne $ExpectedStops -or $script:starts -ne 0){throw ('RECOVERY_GUARD_CASE_FAILED '+$Mode+' '+$caught)}
 if(!$Failure -and ($value.old_pid -ne 21 -or $value.new_pid -ne 22 -or $value.source -cne $script:commit)){throw 'RECOVERY_RESTART_PROOF_MISSING'}
}
$saved=@{}
foreach($name in @('GITHUB_ACTIONS','VELIQ_BETA_INSTALL_SMOKE','ProgramData')){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
$root=Join-Path ([IO.Path]::GetTempPath()) ('veliq-crash-guard-'+[Guid]::NewGuid().ToString('N'))
try{
 $env:GITHUB_ACTIONS='true';$env:VELIQ_BETA_INSTALL_SMOKE='1';$env:ProgramData=$root
 $script:installed=Join-Path $root 'VELIQ';$script:target=Join-Path $script:installed 'veliq-service.exe';$script:commit='a'*40
 New-Item -ItemType Directory -Path $script:installed|Out-Null
 Assert-RecoveryCase 'SUCCESS' '' 1
 Assert-RecoveryCase 'FOREIGN_SCM' 'RECOVERY_FIXTURE_OWNED_SERVICE_REQUIRED' 0
 Assert-RecoveryCase 'FOREIGN_PROCESS' 'RECOVERY_CRASH_IMAGE_MISMATCH' 0
 Assert-RecoveryCase 'PID_CHANGED' 'RECOVERY_CRASH_TARGET_CHANGED' 0
 Assert-RecoveryCase 'BAD_SOURCE' 'RECOVERY_RESTART_IPC_IDENTITY_MISMATCH' 1
 Assert-RecoveryCase 'BAD_IPC_PID' 'RECOVERY_RESTART_IPC_IDENTITY_MISMATCH' 1
 Assert-RecoveryCase 'STATE_CHANGED' 'RECOVERY_RESTART_STATE_CHANGED' 1
 Assert-RecoveryCase 'NO_RESTART' 'RECOVERY_AUTOMATIC_RESTART_TIMEOUT' 1
 Write-Output 'PASS 8 isolated crash recovery guard/identity/state/timeout cases; no real process or SCM mutation'
}finally{
 foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
 if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force}
}
