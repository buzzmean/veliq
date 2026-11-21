[CmdletBinding()]
param([ValidateRange(1,30)][int]$EventMinutes=10)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# Read-only local diagnostics; command lines are CLASSIFIED, never printed.
$service=Get-CimInstance Win32_Service -Filter "Name='VELIQ'" -ErrorAction SilentlyContinue
$scmPID=if($service){[uint32]$service.ProcessId}else{[uint32]0}
[pscustomobject]@{kind='SCM';state=$(if($service){$service.State}else{'NOT_INSTALLED'});process_id=$scmPID;start_mode=$(if($service){$service.StartMode}else{''});exit_code=$(if($service){$service.ExitCode}else{0})}|Format-List
$processes=@(Get-CimInstance Win32_Process -Filter "Name='veliq-service.exe'" -ErrorAction SilentlyContinue|Select-Object -First 32)
$processIDs=@($processes | ForEach-Object {[uint32]$_.ProcessId})
$listeners=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|Where-Object {$_.LocalAddress -in @('127.0.0.1','::1') -and ($_.LocalPort -in @(50165,50166) -or $_.OwningProcess -in $processIDs)}|Select-Object -First 128)
foreach($process in $processes){
 $role='UNKNOWN';$line=[string]$process.CommandLine
 if($process.ProcessId -eq $scmPID -and $scmPID -ne 0){$role='SCM_SERVICE'}
 elseif($line -match '(?:^|\s)-{1,2}chrome-recovery(?:\s|$)'){$role='OWNER_RECOVERY'}
 elseif($line -match '(?:^|\s)-{1,2}browser-policy-watchdog(?:\s|$)'){$role='POLICY_WATCHDOG'}
 elseif($line -match '(?:^|\s)-{1,2}cleanup-browser-policy(?:\s|$)'){$role='POLICY_CLEANUP'}
 elseif($line -match '(?:^|\s)-{1,2}console(?:\s|$)'){$role='CONSOLE_HOST'}
 [pscustomobject]@{kind='PROCESS';role=$role;process_id=$process.ProcessId;parent_id=$process.ParentProcessId;created=$process.CreationDate;path=$process.ExecutablePath;listening_ports=(@($listeners|Where-Object {$_.OwningProcess -eq $process.ProcessId}|Select-Object -ExpandProperty LocalPort)-join ',')}
}
$listeners|Select-Object LocalAddress,LocalPort,OwningProcess|Format-Table -AutoSize
try{
 Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Service Control Manager';Id=@(7031,7032,7034,7036);StartTime=(Get-Date).AddMinutes(-$EventMinutes)} -MaxEvents 200 -ErrorAction Stop|Where-Object {$_.Message -match 'neexitlag|VELIQ Routing Service'}|Select-Object TimeCreated,Id|Format-Table -AutoSize
}catch{Write-Output 'SCM_EVENT_HISTORY_UNAVAILABLE_OR_EMPTY'}
