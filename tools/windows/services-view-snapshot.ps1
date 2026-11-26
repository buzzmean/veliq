#requires -Version 5.1
# Standalone, bounded IPC reads. Never prints a token, path, destination or raw payload.
param([ValidateRange(1,6)][int]$Samples=4)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

function Read-ViewField($Value,[string]$Name,$Default='UNKNOWN') {
 if($null -eq $Value){return $Default}
 $property=$Value.PSObject.Properties[$Name]
 if($null -eq $property -or $null -eq $property.Value){return $Default}
 return $property.Value
}
function Read-ViewBytes([IO.Stream]$Stream,[int]$Count,[DateTime]$Deadline) {
 $buffer=New-Object byte[] $Count
 $offset=0
 while($offset -lt $Count){
  $remaining=[int][Math]::Max(0,($Deadline-[DateTime]::UtcNow).TotalMilliseconds)
  if($remaining -lt 1){throw 'IPC_TIMEOUT'}
  $pending=$Stream.BeginRead($buffer,$offset,$Count-$offset,$null,$null)
  if(!$pending.AsyncWaitHandle.WaitOne($remaining)){throw 'IPC_TIMEOUT'}
  $n=$Stream.EndRead($pending)
  if($n -eq 0){throw 'IPC_CLOSED'}
  $offset+=$n
 }
 return ,$buffer
}
function Invoke-ViewRead([ValidateSet('status','profiles','capture.diagnostics','relay.primary.status')][string]$Method,[string]$TokenFile=(Join-Path $env:ProgramData 'VELIQ\ipc.token'),[string]$PipeName='neexitlag-v1') {
 $pipe=$null;$bytes=$null
 try {
  $id=[Guid]::NewGuid().ToString('N')
  $request=@{version=1;id=$id;sent_at=[DateTimeOffset]::UtcNow.ToString('o');token=[IO.File]::ReadAllText($TokenFile).Trim();method=$Method;payload=$null}|ConvertTo-Json -Compress
  $bytes=[Text.Encoding]::UTF8.GetBytes($request)
  $pipe=[IO.Pipes.NamedPipeClientStream]::new('.',$PipeName,[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous)
  $deadline=[DateTime]::UtcNow.AddSeconds(2)
  $pipe.Connect(800)
  $header=[BitConverter]::GetBytes([uint32]$bytes.Length)
  if([BitConverter]::IsLittleEndian){[Array]::Reverse($header)}
  foreach($part in @($header,$bytes)){
   $remaining=[int][Math]::Max(0,($deadline-[DateTime]::UtcNow).TotalMilliseconds)
   if($remaining -lt 1){throw 'IPC_TIMEOUT'}
   $pending=$pipe.BeginWrite($part,0,$part.Length,$null,$null)
   if(!$pending.AsyncWaitHandle.WaitOne($remaining)){throw 'IPC_TIMEOUT'}
   $pipe.EndWrite($pending)
  }
  $lengthBytes=Read-ViewBytes $pipe 4 $deadline
  if([BitConverter]::IsLittleEndian){[Array]::Reverse($lengthBytes)}
  $length=[BitConverter]::ToUInt32($lengthBytes,0)
  if($length -lt 1 -or $length -gt 65536){throw 'IPC_BAD_FRAME'}
  $response=[Text.Encoding]::UTF8.GetString((Read-ViewBytes $pipe ([int]$length) $deadline))|ConvertFrom-Json
  if($response.version -ne 1 -or $response.id -ne $id){throw 'IPC_BAD_REPLY'}
  if(!$response.ok){throw 'IPC_REJECTED'}
  return [pscustomobject]@{ok=$true;data=$response.data;error_code=''}
 } catch {
  # Do not copy exception messages from an IPC response or credential I/O.
  $code=$_.Exception.Message
  if($code -notmatch '^IPC_(TIMEOUT|CLOSED|BAD_FRAME|BAD_REPLY|REJECTED)$'){$code=$_.Exception.GetType().Name}
  return [pscustomobject]@{ok=$false;data=$null;error_code=$code}
 } finally {
  if($null -ne $pipe){$pipe.Dispose()}
  if($null -ne $bytes){[Array]::Clear($bytes,0,$bytes.Length)}
 }
}
function Get-ViewSample([int]$Index,$Status,$Capture) {
 $flows=@(Read-ViewField $Capture 'flows' @())
 $chat=@($flows|Where-Object {(Read-ViewField $_ 'process_group' '') -eq 'chatgpt-desktop'})
 $relays=@((Read-ViewField $Status 'routes' @())|Where-Object {
  if((Read-ViewField $_ 'id' '') -eq 'DIRECT' -or (Read-ViewField $_ 'status' '') -ne 'healthy'){return $false}
  $observed=[DateTimeOffset]::MinValue
  if(![DateTimeOffset]::TryParse([string](Read-ViewField $_ 'observed_at' ''),[ref]$observed)){return $false}
  $age=([DateTimeOffset]::UtcNow-$observed).TotalSeconds
  return $age -ge -5 -and $age -lt 90
 })
 return [pscustomobject][ordered]@{
  N=$Index
  Time=[DateTimeOffset]::Now.ToString('HH:mm:ss')
  Connected=Read-ViewField $Status 'connected'
  Optimizing=Read-ViewField $Status 'optimizing'
  Profiles=if($null -eq $Status){'UNKNOWN'}else{@(Read-ViewField $Status 'profiles' @()).Count}
  FreshRelays=if($null -eq $Status){'UNKNOWN'}else{$relays.Count}
  Flows=if($null -eq $Capture){'UNKNOWN'}else{$flows.Count}
  Truncated=Read-ViewField $Capture 'truncated'
  CodexFlows=if($null -eq $Capture){'UNKNOWN'}else{$chat.Count}
  CodexBlocked=if($null -eq $Capture){'UNKNOWN'}else{@($chat|Where-Object {(Read-ViewField $_ 'relay_required_blocked' $false) -eq $true -or (Read-ViewField $_ 'selected_route' '') -like 'BLOCK*'}).Count}
 }
}

Write-Output 'VELIQ read-only snapshot v1; service and routes are not changed.'
$profiles=Invoke-ViewRead 'profiles'
if($profiles.ok){Write-Output ('SAVED_PROFILES='+@($profiles.data).Count)}else{Write-Output ('PROFILES_ERROR='+$profiles.error_code)}
$primary=Invoke-ViewRead 'relay.primary.status'
if($primary.ok){
 $connections=@(Read-ViewField $primary.data 'connections' @())
 Write-Output ('PRIMARY_PREFERENCE='+(Read-ViewField $primary.data 'preferred_for_new_opens'))
 Write-Output ('HEALTHY_POOLS='+@($connections|Where-Object {(Read-ViewField $_ 'pool_healthy' $false) -eq $true}).Count)
}else{Write-Output ('PRIMARY_ERROR='+$primary.error_code)}
$rows=@()
for($i=1;$i -le $Samples;$i++){
 $status=Invoke-ViewRead 'status'
 $capture=Invoke-ViewRead 'capture.diagnostics'
 if(!$status.ok){Write-Output ('STATUS_ERROR['+$i+']='+$status.error_code)}
 if(!$capture.ok){Write-Output ('CAPTURE_ERROR['+$i+']='+$capture.error_code)}
 $rows+=Get-ViewSample $i $status.data $capture.data
 if($i -lt $Samples){Start-Sleep -Milliseconds 800}
}
$rows|Format-Table -AutoSize|Out-String -Width 220|Write-Output
