Set-StrictMode -Version Latest
function Assert-Administrator {
 $principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
 if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run from an elevated Windows PowerShell.'}
}
function Assert-VpsIPv4([string]$Address) {
 $parsed=$null
 if(![Net.IPAddress]::TryParse($Address,[ref]$parsed) -or $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){throw 'An actual public VPS IPv4 is required.'}
 $b=$parsed.GetAddressBytes()
 if($b[0] -in @(0,10,127) -or $b[0] -ge 224 -or ($b[0] -eq 192 -and $b[1] -in @(168,0)) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or ($b[0] -eq 198 -and ($b[1] -in @(18,19) -or ($b[1] -eq 51 -and $b[2] -eq 100))) -or ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)){throw 'Private/documentation/special addresses cannot establish Internet acceptance.'}
 return $parsed.ToString()
}
function Assert-Ssh([string]$User,[int]$Port) {
 if($User -notmatch '^[a-z_][a-z0-9_-]*$' -or $Port -lt 1 -or $Port -gt 65535){throw 'Invalid SSH user/port.'}
}
function Read-Exact([IO.Stream]$Stream,[int]$Count,[DateTime]$Deadline) {
 $bytes=New-Object byte[] $Count;$offset=0
 while($offset -lt $Count){
  if([DateTime]::UtcNow -ge $Deadline){throw 'IPC timeout'}
  $pending=$Stream.BeginRead($bytes,$offset,$Count-$offset,$null,$null)
  if(!$pending.AsyncWaitHandle.WaitOne([int][Math]::Max(1,($Deadline-[DateTime]::UtcNow).TotalMilliseconds))){throw 'IPC timeout'}
  $n=$Stream.EndRead($pending)
  if($n -eq 0){throw 'IPC stream closed before complete frame'};$offset+=$n
 }
 return ,$bytes
}
function Invoke-ServiceIPCOnce([string]$Method,$Payload=$null,[string]$TokenFile="$env:ProgramData\VELIQ\ipc.token") {
 $id=[Guid]::NewGuid().ToString('N')
 $request=@{version=1;id=$id;sent_at=[DateTimeOffset]::UtcNow.ToString('o');token=[IO.File]::ReadAllText($TokenFile).Trim();method=$Method;payload=$Payload}|ConvertTo-Json -Depth 8 -Compress
 $bytes=[Text.Encoding]::UTF8.GetBytes($request)
 if($bytes.Length -gt 65536){throw 'IPC request too large'}
 $pipe=[IO.Pipes.NamedPipeClientStream]::new('.','neexitlag-v1',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous)
 try {
  $pipe.Connect(3000)
  $deadline=[DateTime]::UtcNow.AddSeconds(6)
  $header=[BitConverter]::GetBytes([uint32]$bytes.Length);[Array]::Reverse($header)
  foreach($part in @($header,$bytes)){$pending=$pipe.BeginWrite($part,0,$part.Length,$null,$null);if(!$pending.AsyncWaitHandle.WaitOne([int][Math]::Max(1,($deadline-[DateTime]::UtcNow).TotalMilliseconds))){throw 'IPC write timeout'};$pipe.EndWrite($pending)}
  $lengthBytes=Read-Exact $pipe 4 $deadline;[Array]::Reverse($lengthBytes);$length=[BitConverter]::ToUInt32($lengthBytes,0)
  if($length -lt 1 -or $length -gt 65536){throw 'Invalid IPC response size'}
  $response=[Text.Encoding]::UTF8.GetString((Read-Exact $pipe $length $deadline))|ConvertFrom-Json
  if($response.version -ne 1 -or $response.id -ne $id){throw 'IPC version/request ID mismatch'}
  if(!$response.ok){throw $response.error}
  return $response.data
 } finally {$pipe.Dispose()}
}
# The service opens its pipe before slow initialization and answers "service is
# starting" until it finishes; wait for that state instead of failing the caller.
function Invoke-ServiceIPC([string]$Method,$Payload=$null,[string]$TokenFile="$env:ProgramData\VELIQ\ipc.token") {
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 while($true){
  try{return Invoke-ServiceIPCOnce $Method $Payload $TokenFile}
  catch{
   if("$_" -notlike '*service is starting*' -or [DateTime]::UtcNow -ge $deadline){throw}
   Start-Sleep -Milliseconds 500
  }
 }
}
function Invoke-VpsCommand([string]$Address,[string]$User,[int]$Port,[string]$Command) {
 Assert-Ssh $User $Port
 if($User -eq 'root'){$Command=$Command.Replace('sudo -n ','')}
 & ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -p $Port "$User@$Address" $Command
 if($LASTEXITCODE -ne 0){throw 'SSH command failed; configure key/agent, verified known_hosts and noninteractive sudo.'}
}

# Normalize only staged deployment source, never binary or credential files.
function Convert-DeploymentToLF([string]$Directory) {
 foreach($file in Get-ChildItem $Directory -Recurse -File | Where-Object {$_.Extension -in @('.sh','.py','.service')}) {
  $text=[IO.File]::ReadAllText($file.FullName).Replace("`r`n","`n").Replace("`r","`n")
  [IO.File]::WriteAllText($file.FullName,$text,[Text.UTF8Encoding]::new($false))
 }
}
