# Preload shared diagnostics in memory; no remote files or working-directory dependency.
function Get-ActivationRemoteCode([string]$Code){
 $path=Join-Path $PSScriptRoot '..\..\deploy\vps\activation-diagnostics.py'
 $source=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
 $prefix="import base64,sys,types`nm=types.ModuleType('activation_diagnostics');m.__file__='activation-diagnostics.py'`nsys.modules[m.__name__]=m`nexec(compile(base64.b64decode('$source'),m.__file__,'exec'),m.__dict__)`n"
 return $prefix+$Code.TrimStart([char]0xfeff).Replace("`r`n","`n")
}
# Host-verified console transport shared by activation deploy and read-only audit.
# No bootstrap/enroll/provision code is loaded or called here.
function Quote-ActivationSSH([string]$Value){return '"'+[regex]::Replace([regex]::Replace($Value,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"'}
function Invoke-ActivationSSH {
 param([string]$Payload,[string]$RemoteCode,[string]$KnownHosts,[string]$VpsIP,[string]$SSHUser,[int]$SSHPort=22)
 foreach($value in @($Payload,$RemoteCode,$KnownHosts,$VpsIP,$SSHUser)){if([string]::IsNullOrEmpty($value)){throw 'ACTIVATION_SSH_ARGUMENTS_INVALID; no process started; VPS unchanged by this request'}}
 $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-ActivationRemoteCode $RemoteCode)))
 $remote="python3 -c `"exec(__import__('base64').b64decode('$encoded'))`""
 if($SSHUser -ne 'root'){$remote='sudo -n '+$remote}
 $arguments=@('-T','-F','none','-p',"$SSHPort",'-o','StrictHostKeyChecking=ask','-o',"UserKnownHostsFile=$KnownHosts",'-o','GlobalKnownHostsFile=NUL','-o','ConnectTimeout=15','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3',"${SSHUser}@${VpsIP}",$remote)
 $info=[Diagnostics.ProcessStartInfo]::new('ssh.exe',(($arguments|ForEach-Object {Quote-ActivationSSH $_}) -join ' '))
 # .NET Framework lacks StandardInputEncoding. The JSON/base64 payload is
 # ASCII; Python json.loads(bytes) accepts its optional BOM. Core can pin UTF-8.
 if($null -ne $info.PSObject.Properties['StandardInputEncoding']){$info.StandardInputEncoding=[Text.UTF8Encoding]::new($false)}
 $info.UseShellExecute=$false;$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.CreateNoWindow=$false
 # Leave stderr attached to the console: OpenSSH password prompts need it.
 # Remote Python emits only allowlisted diagnostics, never raw command stderr.
 $p=[Diagnostics.Process]::Start($info)
 try{
  $output=$p.StandardOutput.ReadToEndAsync()
  $p.StandardInput.Write($Payload);$p.StandardInput.Close()
  if(!$p.WaitForExit(600000)){try{$p.Kill()}catch{};throw 'ACTIVATION_SSH_TIMEOUT; VPS change state UNKNOWN; run read-only verification'}
  $p.WaitForExit();$p.Refresh()
  $wire=$output.GetAwaiter().GetResult()
  if($wire.Length -gt 131072){throw 'ACTIVATION_SSH_RESPONSE_TOO_LARGE; VPS change state UNKNOWN; run read-only verification'}
  # Safe remote preflight/step reports remain visible even on nonzero exit.
  if($p.ExitCode -ne 0){
   if($wire){Write-Host $wire}
   Write-Host ('ACTIVATION_SSH_EXIT code='+$p.ExitCode+'; remote diagnostics above; VPS change state UNKNOWN unless explicitly reported by remote; run read-only verification')
   throw 'ACTIVATION_REMOTE_OPERATION_FAILED; no claim that VPS was unchanged'
  }
  return $wire
 }finally{$p.Dispose()}
}
