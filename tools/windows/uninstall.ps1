[CmdletBinding()]param([string]$InstallDirectory="$env:ProgramData\VELIQ")
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Administrator
. (Join-Path $PSScriptRoot 'browser-policy-watchdog.ps1')
$service=Get-Service VELIQ -ErrorAction SilentlyContinue
if($service){
 $scm=Get-CimInstance Win32_Service -Filter "Name='VELIQ'" -OperationTimeoutSec 5
 $expected=[IO.Path]::GetFullPath((Join-Path $InstallDirectory 'veliq-service.exe'))
 $match=[regex]::Match([string]$scm.PathName,'^\s*"([^"]+)"(?:\s|$)')
 if(!$match.Success -or [IO.Path]::GetFullPath($match.Groups[1].Value) -ine $expected){throw 'SCM installation path mismatch; no stop/delete/policy changes performed'}

 Remove-VeliqPolicyWatchdog $InstallDirectory

 try {
  if($service.Status -ne 'Stopped'){Stop-Service VELIQ;$service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))}
  & (Join-Path $InstallDirectory 'veliq-service.exe') -cleanup-browser-policy -config (Join-Path $InstallDirectory 'service.json')
  if($LASTEXITCODE){throw 'OWNED_BROWSER_POLICY_CLEANUP_FAILED; SCM/files preserved; update service if cleanup command is unsupported'}
  & sc.exe delete VELIQ|Out-Null
  if($LASTEXITCODE){throw 'SCM deletion failed'}
 }finally{$service.Dispose()}
 $deadline=[DateTime]::UtcNow.AddSeconds(30)
 do {
  $remaining=Get-Service VELIQ -ErrorAction SilentlyContinue
  if(!$remaining){break}
  $remaining.Dispose()
  if([DateTime]::UtcNow -ge $deadline){throw 'SCM deletion is still pending; close Services/other service handles before reinstalling. Preserved files were not removed.'}
  Start-Sleep -Milliseconds 250
 }while($true)
}
if(!$service){Remove-VeliqPolicyWatchdog $InstallDirectory}
if(!$service -and (Test-Path -LiteralPath (Join-Path $InstallDirectory 'service.json'))){
 & (Join-Path $InstallDirectory 'veliq-service.exe') -cleanup-browser-policy -config (Join-Path $InstallDirectory 'service.json')
 if($LASTEXITCODE){throw 'OWNED_BROWSER_POLICY_CLEANUP_FAILED; foreign policy and credentials preserved'}
}
Write-Host 'SCM service removed. Credentials, reports and driver files were preserved for explicit rollback/cleanup.'
