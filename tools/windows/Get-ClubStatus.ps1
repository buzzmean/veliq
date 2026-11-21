# One read-only local/remote summary. Never enables remote access or requests credentials.
[CmdletBinding()]
param([string[]]$ComputerName=@())
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
function Field($o,[string]$n,$default=''){if($null -ne $o){$p=$o.PSObject.Properties[$n];if($p){return $p.Value}};return $default}
if($ComputerName.Count -eq 0){
 . (Join-Path $PSScriptRoot 'common.ps1')
 $svc=Get-Service VELIQ -ErrorAction SilentlyContinue
 if(!$svc -or $svc.Status -ne 'Running'){Write-Output 'VELIQ SERVICE_STOPPED_OR_ABSENT';return}
 $s=Invoke-ServiceIPC 'club.status';Write-Output (Field $s 'summary' 'CLUB_STATUS_UNAVAILABLE');return
}
if($ComputerName.Count -gt 64){throw 'CLUB_SUMMARY_HOST_LIMIT'}
foreach($name in $ComputerName){
 if($name -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$'){throw 'CLUB_SUMMARY_HOST_INVALID'}
 try{
  $path='\\'+$name+'\C$\ProgramData\VELIQ\club-status.json'
  $file=Get-Item -LiteralPath $path;if($file.Length -gt 32768){throw 'CLUB_STATUS_TOO_LARGE'}
  $s=Get-Content -Raw -LiteralPath $path|ConvertFrom-Json
  $at=[DateTimeOffset]::Parse([string](Field $s 'at'));$age=([DateTimeOffset]::UtcNow-$at).TotalSeconds
  if($age -lt -30 -or $age -gt 60){Write-Output ($name+' STALE_STATUS; check service/boot/clock');continue}
  Write-Output ($name+' '+(Field $s 'summary' 'CLUB_STATUS_UNAVAILABLE')+' [file snapshot; not live remote attestation]')
 }catch{Write-Output ($name+' UNAVAILABLE; existing admin-share access required; no permissions/firewall changed')}
}
