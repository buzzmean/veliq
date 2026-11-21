# One-time move of a pre-rebrand install: SCM service "neexitlag" with
# %ProgramData%\neexitlag\neexitlag-service.exe becomes service "VELIQ" with
# %ProgramData%\VELIQ\veliq-service.exe. Identity, certificates, IPC token, state
# and owner ACLs move with the directory unchanged (rename, not copy), so the PC
# stays activated. Paths inside service.json are rewritten. Safe to call when
# nothing legacy is present (no-op). Dot-source, then call Move-VeliqLegacyInstall.
function Move-VeliqLegacyInstall([switch]$Start) {
 $legacyService=Get-Service -Name neexitlag -ErrorAction SilentlyContinue
 $old=Join-Path $env:ProgramData 'neexitlag';$new=Join-Path $env:ProgramData 'VELIQ'
 if(!$legacyService){
  if((Test-Path -LiteralPath $old) -and !(Test-Path -LiteralPath $new) -and (Test-Path -LiteralPath (Join-Path $old 'service.json'))){
   # Preserved state of an uninstalled legacy service: carry it over for reinstall.
   Rename-Item -LiteralPath $old -NewName 'VELIQ'
   $legacyExe=Join-Path $new 'neexitlag-service.exe';if(Test-Path -LiteralPath $legacyExe){Rename-Item -LiteralPath $legacyExe -NewName 'veliq-service.exe'}
   Update-VeliqLegacyManifest (Join-Path $new 'service.json')
  }
  return $false
 }
 if(Get-Service -Name VELIQ -ErrorAction SilentlyContinue){throw 'LEGACY_MIGRATION_CONFLICT: both neexitlag and VELIQ services exist'}
 if(Test-Path -LiteralPath $new){throw "LEGACY_MIGRATION_CONFLICT: $new already exists"}
 foreach($item in @((Get-Item -LiteralPath $old -Force))+@(Get-ChildItem -LiteralPath $old -Recurse -Force)){if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'LEGACY_MIGRATION_REPARSE_POINT_REFUSED'}}
 Write-Host '== Migrating legacy neexitlag install to VELIQ'
 $watchdog=Get-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog' -ErrorAction SilentlyContinue
 if($watchdog){Stop-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog' -ErrorAction SilentlyContinue}
 $startMode=(Get-CimInstance Win32_Service -Filter "Name='neexitlag'" -OperationTimeoutSec 5).StartMode
 if($legacyService.Status -ne 'Stopped'){Stop-Service -Name neexitlag -Force;$legacyService.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
 Get-NetFirewallRule -PolicyStore PersistentStore -Name 'neexitlag-native-tcp-v1*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
 & sc.exe delete neexitlag | Out-Null
 if($LASTEXITCODE){throw 'LEGACY_MIGRATION_SERVICE_DELETE_FAILED'}
 for($i=0;$i -lt 40 -and (Get-Service -Name neexitlag -ErrorAction SilentlyContinue);$i++){Start-Sleep -Milliseconds 250}
 Rename-Item -LiteralPath $old -NewName 'VELIQ'
 Rename-Item -LiteralPath (Join-Path $new 'neexitlag-service.exe') -NewName 'veliq-service.exe'
 $manifestPath=Join-Path $new 'service.json'
 Update-VeliqLegacyManifest $manifestPath
 $binary='"'+(Join-Path $new 'veliq-service.exe')+'" -config "'+$manifestPath+'"'
 New-Service -Name VELIQ -BinaryPathName $binary -DisplayName 'VELIQ Routing Service' -StartupType Automatic | Out-Null
 if($startMode -and $startMode -ne 'Auto'){Set-Service -Name VELIQ -StartupType $(if($startMode -eq 'Manual'){'Manual'}else{'Disabled'})}
 & sc.exe failure VELIQ reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
 . (Join-Path $PSScriptRoot 'native-tcp-firewall.ps1')
 [void](Add-NativeTcpFirewallAdmission (Join-Path $new 'veliq-service.exe'))
 Update-VeliqClubTaskPaths
 if($Start){Start-Service -Name VELIQ;(Get-Service -Name VELIQ).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))}
 if($watchdog){
  Unregister-ScheduledTask -TaskName 'VELIQ-BrowserPolicyWatchdog' -Confirm:$false -ErrorAction SilentlyContinue
  . (Join-Path $PSScriptRoot 'browser-policy-watchdog.ps1')
  Install-VeliqPolicyWatchdog $new
 }
 Write-Host "== Migrated: service VELIQ, $new"
 return $true
}
function Update-VeliqLegacyManifest([string]$Path) {
 if(!(Test-Path -LiteralPath $Path)){return}
 $raw=[IO.File]::ReadAllText($Path)
 $updated=$raw.Replace('\\neexitlag\\neexitlag-service.exe','\\VELIQ\\veliq-service.exe').Replace('\\ProgramData\\neexitlag','\\ProgramData\\VELIQ')
 if($updated -cne $raw){
  $acl=Get-Acl -LiteralPath $Path
  [IO.File]::WriteAllText("$Path.tmp",$updated,[Text.UTF8Encoding]::new($false))
  Set-Acl -LiteralPath "$Path.tmp" -AclObject $acl
  Move-Item -LiteralPath "$Path.tmp" -Destination $Path -Force
 }
}
# The club boot task points at the Setup payload and the service directory; both
# moved ("VELIQ Setup" -> "VELIQ", "neexitlag" -> "VELIQ"). Retarget in place.
function Update-VeliqClubTaskPaths {
 $club=Get-ScheduledTask -TaskName 'VELIQ Club Boot' -ErrorAction SilentlyContinue
 if(!$club){return}
 $action=$club.Actions[0];$old=[string]$action.Arguments
 $new=$old.Replace('\VELIQ Setup\','\VELIQ\').Replace('\ProgramData\neexitlag','\ProgramData\VELIQ')
 if($new -cne $old){$action.Arguments=$new;Set-ScheduledTask -TaskName 'VELIQ Club Boot' -Action $action | Out-Null}
}