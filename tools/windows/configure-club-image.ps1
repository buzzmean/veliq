# Called only by Setup /CLUBIMAGE=1 after a clean ActivationOnly installation.
[CmdletBinding()]
param([string]$InstallDirectory="$env:ProgramData\VELIQ",[string]$ClubCodeFile='')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1');Assert-Administrator
. (Join-Path $PSScriptRoot 'club-image-common.ps1')
Assert-ClubImageClean $InstallDirectory
$manifestPath=Join-Path $InstallDirectory 'service.json';$manifest=Get-Content -Raw -LiteralPath $manifestPath|ConvertFrom-Json
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if($manifest.owner_sid -cne $owner){throw 'CLUB_OWNER_SID_MISMATCH'}
$boot=Join-Path $PSScriptRoot 'club-image-boot.ps1'
foreach($p in @($boot,$InstallDirectory)){if($p.Contains("'")){throw 'CLUB_TASK_PATH_UNSUPPORTED'}}
$action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& '''+$boot+''' -InstallDirectory '''+$InstallDirectory+'''"')
Assert-ClubBootTaskOwnership $action.Arguments
# No enrollment: stage_for_boot pauses the current activation worker. The boot
# flag is also durable protection against a service crash before image capture.
if($ClubCodeFile){& (Join-Path $PSScriptRoot 'stage-club-activation.ps1') -InstallDirectory $InstallDirectory -ProtectedCodeFile $ClubCodeFile}
$manifest|Add-Member -Force -NotePropertyName club_image -NotePropertyValue ([bool]$ClubCodeFile)
$manifest|Add-Member -Force -NotePropertyName club_browser_paths -NotePropertyValue @(Get-ClubBrowserPaths)
Write-ClubJson $manifestPath $manifest
if($ClubCodeFile){Write-ClubJson (Join-Path $InstallDirectory 'club-mode.json') @{version=1;enabled=$true;managed_by='WINDOWS_ADMINISTRATOR'} -OwnerSid $owner -Public}
else{Write-ClubJson (Join-Path $InstallDirectory 'club-account-preparation.json') @{version=1;owner_sid=$owner;browser_paths=@(Get-ClubBrowserPaths)}}
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'VELIQ Club Boot' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force|Out-Null
# Setup installs the GUI machine-wide next to this payload ({app}\VELIQ.exe).
$gui=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\VELIQ.exe'))
$run='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';New-Item $run -Force|Out-Null
Set-ItemProperty -LiteralPath $run -Name VELIQ -Value ('"'+$gui+'" --club')
if(!$ClubCodeFile){Write-Output 'CLUB_ACCOUNT_SIGN_IN_REQUIRED; open VELIQ, sign in and approve the clean image before sealing';return}
Stop-Service VELIQ -ErrorAction Stop
(Get-Service VELIQ).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
Assert-ClubImageClean $InstallDirectory
Write-Output 'CLUB_IMAGE_SEALED; service stopped/automatic, code staged, no device identity; commit image now; per-PC writable overlays REQUIRED'
