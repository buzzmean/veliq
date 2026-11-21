# Per-user GUI install/update only. Never reads/writes service identity or Chrome
# policy. Run as the ordinary installation owner, with GUI exited from the tray.
[CmdletBinding()]
param(
 [string]$SourceDirectory=(Join-Path $PSScriptRoot '..\..\bin\release'),
 [string]$InstallDirectory=(Join-Path $env:LOCALAPPDATA 'Programs\VELIQ'),
 [string]$ShortcutDirectory=[Environment]::GetFolderPath('Programs')
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$source=(Get-Item -LiteralPath (Join-Path $SourceDirectory 'VELIQ.exe')).FullName
$root=[IO.Path]::GetFullPath($InstallDirectory)
if(!(Test-Path -LiteralPath $root)){[void][IO.Directory]::CreateDirectory($root)}
$target=Join-Path $root 'VELIQ.exe';$legacy=Join-Path $root 'NeExitLag.exe'
foreach($path in @($source,$root,$target,$legacy)){
 if((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'VELIQ GUI install refuses reparse points'}
}
if($source -ieq $target){throw 'Build source must differ from installed GUI'}
foreach($p in @(Get-Process -Name VELIQ,NeExitLag -ErrorAction SilentlyContinue)){
 if($p.Path -ieq $target -or $p.Path -ieq $legacy){throw 'Exit VELIQ/legacy GUI through its tray menu before updating'}
}
$stamp=Join-Path $root 'veliq-install.json'
# Never overwrite an unidentified application. Legacy NeExitLag.exe may exist
# alone in this dedicated product directory; keep it as an identical entrypoint.
if((Test-Path -LiteralPath $target) -and !(Test-Path -LiteralPath $stamp)){throw 'Existing VELIQ.exe has no installation marker; refusing overwrite'}
$backup=Join-Path $root ('backups\gui-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($backup)
foreach($name in @('VELIQ.exe','NeExitLag.exe','veliq-install.json')){if(Test-Path -LiteralPath (Join-Path $root $name)){Copy-Item -LiteralPath (Join-Path $root $name) -Destination (Join-Path $backup $name)}}
$changed=@();$pending=Join-Path $root ('.veliq-'+[Guid]::NewGuid().ToString('N'))
try{
 foreach($path in @($target)){
  Copy-Item -LiteralPath $source -Destination $pending
  if(Test-Path -LiteralPath $path){[IO.File]::Replace($pending,$path,[NullString]::Value)}else{[IO.File]::Move($pending,$path)}
  $changed+=,$path
  if((Get-FileHash -LiteralPath $path).Hash -ne (Get-FileHash -LiteralPath $source).Hash){throw 'VELIQ installed GUI hash mismatch'}
 }
 $scripts=Join-Path $SourceDirectory 'tools\windows'
 if(Test-Path -LiteralPath $scripts){
  $destination=Join-Path $root 'tools\windows';[void][IO.Directory]::CreateDirectory($destination)
  Copy-Item -Path (Join-Path $scripts '*.ps1') -Destination $destination -Force
 }
 # The pre-rebrand NeExitLag.exe alias was a copy of the same GUI; remove it.
 if(Test-Path -LiteralPath $legacy){Remove-Item -LiteralPath $legacy -Force}
 @{product='VELIQ';executable='VELIQ.exe';sha256=(Get-FileHash -LiteralPath $target).Hash}|ConvertTo-Json|Set-Content -LiteralPath $stamp -Encoding UTF8
}catch{
 foreach($path in $changed){$old=Join-Path $backup ([IO.Path]::GetFileName($path));if(Test-Path -LiteralPath $old){Copy-Item -LiteralPath $old -Destination $path -Force}else{Remove-Item -LiteralPath $path -Force}}
 throw
}finally{Remove-Item -LiteralPath $pending -Force -ErrorAction SilentlyContinue}
# Display name changes; compatibility registry value and persisted directories do
# not. Only retarget an enabled Run entry which belongs to this installation.
$runKey='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$run=Get-ItemProperty -LiteralPath $runKey -ErrorAction SilentlyContinue
if($null -ne $run -and $null -ne $run.PSObject.Properties['NeExitLag']){
 $old=[string]$run.NeExitLag
 if($old -ieq ('"'+$legacy+'"') -or $old -ieq ('"'+$target+'"')){Set-ItemProperty -LiteralPath $runKey -Name VELIQ -Value ('"'+$target+'"');Remove-ItemProperty -LiteralPath $runKey -Name NeExitLag -ErrorAction SilentlyContinue}
}
[void][IO.Directory]::CreateDirectory($ShortcutDirectory)
$shell=New-Object -ComObject WScript.Shell
$link=Join-Path $ShortcutDirectory 'VELIQ.lnk'
if(Test-Path -LiteralPath $link){$existing=$shell.CreateShortcut($link);if($existing.TargetPath -ine $target -and $existing.TargetPath -ine $legacy){throw 'Foreign VELIQ shortcut preserved; GUI files installed'}}
$shortcut=$shell.CreateShortcut($link);$shortcut.TargetPath=$target;$shortcut.WorkingDirectory=$root;$shortcut.Description='VELIQ';$shortcut.Save()
# Replace only our own legacy Start menu link, after the new link is saved.
$oldLink=Join-Path $ShortcutDirectory 'NeExitLag.lnk'
if(Test-Path -LiteralPath $oldLink){$old=$shell.CreateShortcut($oldLink);if($old.TargetPath -ieq $legacy -or $old.TargetPath -ieq $target){Copy-Item -LiteralPath $oldLink -Destination (Join-Path $backup 'NeExitLag.lnk');Remove-Item -LiteralPath $oldLink}}
Write-Host "VELIQ installed: $target"
Write-Host "Backup: $backup"
Write-Host 'Service identity, profiles, preferences, IPC, Chrome policy/recovery and credentials unchanged.'
