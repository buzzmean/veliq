# Administrative update only: same-owner/session activation pipe, no process kill.
[CmdletBinding()]param()
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1');Assert-Administrator
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
$roots=@((Join-Path $env:LOCALAPPDATA 'Programs\VELIQ'),[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\bin\release')))
$owned=@(Get-Process VELIQ,NeExitLag -ErrorAction SilentlyContinue | Where-Object {$_.SessionId -eq $session -and $_.Path -and ([IO.Path]::GetDirectoryName($_.Path) -in $roots)})
if(!$owned.Count){Write-Output 'VELIQ_GUI_ALREADY_CLOSED';return}
$pipe=[IO.Pipes.NamedPipeClientStream]::new('.','NeExitLag-activate-'+$sid+'-'+$session,[IO.Pipes.PipeDirection]::Out)
try{$pipe.Connect(1500);$pipe.WriteByte(2)}finally{$pipe.Dispose()}
foreach($p in $owned){try{if(!$p.WaitForExit(15000)){throw 'VELIQ_GUI_UPDATE_CLOSE_PENDING; no process killed'}}finally{$p.Dispose()}}
Write-Output 'VELIQ_GUI_CLOSED_FOR_UPDATE; browsers/game processes untouched'
