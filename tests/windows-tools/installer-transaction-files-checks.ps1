# Snapshot/restore only, in a workspace fixture. No service installation or GUI.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if(Get-Service VELIQ -ErrorAction SilentlyContinue){throw 'FILES_FIXTURE_REQUIRES_ABSENT_SERVICE'}
if(Test-Path -LiteralPath (Join-Path $env:ProgramData 'VELIQ')){throw 'FILES_FIXTURE_PRESERVES_EXISTING_STATE'}
$key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{E18D91DB-2E64-4405-A05E-AB15A4192318}_is1'
if(Test-Path -LiteralPath $key){throw 'FILES_FIXTURE_PRESERVES_EXISTING_REGISTRATION'}
foreach($folder in @('CommonPrograms','CommonDesktopDirectory')){
 if(Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath($folder)) 'VELIQ.lnk')){throw 'FILES_FIXTURE_PRESERVES_EXISTING_SHORTCUT'}
}
$base=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../bin'))
$fixture=Join-Path $base ('transaction-test-'+[guid]::NewGuid().ToString('N'))
$app=Join-Path $fixture 'app';$backup=Join-Path $fixture 'backup';$log=Join-Path $fixture 'diagnostics.jsonl'
$script=Join-Path $PSScriptRoot '../../installer/transaction.ps1'
$hostExe=if($PSVersionTable.PSEdition -eq 'Desktop'){Join-Path $PSHOME 'powershell.exe'}else{Join-Path $PSHOME 'pwsh.exe'}
try{
 [void][IO.Directory]::CreateDirectory((Join-Path $app 'gui'))
 [IO.File]::WriteAllText((Join-Path $app 'VELIQ.exe'),'old GUI bytes')
 [IO.File]::WriteAllText((Join-Path $app 'gui/data.dll'),'old library bytes')
 [IO.File]::WriteAllText((Join-Path $app 'unins000.dat'),'old uninstall bytes')
 & $hostExe -NoProfile -File $script -Action Prepare -AppDirectory $app -TransactionDirectory $backup -DiagnosticFile $log
 if($LASTEXITCODE){if(Test-Path -LiteralPath $log){Get-Content -LiteralPath $log -Tail 4|Write-Output};throw 'FILES_PREPARE_FAILED'}
 [IO.File]::WriteAllText((Join-Path $app 'VELIQ.exe'),'new failed GUI bytes')
 [void][IO.Directory]::CreateDirectory((Join-Path $app 'service'))
 [IO.File]::WriteAllText((Join-Path $app 'service/new.exe'),'new payload')
 & $hostExe -NoProfile -File $script -Action Rollback -AppDirectory $app -TransactionDirectory $backup -DiagnosticFile $log
 if($LASTEXITCODE){if(Test-Path -LiteralPath $log){Get-Content -LiteralPath $log -Tail 4|Write-Output};throw 'FILES_ROLLBACK_FAILED'}
 foreach($pair in @(@('VELIQ.exe','old GUI bytes'),@('gui/data.dll','old library bytes'),@('unins000.dat','old uninstall bytes'))){
  if([IO.File]::ReadAllText((Join-Path $app $pair[0])) -cne $pair[1]){throw 'FILES_PREVIOUS_BYTES_NOT_RESTORED'}
 }
 if(Test-Path -LiteralPath (Join-Path $app 'service/new.exe')){throw 'FILES_NEW_PAYLOAD_NOT_REMOVED'}
 if((Get-Content -Raw -LiteralPath $log) -notmatch 'TRANSACTION_ROLLED_BACK'){throw 'FILES_DIAGNOSTICS_MISSING'}
 Write-Output 'PASS real snapshot/restore of GUI, library and uninstall metadata; no service/task/registry/shortcut mutation'
}finally{
 $resolved=[IO.Path]::GetFullPath($fixture)
 if(!$resolved.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'FILES_FIXTURE_CLEANUP_TARGET_INVALID'}
 if(Test-Path -LiteralPath $resolved){Remove-Item -LiteralPath $resolved -Recurse -Force}
}
