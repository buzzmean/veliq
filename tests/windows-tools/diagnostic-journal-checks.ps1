$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../tools/windows/owner-proxy-endpoints.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('veliq-journal-'+[Guid]::NewGuid().ToString('N'))
$state=Join-Path $root 'state';$backup=Join-Path $root 'backup'
try{
 foreach($dir in @($state,$backup)){
  [void][IO.Directory]::CreateDirectory($dir)
  $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
  foreach($sid in @('S-1-5-18','S-1-5-32-544')){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
  Set-Acl -LiteralPath $dir -AclObject $acl
 }
 $manifest=Join-Path $root 'service.json';[IO.File]::WriteAllText($manifest,(@{state_directory=$state}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
 $path=Join-Path $state 'club-health-journal.json'
 $event=@{id=('a'*32);at='2026-11-25T10:00:00Z';pc='PC13';version='0.3.739';source='fixture';code='OS_ERROR';native_code=10061;operation='OPEN';pid=20;birth=30}
 $old=@{format=1;device='fixture-owner';lost=25165;open=$false;rows=@(@{event=$event})}
 [IO.File]::WriteAllText($path,($old|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
 $before=[IO.File]::ReadAllBytes($path)
 $null=Save-VeliqDiagnosticJournal $manifest $backup
 $new=@{format=1;device='fixture-owner';lost=25165;open=$true;history=$old.rows;rows=@(@{event=@{id=('b'*32);code='SERVICE_STARTED'}})}
 [IO.File]::WriteAllText($path,($new|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
 $proof=Assert-VeliqDiagnosticJournalPreserved (Join-Path $backup 'diagnostic-journal.json') $path
 if(!$proof.preserved -or $proof.new_lost -ne 0 -or $proof.lost -ne 25165){throw 'JOURNAL_HISTORICAL_LOSS_NOT_PRESERVED'}
 $null=Restore-VeliqDiagnosticJournal $manifest $backup
 if([Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) -cne [Convert]::ToBase64String($before)){throw 'JOURNAL_739_BYTES_NOT_RESTORED'}
 if(!(Test-Path -LiteralPath (Join-Path $backup 'diagnostic-journal-failed-candidate.json'))){throw 'JOURNAL_CANDIDATE_EVIDENCE_NOT_PRESERVED'}
 # Сбой доказательства: событие отсутствует, код изменён, счётчик вырос/обнулён.
 foreach($kind in @('missing','changed','increased','cleared','device')){
  $bad=$old|ConvertTo-Json -Depth 12 -Compress|ConvertFrom-Json
  if($kind -eq 'missing'){$bad.rows=@()}
  elseif($kind -eq 'changed'){$bad.rows[0].event.native_code=10054}
  elseif($kind -eq 'increased'){$bad.lost=25166}
  elseif($kind -eq 'cleared'){$bad.lost=0}
  else{$bad.device='other-owner'}
  [IO.File]::WriteAllText($path,($bad|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
  $rejected=$false;try{$null=Assert-VeliqDiagnosticJournalPreserved (Join-Path $backup 'diagnostic-journal.json') $path}catch{$rejected=$true}
  if(!$rejected){throw ('JOURNAL_FALSE_PROOF_'+$kind)}
 }
 # Возврат не должен скрывать новую известную потерю.
 $old.lost=25166;[IO.File]::WriteAllText($path,($old|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
 $null=Restore-VeliqDiagnosticJournal $manifest $backup
 if((Get-Content -LiteralPath $path -Raw|ConvertFrom-Json).lost -ne 25166){throw 'JOURNAL_ROLLBACK_RESET_LOSS'}
 # До активации строкаdevice пуста, но журнал всё равно корректен.
 $pending=Join-Path $root 'pending.json';$old.device='';$old.lost=0
 [IO.File]::WriteAllText($pending,($old|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
 $pendingRead=Read-VeliqDiagnosticJournal $pending
 if($pendingRead.value.device -cne ''){throw 'JOURNAL_PENDING_ACTIVATION_REJECTED'}
 foreach($invalid in @($null,7,@{unexpected=$true})){
  $old.device=$invalid
  [IO.File]::WriteAllText($pending,($old|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
  $rejected=$false;try{$null=Read-VeliqDiagnosticJournal $pending}catch{$rejected=$true}
  if(!$rejected){throw 'JOURNAL_INVALID_DEVICE_ACCEPTED'}
 }
 # Подменённый снимок отвергается до записи в рабочий файл.
 [IO.File]::AppendAllText((Join-Path $backup 'diagnostic-journal.json'),' ')
 $rejected=$false;try{$null=Restore-VeliqDiagnosticJournal $manifest $backup}catch{$rejected=$true}
 if(!$rejected){throw 'JOURNAL_TAMPERED_SNAPSHOT_ACCEPTED'}
 Write-Output 'PASS: historical loss, rows/history, exact rollback, candidate evidence, changed event/device/loss and tampered snapshot'
}finally{if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force}}
