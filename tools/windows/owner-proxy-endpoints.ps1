# Only the reversible lease is restored for a legacy binary rollback. The new
# bounded endpoint history is a separate file ignored by older services.
function Save-VeliqOwnerProxyLease([string]$ManifestFile,[string]$BackupDirectory) {
 $m=Get-Content -LiteralPath $ManifestFile -Raw|ConvertFrom-Json
 # StateDirectory has no default in the common Go manifest loader.
 if(!$m.state_directory -or ![IO.Path]::IsPathRooted([string]$m.state_directory)){throw 'OWNER_PROXY_STATE_PATH_INVALID'}
 $directory=(Get-Item -LiteralPath $m.state_directory -Force).FullName
 if((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'OWNER_PROXY_STATE_REPARSE_POINT'}
 $path=Join-Path $directory 'browser-owner-proxy.json'
 $saved=Join-Path $BackupDirectory 'browser-owner-proxy.json'
 $v=@{path=$path;backup=$saved;existed=$false;sha256='';acl_sddl=''}
 if(Test-Path -LiteralPath $path){
  $item=Get-Item -LiteralPath $path -Force
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 524288){throw 'OWNER_PROXY_LEASE_INVALID'}
  $v.acl_sddl=(Get-Acl -LiteralPath $path).Sddl
  Copy-Item -LiteralPath $path -Destination $saved
  $v.sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
  if((Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash -cne $v.sha256){throw 'OWNER_PROXY_BACKUP_MISMATCH'}
  $v.existed=$true
 }
 return $v
}
function Restore-VeliqOwnerProxyLease($Snapshot) {
 if(!$Snapshot.existed){return}
 if((Get-FileHash -LiteralPath $Snapshot.backup -Algorithm SHA256).Hash -cne $Snapshot.sha256){throw 'OWNER_PROXY_ROLLBACK_HASH_MISMATCH'}
 $directory=Split-Path -Parent $Snapshot.path
 if((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'OWNER_PROXY_STATE_REPARSE_POINT'}
 if(Test-Path -LiteralPath $Snapshot.path){
  $item=Get-Item -LiteralPath $Snapshot.path -Force
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'OWNER_PROXY_LEASE_INVALID'}
  $before=Get-Content -LiteralPath $Snapshot.backup -Raw|ConvertFrom-Json
  $current=Get-Content -LiteralPath $Snapshot.path -Raw|ConvertFrom-Json
  if($before.owner -cne $current.owner -or $before.installed.server -cne $current.installed.server -or $before.installed.pac -cne $current.installed.pac){throw 'OWNER_PROXY_ROLLBACK_LEASE_CHANGED'}
 }
 Copy-Item -LiteralPath $Snapshot.backup -Destination $Snapshot.path -Force
 $acl=[Security.AccessControl.FileSecurity]::new()
 $acl.SetSecurityDescriptorSddlForm([string]$Snapshot.acl_sddl)
 Set-Acl -LiteralPath $Snapshot.path -AclObject $acl
 if((Get-FileHash -LiteralPath $Snapshot.path -Algorithm SHA256).Hash -cne $Snapshot.sha256){throw 'OWNER_PROXY_ROLLBACK_READBACK_FAILED'}
}

function Invoke-VeliqOwnerEndpointPreparation([string]$Candidate,[string]$ManifestFile,[string]$DiagnosticDirectory) {
 # Native stderr must remain diagnostic data, not a PowerShell terminating
 # NativeCommandError that hides the exit code and skips the intended guard.
 foreach($path in @($Candidate,$ManifestFile)){
  if(![IO.Path]::IsPathRooted($path) -or $path.IndexOfAny([char[]]@('"',"`r","`n")) -ge 0){throw 'OWNER_PROXY_PREPARE_PATH_INVALID'}
  if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'OWNER_PROXY_PREPARE_REPARSE_POINT'}
 }
 $arguments='-remember-owner-proxy-endpoints -config "'+$ManifestFile+'"'
 $process=Start-Process -FilePath $Candidate -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $DiagnosticDirectory 'endpoint-prepare.stdout') -RedirectStandardError (Join-Path $DiagnosticDirectory 'endpoint-prepare.stderr')
 try{
  # Windows PowerShell 5.1 otherwise returns a null ExitCode after timed wait.
  # Retain the native handle while the child exists, then drain redirection.
  $null=$process.Handle
  if(!$process.WaitForExit(15000)){$process.Kill();$process.WaitForExit();throw 'OWNER_PROXY_ENDPOINT_PREPARE_TIMEOUT'}
  $process.WaitForExit()
  if($null -eq $process.ExitCode){throw 'OWNER_PROXY_ENDPOINT_EXIT_UNAVAILABLE'}
  if($process.ExitCode -ne 0){throw 'OWNER_PROXY_ENDPOINT_PREPARE_FAILED'}
 }finally{$process.Dispose()}
}

# Журнал — изменяемое состояние, а не часть EXE. Холодный снимок делается
# после остановки старой службы и до замены файла; путь берётся из манифеста.
function Get-VeliqDiagnosticJournalPath([string]$ManifestFile) {
 $m=Get-Content -LiteralPath $ManifestFile -Raw|ConvertFrom-Json
 if(!$m.state_directory -or ![IO.Path]::IsPathRooted([string]$m.state_directory)){throw 'JOURNAL_STATE_PATH_INVALID'}
 $directory=[IO.Path]::GetFullPath([string]$m.state_directory)
 $current=$directory
 while($current){
  if((Test-Path -LiteralPath $current) -and ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'JOURNAL_REPARSE_POINT_REJECTED'}
  $current=[IO.Path]::GetDirectoryName($current)
 }
 return (Join-Path $directory 'club-health-journal.json')
}
function Read-VeliqDiagnosticJournal([string]$Path) {
 $item=Get-Item -LiteralPath $Path -Force
 if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 4194304){throw 'JOURNAL_SNAPSHOT_INVALID'}
 $bytes=[IO.File]::ReadAllBytes($item.FullName)
 if($bytes.Length -gt 4194304){throw 'JOURNAL_SNAPSHOT_INVALID'}
 $value=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json
 if($value.format -ne 1 -or !$value.device -or @($value.rows).Count -gt 4096){throw 'JOURNAL_SNAPSHOT_INVALID'}
 $rows=@();if($null -ne $value.rows){$rows=@($value.rows)}
 $history=@();if($value.PSObject.Properties['history'] -and $null -ne $value.history){$history=@($value.history)}
 if($history.Count -gt 4096){throw 'JOURNAL_SNAPSHOT_INVALID'}
 $ids=@{}
 foreach($row in $rows+$history){
  if(!$row -or [string]$row.event.id -cnotmatch '^[0-9a-f]{32}$' -or $ids.ContainsKey([string]$row.event.id)){throw 'JOURNAL_EVENT_ID_INVALID'}
  $ids[[string]$row.event.id]=$row.event
 }
 $null=[uint64]$value.lost
 return [pscustomobject]@{bytes=$bytes;value=$value;events=$ids}
}
function Assert-VeliqDiagnosticBackupDirectory([string]$Directory) {
 $item=Get-Item -LiteralPath $Directory -Force
 if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'JOURNAL_BACKUP_DIRECTORY_INVALID'}
 $acl=Get-Acl -LiteralPath $Directory
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'JOURNAL_BACKUP_ACL_INVALID'}
 }
}
function Save-VeliqDiagnosticJournal([string]$ManifestFile,[string]$BackupDirectory) {
 $path=Get-VeliqDiagnosticJournalPath $ManifestFile
 Assert-VeliqDiagnosticBackupDirectory $BackupDirectory
 $saved=Join-Path $BackupDirectory 'diagnostic-journal.json'
 $meta=Join-Path $BackupDirectory 'diagnostic-journal-snapshot.json'
 foreach($target in @($BackupDirectory,$saved,$meta)){
  $walk=[IO.Path]::GetFullPath($target)
  while($walk){if((Test-Path -LiteralPath $walk) -and ((Get-Item -LiteralPath $walk -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'JOURNAL_REPARSE_POINT_REJECTED'};$walk=[IO.Path]::GetDirectoryName($walk)}
 }
 if((Test-Path -LiteralPath $saved) -or (Test-Path -LiteralPath $meta)){throw 'JOURNAL_SNAPSHOT_ALREADY_EXISTS'}
 $record=@{format=1;path=$path;existed=(Test-Path -LiteralPath $path);sha256='';acl_sddl=''}
 if($record.existed){
  $snapshot=Read-VeliqDiagnosticJournal $path
  $record.acl_sddl=(Get-Acl -LiteralPath $path).Sddl
  [IO.File]::WriteAllBytes($saved,$snapshot.bytes)
  $record.sha256=(Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash
  # Сверяется именно прочитанный снимок, а не повторное чтение живого пути.
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$expected=([BitConverter]::ToString($sha.ComputeHash($snapshot.bytes))).Replace('-','')}finally{$sha.Dispose()}
  if($expected -cne $record.sha256){throw 'JOURNAL_SNAPSHOT_HASH_MISMATCH'}
 }
 [IO.File]::WriteAllText($meta,($record|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
 return [pscustomobject]$record
}
function Restore-VeliqDiagnosticJournal([string]$ManifestFile,[string]$BackupDirectory) {
 Assert-VeliqDiagnosticBackupDirectory $BackupDirectory
 $meta=Join-Path $BackupDirectory 'diagnostic-journal-snapshot.json'
 if(!(Test-Path -LiteralPath $meta)){return}
 $record=Get-Content -LiteralPath $meta -Raw|ConvertFrom-Json
 $path=Get-VeliqDiagnosticJournalPath $ManifestFile
 if($record.format -ne 1 -or [string]$record.path -ine $path){throw 'JOURNAL_ROLLBACK_TARGET_MISMATCH'}
 if(!$record.existed){return}
 $saved=Join-Path $BackupDirectory 'diagnostic-journal.json'
 $snapshot=Read-VeliqDiagnosticJournal $saved
 if((Get-FileHash -LiteralPath $saved -Algorithm SHA256).Hash -cne $record.sha256){throw 'JOURNAL_ROLLBACK_HASH_MISMATCH'}
 $bytes=$snapshot.bytes
 if(Test-Path -LiteralPath $path){
  $current=Read-VeliqDiagnosticJournal $path
  if($current.value.device -cne $snapshot.value.device){throw 'JOURNAL_ROLLBACK_DEVICE_MISMATCH'}
  $archive=Join-Path $BackupDirectory 'diagnostic-journal-failed-candidate.json'
  if(!(Test-Path -LiteralPath $archive)){[IO.File]::WriteAllBytes($archive,$current.bytes)}
  # Уже известные потери нельзя скрыть возвратом к старому значению.
  if([uint64]$current.value.lost -gt [uint64]$snapshot.value.lost){
   $snapshot.value.lost=[uint64]$current.value.lost
   $bytes=[Text.Encoding]::UTF8.GetBytes(($snapshot.value|ConvertTo-Json -Depth 20 -Compress))
  }
 }
 [IO.File]::WriteAllBytes($path,$bytes)
 $acl=Get-Acl -LiteralPath $path
 if($acl.Sddl -cne [string]$record.acl_sddl){
  # SACL не читается и не очищается; изменяется только доступ к самому журналу.
  $acl.SetSecurityDescriptorSddlForm([string]$record.acl_sddl,[Security.AccessControl.AccessControlSections]::Access)
  Set-Acl -LiteralPath $path -AclObject $acl
  if((Get-Acl -LiteralPath $path).Sddl -cne [string]$record.acl_sddl){throw 'JOURNAL_ROLLBACK_ACL_MISMATCH'}
 }
 $actual=[IO.File]::ReadAllBytes($path)
 if([Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($bytes)){throw 'JOURNAL_ROLLBACK_READBACK_FAILED'}
}
function Assert-VeliqDiagnosticJournalPreserved([string]$Before,[string]$After) {
 $a=Read-VeliqDiagnosticJournal $Before;$b=Read-VeliqDiagnosticJournal $After
 if($a.value.device -cne $b.value.device){throw 'JOURNAL_DEVICE_CHANGED'}
 if([uint64]$a.value.lost -ne [uint64]$b.value.lost){throw 'JOURNAL_LOSS_COUNTER_CHANGED'}
 foreach($id in $a.events.Keys){
  if(!$b.events.ContainsKey($id)){throw 'PREVIOUS_JOURNAL_EVENT_MISSING'}
  foreach($field in $a.events[$id].PSObject.Properties){
   $next=$b.events[$id].PSObject.Properties[$field.Name]
   if(!$next -or ($field.Value|ConvertTo-Json -Depth 8 -Compress) -cne ($next.Value|ConvertTo-Json -Depth 8 -Compress)){throw 'PREVIOUS_JOURNAL_EVENT_CHANGED'}
  }
 }
 return [pscustomobject]@{preserved=$true;baseline_events=$a.events.Count;current_events=$b.events.Count;lost=[uint64]$b.value.lost;new_lost=0}
}
