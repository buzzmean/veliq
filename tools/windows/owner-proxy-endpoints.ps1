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
