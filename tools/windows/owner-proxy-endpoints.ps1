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
 $v=@{path=$path;backup=$saved;existed=$false;sha256='';acl=$null}
 if(Test-Path -LiteralPath $path){
  $item=Get-Item -LiteralPath $path -Force
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 524288){throw 'OWNER_PROXY_LEASE_INVALID'}
  $v.acl=Get-Acl -LiteralPath $path
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
 Set-Acl -LiteralPath $Snapshot.path -AclObject $Snapshot.acl
 if((Get-FileHash -LiteralPath $Snapshot.path -Algorithm SHA256).Hash -cne $Snapshot.sha256){throw 'OWNER_PROXY_ROLLBACK_READBACK_FAILED'}
}
