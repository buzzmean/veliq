$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../tools/windows/owner-proxy-endpoints.ps1')
$base=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$root=Join-Path $base ('veliq-endpoints-fixture-'+[Guid]::NewGuid().ToString('N'))
$state=Join-Path $root 'state';$backup=Join-Path $root 'backup'
New-Item -ItemType Directory -Path $state,$backup|Out-Null
try{
 $manifest=Join-Path $root 'service.json'
 [IO.File]::WriteAllText($manifest,(@{state_directory=$state}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
 $path=Join-Path $state 'browser-owner-proxy.json'
 $lease=@{version=1;owner='fixture-owner';original=@{flags=1;server='';pac='';bypass=''};installed=@{flags=3;server='http=127.0.0.1:32101;https=127.0.0.1:32101';pac='';bypass=''}}
 $raw=$lease|ConvertTo-Json -Depth 4
 [IO.File]::WriteAllText($path,$raw,[Text.UTF8Encoding]::new($false))
 $before=(Get-FileHash -LiteralPath $path).Hash
 $snapshot=Save-VeliqOwnerProxyLease $manifest $backup
 # The official transaction persists this snapshot across PowerShell processes.
 $snapshot=$snapshot|ConvertTo-Json -Depth 5|ConvertFrom-Json
 Remove-Item -LiteralPath $path
 Restore-VeliqOwnerProxyLease $snapshot
 if((Get-FileHash -LiteralPath $path).Hash -cne $before){throw 'LEGACY_LEASE_ROLLBACK_FAILED'}
 $lease.owner='foreign-owner';[IO.File]::WriteAllText($path,($lease|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
 $foreign=(Get-FileHash -LiteralPath $path).Hash
 $refused=$false;try{Restore-VeliqOwnerProxyLease $snapshot}catch{$refused=$_.Exception.Message -eq 'OWNER_PROXY_ROLLBACK_LEASE_CHANGED'}
 if(!$refused -or (Get-FileHash -LiteralPath $path).Hash -cne $foreign){throw 'FOREIGN_LEASE_OVERWRITTEN'}
 [IO.File]::AppendAllText($snapshot.backup,'tamper')
 $refused=$false;try{Restore-VeliqOwnerProxyLease $snapshot}catch{$refused=$_.Exception.Message -eq 'OWNER_PROXY_ROLLBACK_HASH_MISMATCH'}
 if(!$refused){throw 'TAMPERED_LEASE_ACCEPTED'}
 if($env:GITHUB_ACTIONS -eq 'true'){
  $candidate=(Resolve-Path (Join-Path $PSScriptRoot '../../bin/veliq-service.exe')).Path
  $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  [IO.File]::WriteAllText($manifest,(@{state_directory=$state;token_file=(Join-Path $root 'unused.token');owner_sid=$owner}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
  $lease.owner=$owner;[IO.File]::WriteAllText($path,($lease|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
  Invoke-VeliqOwnerEndpointPreparation $candidate $manifest $backup
  # This is what the old GUI's optimize=false does during its graceful close.
  Remove-Item -LiteralPath $path
  $persisted=Get-Content -Raw -LiteralPath (Join-Path $state 'browser-owner-endpoints.json')|ConvertFrom-Json
  if($persisted.primary -cne '127.0.0.1:32101' -or $persisted.owner -cne $owner){throw 'PRE_GUI_ADDRESS_NOT_PRESERVED'}
  $lease.owner='foreign-owner';[IO.File]::WriteAllText($path,($lease|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
  $refused=$false;try{Invoke-VeliqOwnerEndpointPreparation $candidate $manifest $backup}catch{$refused=$_.Exception.Message -eq 'OWNER_PROXY_ENDPOINT_PREPARE_FAILED'}
  if(!$refused -or (Get-Content -Raw -LiteralPath (Join-Path $backup 'endpoint-prepare.stderr')) -notmatch 'OWNER_PROXY_JOURNAL_INVALID'){throw 'NATIVE_FAILURE_EXIT_OR_DIAGNOSTIC_LOST'}
 }
 Write-Host 'PASS owner-proxy update/legacy rollback, foreign-state preservation and tamper checks; no service or network mutation'
}finally{
 $resolved=[IO.Path]::GetFullPath($root)
 if(!$resolved.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notlike 'veliq-endpoints-fixture-*'){throw 'FIXTURE_CLEANUP_SCOPE_INVALID'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
