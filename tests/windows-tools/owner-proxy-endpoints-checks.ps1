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
 Write-Host 'PASS owner-proxy update/legacy rollback, foreign-state preservation and tamper checks; no service or network mutation'
}finally{
 $resolved=[IO.Path]::GetFullPath($root)
 if(!$resolved.StartsWith($base,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notlike 'veliq-endpoints-fixture-*'){throw 'FIXTURE_CLEANUP_SCOPE_INVALID'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
