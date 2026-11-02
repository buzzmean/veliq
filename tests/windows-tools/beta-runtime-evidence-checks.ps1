$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$root=Join-Path ([IO.Path]::GetTempPath()) ('veliq-runtime-evidence-'+[Guid]::NewGuid().ToString('N'))
New-Item $root -ItemType Directory|Out-Null
try{
 Copy-Item (Join-Path $repo 'tools/windows/Get-BetaRuntimeEvidence.ps1') $root
 $common=@'
function Invoke-ServiceIPCOnce([string]$Method){
 if($Method -cne 'browser.native.status'){throw 'Unexpected IPC method'}
 return ('{"state":"AUTHORITY_REQUEST_OBSERVED","reason":"private-secret-value","capture_ready":true,"optimizing":true,"identity":"private-secret-value","records":[{"domain":"private-secret-value"}],"authority_transport":{"state":"AUTHORITY_REQUEST_OBSERVED","system_proxy_applied":true,"profiles":[{"profile_id":"chrome","requests":3,"exchanges":2}]}}'|ConvertFrom-Json)
}
'@
 $snapshot=@'
param($Manifest,$PCId)
[pscustomobject]@{source_commit=('a'*40);service_sha256=('b'*64);gui_sha256=('c'*64);secret='private-secret-value'}
'@
 [IO.File]::WriteAllText((Join-Path $root 'common.ps1'),$common,[Text.UTF8Encoding]::new($false))
 [IO.File]::WriteAllText((Join-Path $root 'Get-BetaSnapshot.ps1'),$snapshot,[Text.UTF8Encoding]::new($false))
 $manifest=[ordered]@{source_commit=('a'*40);files=@()}
 foreach($name in @('common.ps1','Get-BetaSnapshot.ps1')){$manifest.files+=@{path=$name;sha256=(Get-FileHash (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant()}}
 [IO.File]::WriteAllText((Join-Path $root 'candidate.json'),($manifest|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
 $script=Join-Path $root 'Get-BetaRuntimeEvidence.ps1';$output=Join-Path $root 'runtime.json';$candidate=Join-Path $root 'candidate.json'
 & $script -Manifest $candidate -PCId PC01 -Stage Enabled -OutputPath $output
 $raw=[IO.File]::ReadAllBytes($output)
 if($raw.Length -gt 2 -and $raw[0] -eq 239 -and $raw[1] -eq 187 -and $raw[2] -eq 191){throw 'Runtime JSON has BOM'}
 $text=[Text.Encoding]::UTF8.GetString($raw);$data=$text|ConvertFrom-Json
 if($text.Contains('private-secret-value') -or $data.reason -cne 'UNKNOWN' -or $data.authority.profiles[0].exchanges -ne 2 -or !$data.authority.system_proxy_applied){throw 'Runtime whitelist or proof mapping failed'}
 $before=(Get-FileHash $output -Algorithm SHA256).Hash
 $refused=$false;try{& $script -Manifest $candidate -PCId PC01 -Stage AfterOff -OutputPath $output}catch{$refused=$true}
 if(!$refused -or (Get-FileHash $output -Algorithm SHA256).Hash -cne $before){throw 'Runtime evidence overwritten'}
 Add-Content -LiteralPath (Join-Path $root 'common.ps1') -Value '# changed'
 $refused=$false;try{& $script -Manifest $candidate -PCId PC01 -Stage Enabled -OutputPath (Join-Path $root 'changed.json')}catch{$refused=$true}
 if(!$refused -or (Test-Path (Join-Path $root 'changed.json'))){throw 'Changed helper accepted'}
 Write-Output 'BETA_RUNTIME_EVIDENCE_CHECKS_PASS; no live service or credentials used'
}finally{Remove-Item $root -Recurse -Force}
