[CmdletBinding()]
param([string]$Destination=(Join-Path $PSScriptRoot '..\..\.e2e\windivert'))
$ErrorActionPreference='Stop'
# Official upstream release, downloaded and hashed over verified HTTPS during preparation.
$uri='https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'
$archiveHash='63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15'
$dllHash='c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'
$sysHash='8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'
if(Test-Path $Destination){throw 'Destination already exists; refusing to overwrite driver files.'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('neexitlag-windivert-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $temp|Out-Null
try {
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $zip=Join-Path $temp 'official.zip'
 Invoke-WebRequest -Uri $uri -OutFile $zip -UseBasicParsing
 if((Get-FileHash $zip -Algorithm SHA256).Hash -ne $archiveHash){throw 'Official archive SHA256 mismatch; aborting.'}
 Expand-Archive $zip (Join-Path $temp 'unpacked')
 $source=Join-Path $temp 'unpacked\WinDivert-2.2.2-A\x64'
 foreach($entry in @(@('WinDivert.dll',$dllHash),@('WinDivert64.sys',$sysHash))){if((Get-FileHash (Join-Path $source $entry[0]) -Algorithm SHA256).Hash -ne $entry[1]){throw "Pinned file mismatch: $($entry[0])"}}
 if((Get-AuthenticodeSignature (Join-Path $source 'WinDivert64.sys')).Status -ne 'Valid'){throw 'Kernel driver signature is not trusted by this Windows installation.'}
 New-Item -ItemType Directory $Destination|Out-Null
 Copy-Item (Join-Path $source 'WinDivert.dll') $Destination
 Copy-Item (Join-Path $source 'WinDivert64.sys') $Destination
 Copy-Item (Join-Path $PSScriptRoot '..\..\third_party\licenses\WinDivert-LICENSE.txt') (Join-Path $Destination 'WinDivert-LICENSE.txt')
 'Unmodified WinDivert 2.2.2. LGPLv3 distribution; replaceable DLL. Corresponding source/build: https://github.com/basil00/WinDivert/tree/v2.2.2' | Set-Content (Join-Path $Destination 'SOURCE.txt') -Encoding UTF8
 @{version='2.2.2-A';source=$uri;archive_sha256=$archiveHash;dll_sha256=$dllHash;driver_sha256=$sysHash}|ConvertTo-Json|ForEach-Object {[IO.File]::WriteAllText((Join-Path $Destination 'pins.json'),$_,(New-Object Text.UTF8Encoding $false))} # no BOM: Go tests decode pins.json with encoding/json
 Write-Host 'WinDivert 2.2.2-A x64 ready. DLL is unsigned and SHA256-pinned; SYS is signed and pinned.'
} finally {Remove-Item $temp -Recurse -Force}
