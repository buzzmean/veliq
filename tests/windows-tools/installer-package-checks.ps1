# Contract validation only, no install, policy, registry, service or network.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../installer/package-contract.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('veliq-package-fixture-'+[guid]::NewGuid().ToString('N'))
function Get-FileHash {param([string]$LiteralPath,[string]$Algorithm='SHA256')
 if($LiteralPath.EndsWith('WinDivert.dll')){return [pscustomobject]@{Hash='c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2'}}
 if($LiteralPath.EndsWith('WinDivert64.sys')){return [pscustomobject]@{Hash='8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'}}
 Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm
}
try{
 $names=@('service/veliq-service.exe','gui/VELIQ.exe','driver/WinDivert.dll','driver/WinDivert64.sys','driver/pins.json','public/ca.pem','public/release.json','installer/install-package.ps1','installer/package-contract.ps1','installer/install-safety.ps1')
 foreach($name in $names){$p=Join-Path $root $name;[void][IO.Directory]::CreateDirectory((Split-Path $p));[IO.File]::WriteAllText($p,'fixture')}
 $rsa=[Security.Cryptography.RSACryptoServiceProvider]::new(2048);$rsa.PersistKeyInCsp=$false
 $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=VELIQ-CI-ONLY',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddDays(1))
 $pem='-----BEGIN CERTIFICATE-----'+"`n"+[Convert]::ToBase64String($cert.RawData)+"`n"+'-----END CERTIFICATE-----'
 [IO.File]::WriteAllText((Join-Path $root 'public/ca.pem'),$pem)
 $sha=[Security.Cryptography.SHA256]::Create();try{$pin=([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose();$cert.Dispose();$rsa.Dispose()}
 @{control_plane_url='https://127.0.0.1:1';ca_der_sha256=$pin;fixture=$false}|ConvertTo-Json|Set-Content (Join-Path $root 'public/release.json')
 @{dll_sha256='c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2';driver_sha256='8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'}|ConvertTo-Json|Set-Content (Join-Path $root 'driver/pins.json')
 $files=@($names|ForEach-Object{@{path=$_;sha256=(Get-FileHash -LiteralPath (Join-Path $root $_)).Hash.ToLowerInvariant()}})
 $manifest=@{product='VELIQ';commit=('a'*40);files=$files};$manifest|ConvertTo-Json -Depth 5|Set-Content (Join-Path $root 'package.json')
 Assert-VeliqPackage $root
 [IO.File]::WriteAllText((Join-Path $root 'unins000.exe'),'inno-generated')
 Assert-VeliqPackage $root
 [IO.File]::AppendAllText((Join-Path $root 'gui/VELIQ.exe'),'tampered')
 $failed=$false;try{Assert-VeliqPackage $root}catch{$failed=$_.Exception.Message -eq 'INSTALL_PACKAGE_HASH_MISMATCH'}
 if(!$failed){throw 'tampered GUI accepted'}
 [IO.File]::WriteAllText((Join-Path $root 'gui/VELIQ.exe'),'fixture')
 $files[0].path='../outside';$manifest|ConvertTo-Json -Depth 5|Set-Content (Join-Path $root 'package.json')
 $failed=$false;try{Assert-VeliqPackage $root}catch{$failed=$true};if(!$failed){throw 'missing required/traversal accepted'}
 Write-Host 'PASS isolated package integrity/tamper/path contracts; driver hashes mocked; no installation'
}finally{Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue;Remove-Item Function:Get-FileHash -ErrorAction SilentlyContinue}
