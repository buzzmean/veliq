# Pure build preflight: no compiler install/build/service/registry/network calls.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repo 'installer\build-support.ps1')
function Check($v,$m){if(!$v){throw $m}}
foreach($name in @('installer/build-support.ps1','installer/build.ps1','tools/windows/build-setup.ps1')){
 $t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $name),[ref]$t,[ref]$e);Check ($e.Count -eq 0) ('Parser '+$name)
}
$root=Join-Path ([IO.Path]::GetTempPath()) ('veliq-build-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory $root|Out-Null
try{
 $rsa=[Security.Cryptography.RSA]::Create();$rsa.KeySize=2048
 $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=VELIQ-FIXTURE',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
 $cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddDays(1))
 $path=Join-Path $root 'ca.pem';[IO.File]::WriteAllText($path,"-----BEGIN CERTIFICATE-----`n"+[Convert]::ToBase64String($cert.RawData)+"`n-----END CERTIFICATE-----")
 Assert-VeliqPublicCA $path
 [IO.File]::AppendAllText($path,"`n-----BEGIN PRIVATE KEY-----")
 $reason='';try{Assert-VeliqPublicCA $path}catch{$reason=$_.Exception.Message};Check ($reason -eq 'PUBLIC_CA_REQUIRED') 'private material accepted'
 $build=Get-Content -Raw (Join-Path $repo 'tools\windows\build-setup.ps1')
 Check ($build.Contains('Initialize-ActivationNuGetSource') -and $build.Contains('--list-sdks')) 'SDK/feed preflight missing'
 Check ($build.Contains('--version 6.4.3') -and $build.Contains('Assert-VeliqInnoCompiler')) 'compiler version/signature preflight missing'
 Check ($build.Contains('BUILD_EXPECTED_COMMIT_MISMATCH') -and $build.Contains('BUILD_TRACKED_CHANGES_PRESENT')) 'build source not pinned'
 Write-Output 'PASS Setup preflight: public CA constraints/private rejection, PS parser, SDK/feed/compiler/version gates; no Inno/Windows installation run'
}finally{if($null -ne $cert){$cert.Dispose()};if($null -ne $rsa){$rsa.Dispose()};Remove-Item -LiteralPath $root -Recurse -Force}
