# Build-only helpers. No enrollment, installation, SSH or service/registry changes.
function Resolve-VeliqInnoCompiler([string]$Compiler='') {
 $candidates=@();if($Compiler){$candidates+=,$Compiler}else{
  $command=Get-Command ISCC.exe -ErrorAction SilentlyContinue;if($command){$candidates+=,$command.Source}
  foreach($base in @(${env:ProgramFiles(x86)},$env:ProgramFiles)){if($base){$candidates+=,(Join-Path $base 'Inno Setup 6\ISCC.exe')}}
 }
 foreach($candidate in $candidates){if(Test-Path -LiteralPath $candidate -PathType Leaf){return (Get-Item -LiteralPath $candidate).FullName}}
 return $null
}
function Assert-VeliqInnoCompiler([string]$Compiler) {
 if(!(Test-Path -LiteralPath $Compiler -PathType Leaf)){throw 'INNO_SETUP_6_4_3_COMPILER_REQUIRED'}
 # The official 6.4.3 build carries no version resource in ISCC.exe (0.0.0.0);
 # its signed uninstaller in the same directory reports ProductVersion 6.4.3.
 $version=(Get-Item -LiteralPath $Compiler).VersionInfo.FileVersion
 # Portable extraction of the signed official 6.4.3 distribution has no
 # uninstaller and carries zero PE versions. Pin the compiler AND its DLL.
 $portable=$false
 $compilerDll=Join-Path (Split-Path -Parent $Compiler) 'ISCmplr.dll'
 if(Test-Path -LiteralPath $compilerDll){
  $portable=(Get-FileHash -LiteralPath $Compiler).Hash -ceq '8A430B74FD1ECEF5651F514A62B5341B0C65E1A53FFE5BA33CC26CF57E67029F' -and
   (Get-FileHash -LiteralPath $compilerDll).Hash -ceq '2C230C3E99BC42215221B2C847356FBBE9EAE33A15A842BE429E94FD26E7C436'
 }
 if(!$portable -and $version -notmatch '^6\.4\.3(\.|$)'){
  $uninstaller=Join-Path (Split-Path -Parent $Compiler) 'unins000.exe'
  if(!(Test-Path -LiteralPath $uninstaller -PathType Leaf) -or ([string](Get-Item -LiteralPath $uninstaller).VersionInfo.ProductVersion).Trim() -notmatch '^6\.4\.3(\.|$)'){throw 'INNO_COMPILER_VERSION_MISMATCH; approved version is 6.4.3'}
  $signature=Get-AuthenticodeSignature -LiteralPath $uninstaller
  if($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch 'Jordan Russell|O=Pyrsys B\.V\.'){throw 'INNO_COMPILER_SIGNATURE_INVALID'}
 }
 # Inno Setup releases are signed by Jordan Russell or, since 2024, his company Pyrsys B.V.
 $signature=Get-AuthenticodeSignature -LiteralPath $Compiler
 if($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch 'Jordan Russell|O=Pyrsys B\.V\.'){throw 'INNO_COMPILER_SIGNATURE_INVALID'}
}
function Assert-VeliqPublicCA([string]$Path) {
 $text=[IO.File]::ReadAllText($Path)
 if($text -match 'PRIVATE KEY' -or ([regex]::Matches($text,'-----BEGIN CERTIFICATE-----')).Count -ne 1){throw 'PUBLIC_CA_REQUIRED'}
 $ca=[Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
 try{
  if($ca.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow -or $ca.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow){throw 'PUBLIC_CA_EXPIRED_OR_NOT_YET_VALID'}
  $basic=@($ca.Extensions|Where-Object {$_.Oid.Value -eq '2.5.29.19'})
  if($basic.Count -ne 1 -or !([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($basic[0],$basic[0].Critical)).CertificateAuthority){throw 'PUBLIC_CA_CONSTRAINT_REQUIRED'}
 }finally{$ca.Dispose()}
}
