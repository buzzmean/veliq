function Assert-VeliqPackage([string]$Root,[switch]$ForPackaging){
 $manifest=Get-Content -Raw -LiteralPath (Join-Path $Root 'package.json')|ConvertFrom-Json
 if($manifest.product -ne 'VELIQ' -or $manifest.commit -notmatch '^[0-9a-f]{40}$' -or @($manifest.files).Count -gt 128){throw 'INSTALL_PACKAGE_INVALID'}
 $required=@('service/veliq-service.exe','gui/VELIQ.exe','driver/WinDivert.dll','driver/WinDivert64.sys','driver/pins.json','public/ca.pem','public/release.json','installer/install-package.ps1','installer/package-contract.ps1','installer/install-safety.ps1','installer/install-scope.ps1','installer/transaction.ps1')
 $names=@($manifest.files|ForEach-Object {([string]$_.path).Replace('\','/').ToLowerInvariant()})
 foreach($name in $names){
  if($name -match '(^|/)(identity\.json|device\.pem|ipc\.token|admin\.token|activation-code\.json.*)$' -or $name -match '\.(key|pfx|p12)$'){throw 'INSTALL_SECRET_FILE_REJECTED'}
 }
 $prefix=[IO.Path]::GetFullPath($Root)+[IO.Path]::DirectorySeparatorChar
 $covered=@(Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object { $_.FullName.Substring($prefix.Length) -notmatch '^(package\.json|install-(result|success)\.json|unins[0-9]{3}\.(exe|dat|msg)|VELIQ\.exe|is-[A-Za-z0-9]+\.tmp)$' })
 if(@($names|Select-Object -Unique).Count -ne $names.Count -or $covered.Count -ne $names.Count){throw 'INSTALL_PACKAGE_COVERAGE_INVALID'}
 foreach($name in $required){if($name -notin $names){throw 'INSTALL_PACKAGE_REQUIRED_FILE_MISSING'}}
 $full=[IO.Path]::GetFullPath($Root)+[IO.Path]::DirectorySeparatorChar
 foreach($f in $manifest.files){
  $path=[IO.Path]::GetFullPath((Join-Path $Root $f.path))
  if(!$path.StartsWith($full,[StringComparison]::OrdinalIgnoreCase) -or [string]$f.path -match '(^|[/\\])\.\.([/\\]|$)' -or $f.sha256 -notmatch '^[0-9a-f]{64}$'){throw 'INSTALL_PACKAGE_PATH_INVALID'}
  if((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'INSTALL_PACKAGE_REPARSE_POINT'}
  if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $f.sha256){throw 'INSTALL_PACKAGE_HASH_MISMATCH'}
 }
 $pins=Get-Content -Raw -LiteralPath (Join-Path $Root 'driver\pins.json')|ConvertFrom-Json
 if($pins.dll_sha256 -ne 'c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2' -or $pins.driver_sha256 -ne '8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2'){throw 'INSTALL_DRIVER_VERSION_UNAPPROVED'}
 foreach($pair in @(@('WinDivert.dll',$pins.dll_sha256),@('WinDivert64.sys',$pins.driver_sha256))){if((Get-FileHash -LiteralPath (Join-Path $Root ('driver\'+$pair[0])) -Algorithm SHA256).Hash -ine $pair[1]){throw 'INSTALL_DRIVER_HASH_MISMATCH'}}
 $config=Get-Content -Raw -LiteralPath (Join-Path $Root 'public\release.json')|ConvertFrom-Json
 if(!$ForPackaging -and $config.PSObject.Properties['fixture'] -and $config.fixture){throw 'INSTALL_FIXTURE_NOT_DISTRIBUTABLE'}
 if([string]$config.control_plane_url -notmatch '^https://[^/]+/?$'){throw 'INSTALL_HTTPS_REQUIRED'}
 $ca=[Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $Root 'public\ca.pem'))
 $hash=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($hash.ComputeHash($ca.RawData))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose();$ca.Dispose()}
 if($actual -cne $config.ca_der_sha256){throw 'INSTALL_CA_PIN_MISMATCH'}
}
