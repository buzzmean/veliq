$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../tools/windows/reinstall-state.ps1')
function Reject-Install([scriptblock]$Body,[string]$Pattern) {
 $message=$null;try{& $Body|Out-Null}catch{$message=$_.Exception.Message}
 if($null -eq $message -or $message -notlike $Pattern){throw "Expected reinstall rejection ($Pattern), got: $message"}
}
function New-ReinstallCA([string]$Path) {
 # .NET Framework/PS5.1 exposes this provider's KeySize as read-only.
 $rsa=[Security.Cryptography.RSACryptoServiceProvider]::new(2048)
 $cert=$null;$sha=$null
 try {
  $rsa.PersistKeyInCsp=$false
  if($rsa.KeySize -ne 2048 -or $rsa.PersistKeyInCsp){throw 'Fixture RSA must be 2048-bit and non-persistent'}
  $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=VELIQ-REINSTALL-TEST-ONLY',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
  $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign),$true))
  $cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddDays(1))
  [IO.File]::WriteAllText($Path,"-----BEGIN CERTIFICATE-----`n"+[Convert]::ToBase64String($cert.RawData)+"`n-----END CERTIFICATE-----`n",[Text.UTF8Encoding]::new($false))
  $sha=[Security.Cryptography.SHA256]::Create()
  return ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant()
 } finally {if($null -ne $sha){$sha.Dispose()};if($null -ne $cert){$cert.Dispose()};$rsa.Dispose()}
}
function Reject-CorruptCA([scriptblock]$Body) {
 $rejected=$false
 try {& $Body|Out-Null} catch {
  $errorCause=$_.Exception
  while($null -ne $errorCause){if($errorCause -is [Security.Cryptography.CryptographicException]){$rejected=$true};$errorCause=$errorCause.InnerException}
  if(!$rejected){throw}
 }
 if(!$rejected){throw 'Corrupted CA was accepted'}
}
$installScript=Join-Path $PSScriptRoot '../../tools/windows/install.ps1'
# Execute the production CA selection/pin block on every platform. No rewritten
# certificate loader, installer execution, service, ACL or registry mutation here.
$pinBlock=[regex]::Match([IO.File]::ReadAllText($installScript),'(?s)# Pin the already verified public CA.*?(?=\$manifestPath=)')
if(!$pinBlock.Success){throw 'Installer CA pin block not found'}
$pinScript=[scriptblock]::Create($pinBlock.Value)
function Read-InstallCAPin([string]$InstallDirectory) {$manifest=@{};& $pinScript;return $manifest.activation_ca_sha256}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('neexitlag reinstall '+[Guid]::NewGuid().ToString('N'))
try {
 New-Item $temp -ItemType Directory|Out-Null
 $installed=Join-Path $temp 'installed';$source=Join-Path $temp 'bundle'
 New-Item $installed,$source -ItemType Directory|Out-Null
 $owner='S-1-5-21-111111111-222222222-333333333-1234'
 $manifest=@{owner_sid=$owner;control_plane_url='https://fixture.invalid:8443';probe_target='203.0.113.1:40000';tcp_probe_target=''}
 [IO.File]::WriteAllText((Join-Path $installed 'service.json'),($manifest|ConvertTo-Json))
 $sources=@{}
 foreach($name in @('identity.json','device.pem','trust.json')) {
  $sources[$name]=Join-Path $source $name
  [IO.File]::WriteAllText($sources[$name],"fixture $name")
  Copy-Item $sources[$name] $installed
 }
 $sources['ca.pem']=Join-Path $source 'ca.pem'
 $relayCAPin=New-ReinstallCA $sources['ca.pem']
 Copy-Item $sources['ca.pem'] $installed
 if((Read-InstallCAPin $source) -cne $relayCAPin){throw 'Installer fallback CA DER SHA256 mismatch'}
 $caBytes=[IO.File]::ReadAllBytes($sources['ca.pem'])
 try {[IO.File]::WriteAllText($sources['ca.pem'],'fixture ca.pem');Reject-CorruptCA {Read-InstallCAPin $source}}
 finally {[IO.File]::WriteAllBytes($sources['ca.pem'],$caBytes)}
 $sources['cp-ca.pem']=Join-Path $source 'cp-ca.pem'
 $controlCAPin=New-ReinstallCA $sources['cp-ca.pem']
 Copy-Item $sources['cp-ca.pem'] $installed
 if($controlCAPin -eq $relayCAPin -or (Read-InstallCAPin $source) -cne $controlCAPin){throw 'Installer did not pin the distinct control-plane CA'}
 $caBytes=[IO.File]::ReadAllBytes($sources['cp-ca.pem'])
 try {[IO.File]::WriteAllText($sources['cp-ca.pem'],'fixture cp-ca.pem');Reject-CorruptCA {Read-InstallCAPin $source}}
 finally {[IO.File]::WriteAllBytes($sources['cp-ca.pem'],$caBytes)}
 Write-Output 'PASS actual installer X509 CA loading, DER SHA256, cp-ca preference and corrupt CA rejection'
 $arguments=@{Directory=$installed;OwnerSid=$owner;ControlPlaneUrl=$manifest.control_plane_url;ProbeTarget=$manifest.probe_target;Sources=$sources}
 Reject-Install {Assert-ServiceInstallState @arguments} '*explicitly use -Reinstall*'
 $before=(Get-FileHash (Join-Path $installed 'identity.json')).Hash
 [void](Assert-ServiceInstallState @arguments -Reinstall)
 Copy-ServiceCredential $sources['identity.json'] (Join-Path $installed 'identity.json')
 if((Get-FileHash (Join-Path $installed 'identity.json')).Hash -ne $before){throw 'Matching credential changed'}
 [IO.File]::WriteAllText($sources['identity.json'],'different identity')
 Reject-Install {Assert-ServiceInstallState @arguments -Reinstall} '*credential/trust mismatch*'
 if((Get-FileHash (Join-Path $installed 'identity.json')).Hash -ne $before){throw 'Credential replaced by mismatched bundle'}
 Copy-Item (Join-Path $installed 'identity.json') $sources['identity.json'] -Force
 foreach($name in @('ca.pem','cp-ca.pem')) {
  $savedCA=[IO.File]::ReadAllBytes($sources[$name]);$installedCAHash=(Get-FileHash (Join-Path $installed $name)).Hash
  try {[IO.File]::WriteAllText($sources[$name],'corrupted CA');Reject-Install {Assert-ServiceInstallState @arguments -Reinstall} '*credential/trust mismatch*'}
  finally {[IO.File]::WriteAllBytes($sources[$name],$savedCA)}
  if((Get-FileHash (Join-Path $installed $name)).Hash -ne $installedCAHash){throw 'Corrupt CA replaced a preserved certificate'}
 }
 $arguments.OwnerSid='different owner';Reject-Install {Assert-ServiceInstallState @arguments -Reinstall} '*owner_sid mismatch*';$arguments.OwnerSid=$owner
 $arguments.ProbeTarget='203.0.113.2:40000';Reject-Install {Assert-ServiceInstallState @arguments -Reinstall} '*probe_target mismatch*';$arguments.ProbeTarget=$manifest.probe_target
 Write-Output 'PASS explicit reinstall preflight, preserved identity and owner/target/credential mismatch rejection'

 if($env:OS -eq 'Windows_NT') {
  # Actual install/uninstall scripts and filesystem/ACL operations. SCM/task
  # commands and policy cleanup are isolated stubs; no real service/task/driver.
  $global:neexitlagReinstallFixture=@{serviceCreated=$false;creates=0;deletes=0;task=$null;binaryPath=''}
  $global:neexitlagReinstallFixture.mockService=[pscustomobject]@{Status='Running';Disposed=$false}
  $global:neexitlagReinstallFixture.mockService|Add-Member ScriptMethod WaitForStatus {param($status,$timeout) $this.Status=$status}
  $global:neexitlagReinstallFixture.mockService|Add-Member ScriptMethod Dispose {$this.Disposed=$true}
  function Get-Service {param([string]$Name) if($Name -ne 'VELIQ'){throw 'Unexpected SCM name'};if($global:neexitlagReinstallFixture.serviceCreated){return $global:neexitlagReinstallFixture.mockService}}
  function New-Service {param($Name,$BinaryPathName,$DisplayName,$StartupType) if($Name -ne 'VELIQ' -or $DisplayName -ne 'VELIQ Routing Service'){throw 'SCM compatibility/display-name mismatch'};$global:neexitlagReinstallFixture.creates++;$global:neexitlagReinstallFixture.serviceCreated=$true;$global:neexitlagReinstallFixture.binaryPath=$BinaryPathName;$global:neexitlagReinstallFixture.mockService.Status='Running';$global:neexitlagReinstallFixture.mockService.Disposed=$false}
  function Set-Service {param($Name,$StartupType) if($Name -ne 'VELIQ' -or $StartupType -ne 'Automatic'){throw 'Unexpected SCM startup mode'}}
  function Get-CimInstance {param($ClassName,$Filter,$OperationTimeoutSec) if($ClassName -ne 'Win32_Service' -or $Filter -ne "Name='VELIQ'"){throw 'Unexpected SCM query'};return [pscustomobject]@{StartMode='Auto';PathName=$global:neexitlagReinstallFixture.binaryPath}}
  function Start-Service {param($Name) if($Name -ne 'VELIQ'){throw 'Unexpected SCM start'}}
  function Stop-Service {param($Name) if($Name -ne 'VELIQ'){throw 'Unexpected SCM stop'};$global:neexitlagReinstallFixture.mockService.Status='Stopped'}
  function sc.exe {if($args[0] -eq 'delete'){$global:neexitlagReinstallFixture.deletes++;$global:neexitlagReinstallFixture.serviceCreated=$false};$global:LASTEXITCODE=0}
  function Get-ScheduledTask {param($TaskName,$ErrorAction) if($TaskName -ne 'VELIQ-BrowserPolicyWatchdog'){throw 'Unexpected task'};return $global:neexitlagReinstallFixture.task}
  function New-ScheduledTaskAction {param($Execute,$Argument)return [pscustomobject]@{Execute=$Execute;Arguments=$Argument}}
  function New-ScheduledTaskTrigger {param([switch]$AtStartup,[switch]$AtLogOn)return [pscustomobject]@{Boot=[bool]$AtStartup;Logon=[bool]$AtLogOn}}
  function New-ScheduledTaskSettingsSet {param($ExecutionTimeLimit,$RestartCount,$RestartInterval,[switch]$StartWhenAvailable,$MultipleInstances)return [pscustomobject]@{MultipleInstances=$MultipleInstances}}
  function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel)if($UserId -ne 'SYSTEM'){throw 'Unexpected task principal'};return $UserId}
  function Register-ScheduledTask {param($TaskName,$Description,$Action,$Trigger,$Settings,$Principal,[switch]$Force)$global:neexitlagReinstallFixture.task=[pscustomobject]@{Description=$Description;Actions=@($Action)}}
  function Start-ScheduledTask {param($TaskName)}
  function Stop-ScheduledTask {param($TaskName,$ErrorAction)}
  function Unregister-ScheduledTask {param($TaskName,[switch]$Confirm,$ErrorAction)$global:neexitlagReinstallFixture.task=$null}
  $target=Join-Path $temp 'actual install';$driver=Join-Path $temp 'driver'
  New-Item $driver -ItemType Directory|Out-Null
  foreach($name in @('WinDivert.dll','WinDivert64.sys')){[IO.File]::WriteAllText((Join-Path $driver $name),"fixture $name")}
  # A tiny locally compiled executable accepts only uninstall's cleanup command.
  # It never loads VELIQ, opens sockets or touches browser policy.
  $stub=Join-Path $temp 'service.go';$exe=Join-Path $temp 'service.exe'
  [IO.File]::WriteAllText($stub,'package main; import "os"; func main(){if len(os.Args)!=4 || os.Args[1]!="-cleanup-browser-policy" || os.Args[2]!="-config" {os.Exit(97)}; if _,e:=os.Stat(os.Args[3]);e!=nil {os.Exit(98)}}',[Text.UTF8Encoding]::new($false))
  & go build -o $exe $stub
  if($LASTEXITCODE -ne 0){throw 'Reinstall cleanup fixture build failed'}
  $params=@{NativeTcpFirewall=$false;ServiceExecutable=$exe;OwnerSid=$owner;DeviceDirectory=$source;TrustDirectory=$source;DriverDirectory=$driver;DllSha256=(Get-FileHash (Join-Path $driver 'WinDivert.dll')).Hash;DriverSha256=(Get-FileHash (Join-Path $driver 'WinDivert64.sys')).Hash;ControlPlaneUrl=$manifest.control_plane_url;ProbeTarget=$manifest.probe_target;InstallDirectory=$target}
  $badTrust=Join-Path $temp 'bad trust';New-Item $badTrust -ItemType Directory|Out-Null
  Copy-Item $sources['ca.pem'] $badTrust
  Copy-Item $sources['trust.json'] $badTrust
  [IO.File]::WriteAllText((Join-Path $badTrust 'cp-ca.pem'),'corrupt CA')
  $badParams=$params.Clone();$badParams.TrustDirectory=$badTrust;$badParams.InstallDirectory=Join-Path $temp 'rejected install'
  Reject-CorruptCA {& $installScript @badParams}
  if($global:neexitlagReinstallFixture.creates -ne 0 -or (Test-Path (Join-Path $badParams.InstallDirectory 'service.json'))){throw 'Corrupt CA reached service creation/manifest publication'}
  & $installScript @params
  if((Get-Content -LiteralPath (Join-Path $target 'service.json') -Raw|ConvertFrom-Json).activation_ca_sha256 -cne $controlCAPin){throw 'Installed CA DER SHA256 mismatch'}
  $state=Join-Path $target 'state/profile-fixture.json';[IO.File]::WriteAllText($state,'preserve profile/settings state')
  $protected=@('identity.json','device.pem','trust.json','ca.pem','cp-ca.pem','ipc.token','state/profile-fixture.json')
  $hashes=@{};foreach($name in $protected){$hashes[$name]=(Get-FileHash (Join-Path $target $name)).Hash}
  & (Join-Path $PSScriptRoot '../../tools/windows/uninstall.ps1') -InstallDirectory $target
  if($global:neexitlagReinstallFixture.deletes -ne 1 -or !$global:neexitlagReinstallFixture.mockService.Disposed -or !(Test-Path $target)){throw 'Uninstall did not preserve files/release SCM handle'}
  Reject-Install {& $installScript @params} '*explicitly use -Reinstall*'
  [IO.File]::AppendAllText($exe,'upgraded executable fixture marker')
  & $installScript @params -Reinstall
  if($global:neexitlagReinstallFixture.creates -ne 2 -or (Get-FileHash (Join-Path $target 'veliq-service.exe')).Hash -ne (Get-FileHash $exe).Hash){throw 'Explicit upgrade did not install new executable'}
  if((Get-Content -LiteralPath (Join-Path $target 'service.json') -Raw|ConvertFrom-Json).activation_ca_sha256 -cne $controlCAPin){throw 'Reinstall changed CA DER SHA256'}
  foreach($name in $protected){if((Get-FileHash (Join-Path $target $name)).Hash -ne $hashes[$name]){throw "Reinstall changed preserved $name"}}
  foreach($item in @((Get-Item $target)) + @(Get-ChildItem $target -Recurse -Force)) {
   $acl=Get-Acl $item.FullName
   if(!$acl.AreAccessRulesProtected){throw 'Service path retained inherited access'}
   foreach($rule in $acl.Access) {
    $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if($sid -notin @('S-1-5-18','S-1-5-32-544',$owner)){throw "Unexpected access grant $sid"}
    if($sid -eq $owner) {
     if($item.FullName -ne $target -and $item.FullName -ne (Join-Path $target 'ipc.token') -and $item.FullName -ne (Join-Path $target 'veliq-service.exe') -and $item.FullName -ne (Join-Path (Join-Path $target 'state') 'browser-recovery-guard.json')){throw 'GUI owner gained credential/state access'}
     if($rule.InheritanceFlags -ne 'None' -or ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write)){throw 'GUI access became writable/inheritable'}
    }
   }
  }
  # Exercise only the updater's pure SCM-target validator and actual executable
  # ACL operation. No production SCM/IPC update is invoked by these filesystem tests.
  $parseErrors=$null;$tokens=$null
  $updateAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../../tools/windows/update-service.ps1'),[ref]$tokens,[ref]$parseErrors)
  if($parseErrors.Count){throw 'Updater did not parse'}
  foreach($name in @('Assert-ServiceUpdateScmTarget','Set-BinaryOwnerReadExecute')){
   $definition=$updateAst.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object{$_.Name -eq $name}|Select-Object -First 1
   if($null -eq $definition){throw "Missing updater validator: $name"}
   . ([scriptblock]::Create($definition.Extent.Text))
  }
  $binary=Join-Path $target 'veliq-service.exe'
  Assert-ServiceUpdateScmTarget ('"'+$binary+'" -config "'+(Join-Path $target 'service.json')+'"') $binary
  Reject-Install {Assert-ServiceUpdateScmTarget '"C:\Wrong\service.exe"' $binary} '*SCM executable does not match*'
  Reject-Install {Assert-ServiceUpdateScmTarget $binary $binary} '*SCM executable does not match*'
  Set-BinaryOwnerReadExecute $binary $owner
  foreach($rule in (Get-Acl -LiteralPath $binary).Access){
   $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
   if($sid -eq $owner -and (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -or !($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ExecuteFile))){throw 'Updater owner binary rights must be RX only'}
   if($sid -notin @($owner,'S-1-5-18','S-1-5-32-544')){throw 'Updater broadened executable access'}
  }
  foreach($name in $protected){if((Get-FileHash (Join-Path $target $name)).Hash -ne $hashes[$name]){throw 'Executable ACL update modified preserved credentials/state'}}
  Write-Output 'PASS updater SCM target refusal and owner executable RX without credential/state changes'
  Write-Output 'PASS actual Windows install/uninstall/reinstall with mocked SCM: binary updated, credentials/token/state preserved, restrictive ACLs'
 }
}finally{Remove-Item $temp -Recurse -Force;Remove-Variable neexitlagReinstallFixture -Scope Global -ErrorAction SilentlyContinue}
