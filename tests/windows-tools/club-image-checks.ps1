# Pure image contracts, no services/tasks/registry/enrollment/install operations.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repo 'tools/windows/club-image-common.ps1')
function Check($v,$why){if(!$v){throw $why}}
foreach($n in @('club-image-common','configure-club-image','club-image-boot')){
 $t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repo ('tools/windows/'+$n+'.ps1')),[ref]$t,[ref]$e);Check ($e.Count -eq 0) ('parser '+$n)
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('veliq-image-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory $temp|Out-Null
try{
 Assert-ClubImageClean $temp
 foreach($n in @('identity.json','device.pem','probe.token','club-boot-ready.json')){
  $p=Join-Path $temp $n;Set-Content -LiteralPath $p 'fixture';$errorCode='';try{Assert-ClubImageClean $temp}catch{$errorCode=$_.Exception.Message};Check ($errorCode -like 'CLUB_IMAGE_HAS_RUNTIME_STATE*') 'dirty image accepted';Check (Test-Path $p) 'existing material removed';Remove-Item $p
 }
 $dir=Join-Path $temp 'state/activation-pending/machine/request';New-Item -ItemType Directory -Force $dir|Out-Null;Set-Content (Join-Path $dir 'identity.json') 'fixture'
 $errorCode='';try{Assert-ClubImageClean $temp}catch{$errorCode=$_.Exception.Message};Check ($errorCode -like 'CLUB_IMAGE_HAS_PENDING_PRIVATE_KEY*') 'pending identity accepted'
 $env:SystemRoot='C:\Windows'
 function Get-ScheduledTask { param($TaskName) return $script:fixtureTask }
 $script:fixtureTask=$null;Assert-ClubBootTaskOwnership 'owned'
 $script:fixtureTask=[pscustomobject]@{Actions=@([pscustomobject]@{Execute='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';Arguments='owned'});Principal=[pscustomobject]@{UserId='SYSTEM'}}
 Assert-ClubBootTaskOwnership 'owned'
 $errorCode='';try{Assert-ClubBootTaskOwnership 'foreign'}catch{$errorCode=$_.Exception.Message};Check ($errorCode -eq 'CLUB_FOREIGN_BOOT_TASK_PRESERVED') 'foreign task replaced'
 Write-Output 'PASS clean image/private material/boot flag gates, no deletion, PS parser; SYSTEM task and real freeze NOT executed'
}finally{Remove-Item -LiteralPath $temp -Recurse -Force}
$token=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'tools/windows/Get-ClubStatus.ps1'),[ref]$token,[ref]$errors);Check ($errors.Count -eq 0) 'status parser'
function global:Get-Service { param($Name) return $null }
try{$message=& (Join-Path $repo 'tools/windows/Get-ClubStatus.ps1');Check ($message -eq 'VELIQ SERVICE_STOPPED_OR_ABSENT') 'stopped service shown READY'}finally{Remove-Item function:global:Get-Service}

if($env:OS -eq 'Windows_NT'){
 $dir=Join-Path ([IO.Path]::GetTempPath()) ('veliq-acl-fixture-'+[guid]::NewGuid().ToString('N'))
 try{
  New-Item -ItemType Directory -Path (Join-Path $dir 'tools/windows') -Force|Out-Null
  $file=Join-Path $dir 'tools/windows/boot-fixture.ps1';[IO.File]::WriteAllText($file,'# inert fixture')
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  Protect-ClubPackageTree -Root $dir -OwnerSid $sid
  foreach($p in @($dir,(Join-Path $dir 'tools'),(Split-Path $file),$file)){
   $acl=Get-Acl -LiteralPath $p
   Check ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544') 'future guest owns SYSTEM dependency'
   Check $acl.AreAccessRulesProtected 'SYSTEM dependency inherits writable permissions'
   foreach($ace in $acl.Access){if($ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid){Check (($ace.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -eq 0) 'guest can write SYSTEM dependency'}}
  }
  Write-Output 'PASS native Windows temporary SYSTEM-task dependency ownership/ACL; no scheduled task or installation'
 }finally{if(Test-Path $dir){Remove-Item -LiteralPath $dir -Recurse -Force}}
}else{Write-Output 'SKIP native Windows task dependency ACL (requires Windows admin); parser only'}
