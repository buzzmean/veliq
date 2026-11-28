# Explicit machine administrator opt-in. No service/GUI restart or Setup launch.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][bool]$Enabled)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if(![Environment]::Is64BitProcess){throw 'CLUB_UPDATE_POLICY_REQUIRES_64BIT_HOST'}
. (Join-Path $PSScriptRoot 'common.ps1');Assert-Administrator
$path='HKLM:\SOFTWARE\VELIQ\ClubUpdates'
if(Test-Path -LiteralPath $path){
 $existing=Get-Acl -LiteralPath $path
 $owner=$existing.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if($owner -notin @('S-1-5-18','S-1-5-32-544') -or !$existing.AreAccessRulesProtected){throw 'CLUB_UPDATE_FOREIGN_POLICY_PRESERVED'}
 $rules=@($existing.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
 if($rules.Count -ne 2){throw 'CLUB_UPDATE_FOREIGN_POLICY_PRESERVED'}
 $seen=@{}
 foreach($rule in $rules){
  $sid=$rule.IdentityReference.Value
  if($sid -notin @('S-1-5-18','S-1-5-32-544') -or $seen.ContainsKey($sid) -or $rule.AccessControlType -ne 'Allow' -or $rule.RegistryRights -ne 'FullControl'){throw 'CLUB_UPDATE_FOREIGN_POLICY_PRESERVED'}
  $seen[$sid]=$true
 }
}
$null=New-Item -Path $path -Force
$acl=[Security.AccessControl.RegistrySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
foreach($sid in @('S-1-5-18','S-1-5-32-544')){
 $acl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow'))
}
Set-Acl -LiteralPath $path -AclObject $acl
# Disarm before schema changes; publish the enabled bit last.
$null=New-ItemProperty -LiteralPath $path -Name AutoInstall -Value 0 -PropertyType DWord -Force
$null=New-ItemProperty -LiteralPath $path -Name Version -Value 1 -PropertyType DWord -Force
if($Enabled){$null=New-ItemProperty -LiteralPath $path -Name AutoInstall -Value 1 -PropertyType DWord -Force}
Write-Output ('CLUB_BACKGROUND_UPDATES_'+$(if($Enabled){'ENABLED'}else{'DISABLED'})+'; applies on next check; no processes restarted')
