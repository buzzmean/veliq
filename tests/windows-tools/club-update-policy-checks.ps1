# Run the real administrator script against in-memory registry provider stubs.
# No real machine policy or service is changed.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$source=Join-Path $PSScriptRoot '../../tools/windows/Set-ClubUpdatePolicy.ps1'
$global:VeliqClubUpdatePolicyFixture=@{exists=$false;policyAcl=$null;values=@{};writes=0}
function Test-Path {param($LiteralPath) if($LiteralPath -cne 'HKLM:\SOFTWARE\VELIQ\ClubUpdates'){throw 'POLICY_TEST_UNEXPECTED_PATH'};return $global:VeliqClubUpdatePolicyFixture.exists}
function Get-Acl {param($LiteralPath) return $global:VeliqClubUpdatePolicyFixture.policyAcl}
function New-Item {param($Path,[switch]$Force) $global:VeliqClubUpdatePolicyFixture.exists=$true}
function Set-Acl {param($LiteralPath,$AclObject) $global:VeliqClubUpdatePolicyFixture.policyAcl=$AclObject}
function New-ItemProperty {param($LiteralPath,$Name,$Value,$PropertyType,[switch]$Force) if($PropertyType -cne 'DWord'){throw 'POLICY_TEST_WRONG_KIND'};$global:VeliqClubUpdatePolicyFixture.values[$Name]=$Value;$global:VeliqClubUpdatePolicyFixture.writes++}
try{
& $source -Enabled $true
if($global:VeliqClubUpdatePolicyFixture.values.Version -ne 1 -or $global:VeliqClubUpdatePolicyFixture.values.AutoInstall -ne 1){throw 'POLICY_ENABLE_FAILED'}
if(!$global:VeliqClubUpdatePolicyFixture.policyAcl.AreAccessRulesProtected -or $global:VeliqClubUpdatePolicyFixture.policyAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544'){throw 'POLICY_OWNER_DACL_INVALID'}
$rules=@($global:VeliqClubUpdatePolicyFixture.policyAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
if($rules.Count -ne 2){throw 'POLICY_UNEXPECTED_PRINCIPALS'}
& $source -Enabled $false
if($global:VeliqClubUpdatePolicyFixture.values.AutoInstall -ne 0){throw 'POLICY_DISABLE_FAILED'}
$global:VeliqClubUpdatePolicyFixture.policyAcl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadKey','Allow'))
$before=$global:VeliqClubUpdatePolicyFixture.writes;$refused=$false
try{& $source -Enabled $true}catch{if($_.Exception.Message -cne 'CLUB_UPDATE_FOREIGN_POLICY_PRESERVED'){throw};$refused=$true}
if(!$refused -or $global:VeliqClubUpdatePolicyFixture.writes -ne $before){throw 'POLICY_FOREIGN_STATE_OVERWRITTEN'}
Write-Output 'PASS real policy script: enable/disable DWORD, protected administrator owner, extra principal refused before mutation; no real registry writes'

}finally{Remove-Variable -Scope Global -Name VeliqClubUpdatePolicyFixture -ErrorAction SilentlyContinue}
