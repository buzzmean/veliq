# Run the real administrator script against in-memory registry provider stubs.
# No real machine policy or service is changed.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$source=Join-Path $PSScriptRoot '../../tools/windows/Set-ClubUpdatePolicy.ps1'
$script:exists=$false;$script:policyAcl=$null;$script:values=@{};$script:writes=0
function Test-Path {param($LiteralPath) if($LiteralPath -cne 'HKLM:\SOFTWARE\VELIQ\ClubUpdates'){throw 'POLICY_TEST_UNEXPECTED_PATH'};return $script:exists}
function Get-Acl {param($LiteralPath) return $script:policyAcl}
function New-Item {param($Path,[switch]$Force) $script:exists=$true}
function Set-Acl {param($LiteralPath,$AclObject) $script:policyAcl=$AclObject}
function New-ItemProperty {param($LiteralPath,$Name,$Value,$PropertyType,[switch]$Force) if($PropertyType -cne 'DWord'){throw 'POLICY_TEST_WRONG_KIND'};$script:values[$Name]=$Value;$script:writes++}
& $source -Enabled $true
if($script:values.Version -ne 1 -or $script:values.AutoInstall -ne 1){throw 'POLICY_ENABLE_FAILED'}
if(!$script:policyAcl.AreAccessRulesProtected -or $script:policyAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544'){throw 'POLICY_OWNER_DACL_INVALID'}
$rules=@($script:policyAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
if($rules.Count -ne 2){throw 'POLICY_UNEXPECTED_PRINCIPALS'}
& $source -Enabled $false
if($script:values.AutoInstall -ne 0){throw 'POLICY_DISABLE_FAILED'}
$script:policyAcl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadKey','Allow'))
$before=$script:writes;$refused=$false
try{& $source -Enabled $true}catch{if($_.Exception.Message -cne 'CLUB_UPDATE_FOREIGN_POLICY_PRESERVED'){throw};$refused=$true}
if(!$refused -or $script:writes -ne $before){throw 'POLICY_FOREIGN_STATE_OVERWRITTEN'}
Write-Output 'PASS real policy script: enable/disable DWORD, protected administrator owner, extra principal refused before mutation; no real registry writes'
