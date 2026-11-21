$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../../tools/windows/native-tcp-firewall.ps1')
. (Join-Path $PSScriptRoot '../../platform/windows/native_firewall_probe.ps1')
$script:rule=$null;$script:created=0;$script:removed=0;$script:databaseError=$false;$script:denyLocal=$false
function Get-NetFirewallRule {param($PolicyStore,$Name,$ErrorAction) if($script:databaseError){throw 'fixture API failure'};if($null -ne $script:rule){$script:rule}}
function Get-NetFirewallApplicationFilter {param($AssociatedNetFirewallRule,$ErrorAction) [pscustomobject]@{Program=$AssociatedNetFirewallRule.Program}}
function Get-NetFirewallPortFilter {param($AssociatedNetFirewallRule,$ErrorAction) [pscustomobject]@{Protocol='TCP';LocalPort='Any';RemotePort='Any'}}
function Get-NetFirewallProfile {param($PolicyStore,$ErrorAction) [pscustomobject]@{Enabled='True';AllowInboundRules='True';AllowLocalFirewallRules=(!$script:denyLocal).ToString()}}
function New-NetFirewallRule {param($PolicyStore,$Name,$DisplayName,$Group,$Description,$Program,$Protocol,$Direction,$Action,$Enabled,$Profile,$EdgeTraversalPolicy,$ErrorAction)
 if($PolicyStore -ne 'PersistentStore' -or $Protocol -ne 'TCP'){throw 'wrong scope'}
 $script:created++;$script:rule=[pscustomobject]@{Name=$Name;Group=$Group;Description=$Description;Program=$Program;Direction=$Direction;Action=$Action;Enabled=$Enabled;Profile=$Profile;EdgeTraversalPolicy=$EdgeTraversalPolicy}
}
function Remove-NetFirewallRule {param($PolicyStore,$Name,$ErrorAction) if($Name -ne 'VELIQ-native-tcp-v1' -or $PolicyStore -ne 'PersistentStore'){throw 'foreign removal'};$script:removed++;$script:rule=$null}
function Assert-Check([bool]$Value,[string]$Message){if(!$Value){throw $Message}}
function Reject-Check([scriptblock]$Action,[string]$Pattern){try{& $Action;throw 'UNEXPECTED_SUCCESS'}catch{if($_.Exception.Message -notlike $Pattern){throw}}}
$root=Join-Path ([IO.Path]::GetTempPath()) ('veliq-fw-'+[Guid]::NewGuid().ToString('N'))
try{
 New-Item -ItemType Directory -Path $root|Out-Null
 $binary=Join-Path $root 'veliq-service.exe';[IO.File]::WriteAllText($binary,'fixture, never executed')
 Assert-Check ((Get-VeliqNativeFirewallSnapshot $binary).state -eq 'MISSING') 'missing rule not observed'
 Assert-Check (Add-NativeTcpFirewallAdmission $binary) 'fresh rule not created'
 $snapshot=Get-VeliqNativeFirewallSnapshot $binary
 Assert-Check ($snapshot.state -eq 'APPLIED' -and $snapshot.effective -and $snapshot.program_matches) 'actual effective app scope not observed'
 Assert-Check (!(Add-NativeTcpFirewallAdmission $binary)) 'idempotent setup duplicated rule'
 Assert-Check ($script:created -eq 1) 'more than one rule'
 $script:rule.Program='C:\foreign.exe'
 Assert-Check ((Get-VeliqNativeFirewallSnapshot $binary).state -eq 'SCOPE_MISMATCH') 'wrong program reported applied'
 Reject-Check {Add-NativeTcpFirewallAdmission $binary} '*SCOPE_CHANGED*'
 Reject-Check {Remove-NativeTcpFirewallAdmission $binary} '*SCOPE_CHANGED*'
 Assert-Check ($script:removed -eq 0) 'foreign scope removed'
 $script:rule.Program=$binary;$script:rule.Description='foreign'
 Assert-Check ((Get-VeliqNativeFirewallSnapshot $binary).state -eq 'FOREIGN_RULE') 'foreign rule reported applied'
 Reject-Check {Add-NativeTcpFirewallAdmission $binary} '*FOREIGN_RULE*'
 Reject-Check {Remove-NativeTcpFirewallAdmission $binary} '*FOREIGN_RULE*'
 $script:rule.Description='VELIQ_NATIVE_TCP_REFLECTION_V1'
 Remove-NativeTcpFirewallAdmission $binary
 Assert-Check ($script:removed -eq 1) 'owned rollback not removed'
 $script:databaseError=$true
 Reject-Check {Add-NativeTcpFirewallAdmission $binary} '*fixture API failure*'
 Reject-Check {Get-VeliqNativeFirewallSnapshot $binary} '*fixture API failure*'
 Assert-Check ($script:created -eq 1) 'API failure was interpreted as no rule'
 $script:databaseError=$false;$script:denyLocal=$true
 Reject-Check {Add-NativeTcpFirewallAdmission $binary} '*FORBIDDEN_BY_POLICY*'
 Assert-Check ($script:removed -eq 2 -and $null -eq $script:rule) 'blocked new rule left behind'
 $script:denyLocal=$false
 Assert-Check (Add-NativeTcpFirewallAdmission $binary) 'retry after policy recovery failed'
 $script:denyLocal=$true
 Assert-Check ((Get-VeliqNativeFirewallSnapshot $binary).state -eq 'LOCAL_RULES_FORBIDDEN_BY_POLICY') 'GPO denial reported applied'
 Reject-Check {Add-NativeTcpFirewallAdmission $binary} '*FORBIDDEN_BY_POLICY*'
 Assert-Check ($null -ne $script:rule -and $script:removed -eq 2) 'existing rule removed on failed idempotent check'
 $script:denyLocal=$false;Remove-NativeTcpFirewallAdmission $binary
 $other=Join-Path $root 'foreign.exe';[IO.File]::WriteAllText($other,'fixture')
 Reject-Check {Add-NativeTcpFirewallAdmission $other} '*EXECUTABLE_INVALID*'
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../../tools/windows/update-service.ps1'),[ref]$tokens,[ref]$errors)
 Assert-Check ($errors.Count -eq 0) 'updater parse errors'
 $switch=@($ast.ParamBlock.Parameters|Where-Object {$_.Name.VariablePath.UserPath -eq 'NativeTcpFirewall'})
 Assert-Check ($switch.Count -eq 1 -and $switch[0].DefaultValue.Extent.Text -eq '$true') 'native default update omitted app-scoped admission'
 Write-Host 'PASS native firewall: app/TCP scope, idempotence, foreign refusal, API errors, policy denial, rollback and native default updater'
}finally{if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force}}
