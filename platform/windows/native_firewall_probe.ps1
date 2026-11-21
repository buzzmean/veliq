# Read-only function, embedded in the service. No registry/firewall writes and no
# executable path, credentials, process arguments or arbitrary errors in output.
function Get-VeliqNativeFirewallSnapshot([string]$Executable) {
 $ErrorActionPreference='Stop'
 $name='VELIQ-native-tcp-v1'
 $result=[ordered]@{state='MISSING';known=$true;rule_present=$false;program_matches=$false;effective=$false;local_rules_permitted=$true}
 $persistent=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name ($name+'*') -ErrorAction Stop | Where-Object Name -eq $name)
 if($persistent.Count -eq 0){return [pscustomobject]$result}
 $result.rule_present=$true
 if($persistent.Count -ne 1){$result.state='AMBIGUOUS_RULE';return [pscustomobject]$result}
 $rule=$persistent[0]
 if([string]$rule.Description -cne 'VELIQ_NATIVE_TCP_REFLECTION_V1' -or [string]$rule.Group -cne 'VELIQ owned service rules'){$result.state='FOREIGN_RULE';return [pscustomobject]$result}
 $active=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name ($name+'*') -ErrorAction Stop | Where-Object Name -eq $name)
 if($active.Count -ne 1){$result.state='RULE_NOT_EFFECTIVE';return [pscustomobject]$result}
 foreach($candidate in @($rule,$active[0])) {
  $app=Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $candidate -ErrorAction Stop
  $port=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $candidate -ErrorAction Stop
  $result.program_matches=([string]$app.Program -ieq $Executable)
  if(!$result.program_matches -or [string]$candidate.Description -cne 'VELIQ_NATIVE_TCP_REFLECTION_V1' -or [string]$candidate.Group -cne 'VELIQ owned service rules' -or [string]$candidate.Direction -ne 'Inbound' -or [string]$candidate.Action -ne 'Allow' -or [string]$candidate.Enabled -ne 'True' -or [string]$candidate.Profile -ne 'Any' -or [string]$candidate.EdgeTraversalPolicy -ne 'Block' -or [string]$port.Protocol -notin @('TCP','6') -or [string]$port.LocalPort -ne 'Any' -or [string]$port.RemotePort -ne 'Any'){$result.state='SCOPE_MISMATCH';return [pscustomobject]$result}
 }
 foreach($firewallProfile in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)){
  if([string]$firewallProfile.Enabled -eq 'True' -and ([string]$firewallProfile.AllowInboundRules -eq 'False' -or [string]$firewallProfile.AllowLocalFirewallRules -eq 'False')){$result.state='LOCAL_RULES_FORBIDDEN_BY_POLICY';$result.local_rules_permitted=$false;return [pscustomobject]$result}
 }
 $result.state='APPLIED';$result.effective=$true
 return [pscustomobject]$result
}
