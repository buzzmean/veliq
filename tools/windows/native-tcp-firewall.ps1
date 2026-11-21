# Function definitions only. Dot-sourcing never changes firewall configuration.
# WinDivert reflects a selected TCP SYN into the service listener. Windows
# Firewall still applies to that inbound packet; NETWORK injection is not a
# firewall bypass. No proxy port is exposed: the driver drops physical inbound
# listener traffic and accept requires an exact per-flow mapping.
function Get-NativeTcpFirewallPath([string]$Executable) {
 $item=Get-Item -LiteralPath $Executable -Force -ErrorAction Stop
 if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Name -ine 'veliq-service.exe'){throw 'NATIVE_FIREWALL_EXECUTABLE_INVALID'}
 $path=[IO.Path]::GetFullPath($item.FullName)
 if($path.StartsWith('\\')){throw 'NATIVE_FIREWALL_LOCAL_EXECUTABLE_REQUIRED'}
 return $path
}
function Assert-NativeTcpFirewallRule($Rule,[string]$Path) {
 if([string]$Rule.Description -cne 'VELIQ_NATIVE_TCP_REFLECTION_V1' -or [string]$Rule.Group -cne 'VELIQ owned service rules'){throw 'NATIVE_FIREWALL_FOREIGN_RULE'}
 $app=Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
 $port=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction Stop
 if([string]$app.Program -ine $Path -or [string]$Rule.Direction -ne 'Inbound' -or [string]$Rule.Action -ne 'Allow' -or [string]$Rule.Enabled -ne 'True' -or [string]$Rule.Profile -ne 'Any' -or [string]$Rule.EdgeTraversalPolicy -ne 'Block' -or [string]$port.Protocol -notin @('TCP','6') -or [string]$port.LocalPort -ne 'Any' -or [string]$port.RemotePort -ne 'Any'){throw 'NATIVE_FIREWALL_RULE_SCOPE_CHANGED'}
}
function Add-NativeTcpFirewallAdmission([string]$Executable) {
 $path=Get-NativeTcpFirewallPath $Executable
 $name='VELIQ-native-tcp-v1'
 $existing=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name ($name+'*') -ErrorAction Stop | Where-Object Name -eq $name)
 if($existing.Count -gt 1){throw 'NATIVE_FIREWALL_AMBIGUOUS_RULE'}
 if($existing.Count -eq 1){Assert-NativeTcpFirewallRule $existing[0] $path}
 $created=$false
 try {
  if($existing.Count -eq 0){
  New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName 'VELIQ native TCP reflection' -Group 'VELIQ owned service rules' -Description 'VELIQ_NATIVE_TCP_REFLECTION_V1' -Program $path -Protocol TCP -Direction Inbound -Action Allow -Enabled True -Profile Any -EdgeTraversalPolicy Block -ErrorAction Stop | Out-Null
  $created=$true
  }
  $rule=Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
  Assert-NativeTcpFirewallRule $rule $path
  $active=Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction Stop
  Assert-NativeTcpFirewallRule $active $path
  foreach($firewallProfile in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
   if([string]$firewallProfile.Enabled -eq 'True' -and ([string]$firewallProfile.AllowInboundRules -eq 'False' -or [string]$firewallProfile.AllowLocalFirewallRules -eq 'False')){throw 'NATIVE_FIREWALL_LOCAL_RULES_FORBIDDEN_BY_POLICY'}
  }
  return $created
 } catch {
  if($created){Remove-NativeTcpFirewallAdmission $Executable}
  throw
 }
}
function Remove-NativeTcpFirewallAdmission([string]$Executable) {
 $path=Get-NativeTcpFirewallPath $Executable
 $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'VELIQ-native-tcp-v1*' -ErrorAction Stop | Where-Object Name -eq 'VELIQ-native-tcp-v1')
 if($rules.Count -eq 0){return}
 if($rules.Count -ne 1){throw 'NATIVE_FIREWALL_AMBIGUOUS_RULE'}
 Assert-NativeTcpFirewallRule $rules[0] $path
 Remove-NetFirewallRule -PolicyStore PersistentStore -Name 'VELIQ-native-tcp-v1' -ErrorAction Stop
}
