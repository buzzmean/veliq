# Preflight performs no mutation: explicit reuse, same owner/targets/credentials,
# no reparse points. A mismatched bundle must not silently replace a device.
function Assert-ServiceInstallState([string]$Directory,[switch]$Reinstall,[string]$OwnerSid,[string]$ControlPlaneUrl,[string]$ProbeTarget,[hashtable]$Sources) {
 if(!(Test-Path -LiteralPath $Directory)){return $null}
 if(!$Reinstall){throw 'Installation directory exists. Uninstall SCM if necessary, then explicitly use -Reinstall; credentials/state were preserved.'}
 $root=Get-Item -LiteralPath $Directory -Force
 if(!$root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Install directory must be a real directory, not a reparse point'}
 foreach($item in Get-ChildItem -LiteralPath $Directory -Force -Recurse){if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reinstall refuses reparse points in preserved service state'}}
 $manifestPath=Join-Path $Directory 'service.json'
 if(!(Test-Path -LiteralPath $manifestPath)){throw 'Preserved directory has no service.json; refusing to guess its owner or replace credentials'}
 $manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
 foreach($pair in @(@('owner_sid',$OwnerSid),@('control_plane_url',$ControlPlaneUrl),@('probe_target',$ProbeTarget))) {
  $property=$manifest.PSObject.Properties[$pair[0]]
  if($null -eq $property -or $property.Value -cne $pair[1]){throw "Reinstall $($pair[0]) mismatch; existing installation was not modified"}
 }
 foreach($pair in @(@('token_file','ipc.token'),@('device_identity_file','identity.json'),@('device_certificate','device.pem'),@('trust_file','trust.json'),@('ca_file','ca.pem'),@('probe_token_file','probe.token'),@('control_plane_ca_file','cp-ca.pem'),@('state_directory','state'))) {
  $property=$manifest.PSObject.Properties[$pair[0]]
  if($null -ne $property -and [IO.Path]::GetFullPath($property.Value) -ine [IO.Path]::GetFullPath((Join-Path $Directory $pair[1]))){throw "Reinstall refuses external preserved $($pair[0]); installation not modified"}
 }
 foreach($name in $Sources.Keys) {
  $installed=Join-Path $Directory $name
  if(Test-Path -LiteralPath $installed){
   if((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $Sources[$name] -Algorithm SHA256).Hash){throw "Reinstall credential/trust mismatch: $name; preserved files were not modified"}
  }
 }
 return $manifest
}
function Copy-ServiceCredential([string]$Source,[string]$Destination) {
 # Assert-ServiceInstallState validated equality before any install mutation.
 if(!(Test-Path -LiteralPath $Destination)){Copy-Item -LiteralPath $Source -Destination $Destination -ErrorAction Stop}
}
function Protect-ServiceDirectory([string]$Directory,[string]$OwnerSid) {
 # Replace the DACL, including old explicit grants. Same least-privilege contract
 # as a fresh install: only SYSTEM/admins inherit; GUI owner gets root/binary RX, token/public guard R.
 $fullRoot=(Get-Item -LiteralPath $Directory -Force).FullName
 foreach($item in @((Get-Item -LiteralPath $Directory -Force)) + @(Get-ChildItem -LiteralPath $Directory -Recurse -Force)) {
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Refusing ACL changes through a reparse point'}
  if($item.PSIsContainer){$acl=[Security.AccessControl.DirectorySecurity]::new();$inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}
  else {$acl=[Security.AccessControl.FileSecurity]::new();$inherit=[Security.AccessControl.InheritanceFlags]::None}
  $acl.SetAccessRuleProtection($true,$false)
  $admins=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  $acl.SetOwner($admins)
  foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
   $rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
   [void]$acl.AddAccessRule($rule)
  }
  $rights=$null
  if($item.FullName -eq $fullRoot){$rights=[Security.AccessControl.FileSystemRights]::ReadAndExecute}
  elseif($item.FullName -eq (Join-Path $fullRoot 'veliq-service.exe')){$rights=[Security.AccessControl.FileSystemRights]::ReadAndExecute}
  elseif($item.FullName -eq (Join-Path (Join-Path $fullRoot 'state') 'browser-recovery-guard.json')){$rights=[Security.AccessControl.FileSystemRights]::Read}
  elseif($item.FullName -eq (Join-Path $fullRoot 'ipc.token')){$rights=[Security.AccessControl.FileSystemRights]::Read}
  if($null -ne $rights){[void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($OwnerSid),$rights,[Security.AccessControl.InheritanceFlags]::None,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))}
  Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop
 }
}
