[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$ControlPlaneUrl,
 [Parameter(Mandatory=$true)][string]$ProbeTarget,
 [string]$InstallDirectory="$env:ProgramData\VELIQ"
)
# Moves an installed client to another control plane host that serves a leaf
# certificate from the SAME pinned CA (cp-ca.pem is not touched). Identity,
# credentials, trust and state stay as they are. A timestamped backup of
# service.json is kept next to it; rerun with the old values to roll back.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Administrator
$uri=[Uri]$ControlPlaneUrl
if($uri.Scheme -ne 'https' -or $uri.AbsolutePath -ne '/'){throw 'ControlPlaneUrl must be https://host:port'}
$m=[regex]::Match($ProbeTarget,'^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$')
if(!$m.Success -or [int]$m.Groups[2].Value -gt 65535){throw 'ProbeTarget must be IPv4:port'}
$probe=New-Object Net.IPEndPoint ([Net.IPAddress]::Parse($m.Groups[1].Value)),([int]$m.Groups[2].Value)
$path=Join-Path $InstallDirectory 'service.json'
$item=Get-Item -LiteralPath $path -Force
if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'service.json is a reparse point'}
$raw=[IO.File]::ReadAllText($path)
$manifest=$raw|ConvertFrom-Json
$old="$($manifest.control_plane_url) / $($manifest.probe_target)"
if($manifest.control_plane_url -ceq $ControlPlaneUrl -and $manifest.probe_target -ceq $ProbeTarget){Write-Host "Already on $ControlPlaneUrl";return}
$backup="$path.bak-$(Get-Date -Format yyyyMMddHHmmss)"
Copy-Item -LiteralPath $path -Destination $backup
$manifest.control_plane_url=$ControlPlaneUrl
$manifest.probe_target=$probe.ToString()
if($manifest.PSObject.Properties['tcp_probe_target'] -and $manifest.tcp_probe_target){$manifest.tcp_probe_target=$probe.ToString()}
$acl=Get-Acl -LiteralPath $path
$tmp="$path.tmp"
[IO.File]::WriteAllText($tmp,($manifest|ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding $false))
Set-Acl -LiteralPath $tmp -AclObject $acl
Move-Item -LiteralPath $tmp -Destination $path -Force
Restart-Service VELIQ
Write-Host "control plane: $old -> $ControlPlaneUrl / $($probe.ToString())"
Write-Host "backup: $backup"
