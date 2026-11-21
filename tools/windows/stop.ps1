[CmdletBinding()]param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Administrator
Stop-Service VELIQ
(Get-Service VELIQ).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
Write-Host 'Service stopped. Verify ordinary networking remains DIRECT.'
