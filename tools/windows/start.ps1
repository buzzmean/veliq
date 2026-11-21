[CmdletBinding()]param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Administrator
Start-Service VELIQ
(Get-Service VELIQ).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
Invoke-ServiceIPC 'status'|ConvertTo-Json -Depth 5
