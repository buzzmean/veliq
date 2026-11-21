# Read-only comparison through the already authenticated service relay pool.
# No enrollment, SSH, credential changes, DNS changes or Chrome policy changes.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$HostName,
 [Parameter(Mandatory=$true)][ValidateCount(1,3)][string[]]$Candidates,
 [string]$RelayId='VPS-01',
 [string]$TokenFile="$env:ProgramData\VELIQ\ipc.token",
 [string]$ReportFile=''
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$result=Invoke-ServiceIPC 'browser.origin.check' @{host=$HostName.ToLowerInvariant();candidates=$Candidates;relay_id=$RelayId} $TokenFile
$raw=$result|ConvertTo-Json -Depth 12
if($ReportFile){$parent=Split-Path ([IO.Path]::GetFullPath($ReportFile));[void][IO.Directory]::CreateDirectory($parent);$raw|Set-Content -LiteralPath $ReportFile -Encoding UTF8}
$raw
Write-Host 'This checks origin TLS/HTTP through authenticated RELAY. It does not prove Chrome or complete-site PASS.'

if(@($result.candidates|Where-Object{$_.origin_verified}).Count -eq 0){throw 'No candidate passed origin TLS/HTTP verification. Saved diagnostics are not a site PASS.'}
