# Admin-only replacement of one protected file. Does not call SSH/CP or print a code.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$CodeFile,[string]$InstallDirectory="$env:ProgramData\VELIQ",[switch]$Image)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1');Assert-Administrator
. (Join-Path $PSScriptRoot 'club-image-common.ps1')
. (Join-Path $PSScriptRoot 'club-code-common.ps1')
$m=Get-Content -Raw -LiteralPath (Join-Path $InstallDirectory 'service.json')|ConvertFrom-Json
if(!$m.PSObject.Properties['club_image'] -or !$m.club_image){throw 'NOT_CLUB_IMAGE'}
$code=Read-ClubCodeFile $CodeFile
try{
 if($Image){Assert-ClubImageClean $InstallDirectory}
 $record=New-ClubPendingRecord $code
 Invoke-ClubCodeReplacement -Directory $InstallDirectory -Record $record -Image:$Image
 Write-Output 'CLUB_CODE_REPLACED; no identity deleted; check club.status; freeze requires updating the sealed base image too'
}finally{Remove-Variable code,record -ErrorAction SilentlyContinue}
