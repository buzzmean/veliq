# SYSTEM startup task. No secrets/remote administration/browser processes touched.
[CmdletBinding()]
param([string]$InstallDirectory="$env:ProgramData\VELIQ")
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1');Assert-Administrator
. (Join-Path $PSScriptRoot 'club-image-common.ps1')
$step='MANIFEST';$owner=''
try{
 $m=Get-Content -Raw -LiteralPath (Join-Path $InstallDirectory 'service.json')|ConvertFrom-Json
 if(!$m.PSObject.Properties['club_image'] -or !$m.club_image){throw 'NOT_CLUB_IMAGE'}
 $owner=[string]$m.owner_sid
 $step='BOOT_FLAG';Write-ClubJson (Join-Path $InstallDirectory 'club-boot-ready.json') @{version=1;source='VELIQ_CLUB_BOOT';created_at=[DateTime]::UtcNow.ToString('o')}
 $step='SERVICE_START';$service=Get-Service VELIQ;if($service.Status -ne 'Running'){Start-Service VELIQ}
 (Get-Service VELIQ).WaitForStatus('Running',[TimeSpan]::FromSeconds(45))
 Write-ClubJson (Join-Path $InstallDirectory 'club-boot.json') @{result='BOOT_STARTED';at=[DateTime]::UtcNow.ToString('o');step=$step;activation='PENDING_SERVICE_VERIFICATION'} -OwnerSid $owner -Public
}catch{
 if($owner){Write-ClubJson (Join-Path $InstallDirectory 'club-boot.json') @{result='FAIL';at=[DateTime]::UtcNow.ToString('o');step=$step;code='CLUB_BOOT_FAILED'} -OwnerSid $owner -Public}
 throw ('CLUB_BOOT_FAILED step='+$step)
}
