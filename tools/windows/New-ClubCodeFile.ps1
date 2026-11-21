# Administrative preparation once per image, not on each guest PC.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1');Assert-Administrator
. (Join-Path $PSScriptRoot 'club-image-common.ps1')
. (Join-Path $PSScriptRoot 'club-code-common.ps1')
if(Test-Path -LiteralPath $Path){throw 'CLUB_CODE_FILE_EXISTS_PRESERVED'}
$secure=Read-Host 'Код клуба (не выводится)' -AsSecureString;$ptr=[IntPtr]::Zero
try{
 $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure);$code=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
 $null=New-ClubPendingRecord $code
 # Protect an empty file before writing the code. Parent must already exist.
 $f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$f.Dispose()
 Set-ClubFileAcl $Path
 [IO.File]::WriteAllText($Path,$code,[Text.UTF8Encoding]::new($false))
 Write-Output 'CLUB_CODE_FILE_READY; SYSTEM/Administrators only; never share publicly or commit'
}finally{if($ptr -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)};Remove-Variable code -ErrorAction SilentlyContinue;$secure.Dispose()}
