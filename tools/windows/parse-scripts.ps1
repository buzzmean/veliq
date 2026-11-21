[CmdletBinding()]param([string]$Directory=$PSScriptRoot)
$ErrorActionPreference='Stop'
$failed=$false
foreach($file in Get-ChildItem $Directory -Filter '*.ps1' -Recurse){
 $tokens=$null;$errors=$null
 [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
 if($errors.Count){$failed=$true;Write-Output "FAIL $($file.Name)";$errors|ForEach-Object{Write-Output $_.Message}}else{Write-Output "PASS $($file.Name)"}
}
if($failed){exit 1}
