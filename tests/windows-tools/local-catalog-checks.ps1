#requires -Version 5.1
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\..\tools\windows\diag-no-vpn.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($name in @('Prop','Write-LocalCatalogEvidence')){$f=$ast.Find({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true);if(!$f){throw 'Missing catalog helper'};Invoke-Expression $f.Extent.Text}
$script:lines=@();function Say([string]$s){$script:lines+=@($s)}
Write-LocalCatalogEvidence $null
Write-LocalCatalogEvidence ([pscustomobject]@{source='BUNDLED_REVIEWED';version=0;schema=1;rules=119;unsupported=102;plans=@([pscustomobject]@{ID='catalog-test';source='flowseal';rule='rule-test';adaptation='own code';secret='DO_NOT_PRINT'});secret='DO_NOT_PRINT'})
$text=$script:lines -join "`n"
if($text -notmatch 'UNINSTRUMENTED' -or $text -notmatch 'available_plans=1' -or $text -match 'DO_NOT_PRINT' -or $text -notmatch 'NOT local bypass confirmation'){throw 'Catalog evidence missing or unsafe'}
Write-Host ('PASS bounded catalog evidence, legacy and safe fixed fields; PowerShell '+$PSVersionTable.PSVersion)
