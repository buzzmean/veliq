#requires -Version 5.1
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$t=$null;$e=$null
$a=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../../tools/windows/diag-no-vpn.ps1'),[ref]$t,[ref]$e)
if($e.Count){throw ($e|Out-String)}
foreach($n in @('Prop','Write-RiotEvidence')){$f=$a.Find({param($x)$x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n},$true);Invoke-Expression $f.Extent.Text}
$script:lines=@();function Say([string]$s){$script:lines+=$s}
Write-RiotEvidence ([pscustomobject]@{records=@([pscustomobject]@{domain='sieve.services.riotcdn.net';policy=[pscustomobject]@{action='DIRECT';reason='second DNS address'};secret='NEVER_PRINT'});stages=@([pscustomobject]@{stage='LOCAL';RX=12345})})
$s=$script:lines -join ' '
if($s -notmatch 'stage=DIRECT' -or $s -notmatch 'stage=LOCAL.*rx=12345' -or $s -match 'NEVER_PRINT'){throw 'Riot projection failed'}
Write-Host 'PASS safe Riot diagnostics and parser (PS7; native PS5.1 separately required)'
