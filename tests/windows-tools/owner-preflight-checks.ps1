#requires -Version 5.1
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\..\tools\windows\owner-tools-preflight.ps1')
$pythonReal=Get-Command python3,python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$script:candidates=@([pscustomobject]@{Source='C:\Users\fixture\AppData\Local\Microsoft\WindowsApps\python.exe'})
function Get-Command {param($Name,$CommandType,[switch]$All,$ErrorAction);$script:candidates}
try {
 $rejected=$false
 try{Resolve-OwnerPython | Out-Null}catch{$rejected=$_.Exception.Message -match 'PYTHON_3_REQUIRED.*winget install --exact --id Python.Python.3.12'}
 if(!$rejected){throw 'Store alias accepted or missing installation instruction'}
 if($null -ne $pythonReal){$script:candidates=@($pythonReal);$found=Resolve-OwnerPython;if($found.File -ne $pythonReal.Source){throw 'Real Python missing'}}
 $script:probeArgs=@()
 function Invoke-PythonFixture {$script:probeArgs=@($args);$global:LASTEXITCODE=0;'VELIQ_PYTHON_READY'}
 $script:candidates=@([pscustomobject]@{Source='Invoke-PythonFixture'})
 Resolve-OwnerPython | Out-Null
 if($script:probeArgs.Count -ne 2 -or $script:probeArgs[0] -ne '-c' -or $script:probeArgs[1].Contains('"') -or !$script:probeArgs[1].Contains("'VELIQ_PYTHON_READY'")){throw 'Unsafe PS5.1 native quote marshalling'}
 Remove-Item Function:\Invoke-PythonFixture
} finally {Remove-Item Function:\Get-Command}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('veliq-checkout-fixture-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
 & git -C $temp init --quiet;if($LASTEXITCODE){throw 'fixture git init'}
 [IO.File]::WriteAllText((Join-Path $temp 'source.txt'),'source')
 & git -C $temp add source.txt
 & git -C $temp -c user.name=fixture -c user.email=fixture@example.invalid commit --quiet -m fixture;if($LASTEXITCODE){throw 'fixture commit'}
 [IO.File]::WriteAllText((Join-Path $temp 'untracked-owner-output.txt'),'private fixture output')
 Assert-TrackedCheckout $temp
 [IO.File]::WriteAllText((Join-Path $temp 'source.txt'),'changed source')
 $rejected=$false;try{Assert-TrackedCheckout $temp}catch{$rejected=$_.Exception.Message -match 'CLEAN_TRACKED_CHECKOUT_REQUIRED'}
 if(!$rejected){throw 'Tracked modification accepted'}
} finally {Remove-Item -LiteralPath $temp -Force -Recurse}
Write-Host ('PASS tracked-only cleanliness, Store alias rejection, real Python, safe install instruction; PowerShell '+$PSVersionTable.PSVersion)
