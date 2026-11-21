#requires -Version 5.1
# Offline fixture only. Never changes the caller's Git configuration or checkout.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(-not (Get-Command git -ErrorAction SilentlyContinue)){throw 'Install Git: winget install --id Git.Git -e'}
function Invoke-FixtureGit([string[]]$GitArguments) {
    $saved=$ErrorActionPreference
    try {
        # Windows PowerShell 5.1 turns native stderr warnings into errors under Stop.
        $ErrorActionPreference='Continue'
        $output=@(& git @GitArguments 2>&1)
        $code=$LASTEXITCODE
    } finally {$ErrorActionPreference=$saved}
    if($code){throw ('RESOURCE_FIXTURE_GIT_FAILED exit='+$code+' command=git '+($GitArguments -join ' '))}
    return $output
}
$null=Invoke-FixtureGit @('--version')
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$temp=Join-Path ([IO.Path]::GetTempPath()) ('veliq-resource-checkout-'+[Guid]::NewGuid().ToString('N'))
$utf8=New-Object Text.UTF8Encoding($false)
$catalog='apps/desktop-core/Resources/GameCatalog.json'
$textPaths=@($catalog,'core/localstrategy/catalog.json','core/originpolicy/registry.json')
$manifest=Get-Content -LiteralPath (Join-Path $root 'assets/brand/SOURCES.json') -Raw | ConvertFrom-Json
$textPaths+=@($manifest.files.PSObject.Properties | ForEach-Object {'assets/brand/'+$_.Name})
$hashes=@{}
foreach($path in $textPaths){$hashes[$path]=(Get-FileHash -LiteralPath (Join-Path $root $path) -Algorithm SHA256).Hash}
$code=Get-Content -LiteralPath (Join-Path $root 'apps/desktop-core/GameCatalog.cs') -Raw
$match=[regex]::Match($code,'BundledSha256\s*=\s*"([A-Fa-f0-9]{64})"')
if(-not $match.Success -or $hashes[$catalog] -ine $match.Groups[1].Value){throw 'SOURCE_GAME_CATALOG_HASH_MISMATCH'}
foreach($entry in $manifest.files.PSObject.Properties){if($hashes['assets/brand/'+$entry.Name] -ine $entry.Value){throw 'SOURCE_BRAND_HASH_MISMATCH'}}
try {
    [void][IO.Directory]::CreateDirectory($temp)
    $null=Invoke-FixtureGit @('init','--quiet',$temp)
    foreach($setting in @('core.autocrlf=true','core.eol=crlf','core.safecrlf=false')){
        $pair=$setting.Split('=');$null=Invoke-FixtureGit @('-C',$temp,'config','--local',$pair[0],$pair[1])
    }
    foreach($path in $textPaths){
        $target=Join-Path $temp $path
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
        [IO.File]::WriteAllBytes($target,[IO.File]::ReadAllBytes((Join-Path $root $path)))
    }
    $attributes=Join-Path $temp '.gitattributes'
    [IO.File]::WriteAllText($attributes,"* text=auto`n",$utf8)
    $null=Invoke-FixtureGit @('-C',$temp,'add','--','.')
    Remove-Item -LiteralPath (Join-Path $temp $catalog)
    $null=Invoke-FixtureGit @('-C',$temp,'checkout-index','--force','--',$catalog)
    $crlf=[IO.File]::ReadAllBytes((Join-Path $temp $catalog))
    if($crlf -notcontains [byte]13 -or (Get-FileHash (Join-Path $temp $catalog)).Hash -eq $hashes[$catalog]){
        throw 'AUTOCRLF_BASELINE_DID_NOT_REPRODUCE'
    }
    # Apply the real attributes without changing the canonical bytes in the index.
    [IO.File]::WriteAllBytes($attributes,[IO.File]::ReadAllBytes((Join-Path $root '.gitattributes')))
    $binaryPaths=@('fixture.zip','fixture.dll','fixture.sys')
    $binary=[byte[]](80,75,10,65,13,10,66) # No NUL: binary attributes must prevent text conversion.
    foreach($path in $binaryPaths){[IO.File]::WriteAllBytes((Join-Path $temp $path),$binary)}
    $null=Invoke-FixtureGit (@('-C',$temp,'add','--','.gitattributes')+$binaryPaths)
    foreach($path in ($textPaths+$binaryPaths)){Remove-Item -LiteralPath (Join-Path $temp $path)}
    $null=Invoke-FixtureGit @('-C',$temp,'checkout-index','--all','--force')
    foreach($path in $textPaths){
        $bytes=[IO.File]::ReadAllBytes((Join-Path $temp $path))
        if($bytes -contains [byte]13 -or (Get-FileHash (Join-Path $temp $path)).Hash -ne $hashes[$path]){
            throw ('AUTOCRLF_RESOURCE_BYTES_CHANGED: '+$path)
        }
    }
    foreach($path in $binaryPaths){
        if([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $temp $path))) -cne [Convert]::ToBase64String($binary)){
            throw ('AUTOCRLF_BINARY_BYTES_CHANGED: '+$path)
        }
    }
    $eol=Invoke-FixtureGit (@('-C',$temp,'ls-files','--eol','--')+$textPaths+$binaryPaths)
    $eol | ForEach-Object {Write-Host $_}
    Write-Host ('PASS autocrlf=true: baseline CRLF reproduced; 7 LF resources and 3 binary fixtures unchanged; PowerShell '+$PSVersionTable.PSVersion)
} finally {if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Recurse -Force}}
