# Owner release: build Setup from a clean commit, sign the manifest on the
# control-plane host with the existing config key (clients already trust it),
# and publish both files as a GitHub release of buzzmean/veliq. Installed PCs
# pick it up within ~6 h (club images excluded).
[CmdletBinding()]
param(
 [string]$SignHost='146.0.77.98',
 [string]$Repository='buzzmean/veliq',
 [string]$Version='0.3',
 [switch]$SkipBuild
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$dirty=@(& git -C $repo status --porcelain --untracked-files=no);if($dirty.Count){throw 'RELEASE_TRACKED_CHANGES_PRESENT'}
$commit=(& git -C $repo rev-parse HEAD).Trim();$build=[uint64](& git -C $repo rev-list --count HEAD).Trim()
if(!$SkipBuild){
 & (Join-Path $PSScriptRoot 'build-e2e.ps1') | Out-Null
 & (Join-Path $PSScriptRoot 'build-desktop.ps1') | Out-Null
 & (Join-Path $PSScriptRoot 'build-setup.ps1') -ExpectedCommit $commit | Out-Null
}
$setup=Join-Path $repo 'bin\installer\VELIQ-Setup.exe'
$item=Get-Item -LiteralPath $setup
$manifest=[ordered]@{build=$build;version="$Version.$build";commit=$commit;setup_size=$item.Length;setup_sha256=(Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()}
$work=Join-Path $repo 'bin\release-publish';[void][IO.Directory]::CreateDirectory($work)
$plain=Join-Path $work 'manifest.json';$signed=Join-Path $work 'veliq-release.json'
[IO.File]::WriteAllText($plain,($manifest|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))

# Signing helper lives on the CP host; the key never leaves it.
$signer=Join-Path $work 'release-sign'
$env:GOOS='linux';$env:GOARCH='amd64'
try{& go build -trimpath -o $signer (Join-Path $repo 'tools\release-sign');if($LASTEXITCODE){throw 'RELEASE_SIGNER_BUILD_FAILED'}}finally{Remove-Item Env:GOOS,Env:GOARCH}
& scp -q -o BatchMode=yes $signer ("root@${SignHost}:/opt/neexitlag/maintenance/release-sign");if($LASTEXITCODE){throw 'RELEASE_SIGNER_UPLOAD_FAILED'}
# Copy instead of piping: Windows PowerShell 5.1 prefixes piped native input with a BOM.
& scp -q -o BatchMode=yes $plain ("root@${SignHost}:/tmp/veliq-release-manifest.json");if($LASTEXITCODE){throw 'RELEASE_MANIFEST_UPLOAD_FAILED'}
$out=& ssh -o BatchMode=yes "root@$SignHost" 'chmod 750 /opt/neexitlag/maintenance/release-sign && /opt/neexitlag/maintenance/release-sign < /tmp/veliq-release-manifest.json; rc=$?; rm -f /tmp/veliq-release-manifest.json; exit $rc'
if($LASTEXITCODE -or !$out){throw 'RELEASE_SIGN_FAILED'}
[IO.File]::WriteAllText($signed,($out -join "`n"),[Text.UTF8Encoding]::new($false))

# GitHub release with the git credential already stored for this repository.
# Feed git from a file: Windows PowerShell 5.1 pipes native input with a BOM.
$query=Join-Path $work 'credential-query.txt';[IO.File]::WriteAllText($query,"protocol=https`nhost=github.com`n`n",[Text.UTF8Encoding]::new($false))
$cred=& cmd.exe /d /c ('git credential fill < "'+$query+'"');Remove-Item -LiteralPath $query -Force
$token=(($cred | Where-Object {$_ -like 'password=*'}) -replace '^password=','')
if(!$token){throw 'GITHUB_CREDENTIAL_REQUIRED; run git credential-manager github login'}
$headers=@{Authorization="Bearer $token";Accept='application/vnd.github+json';'User-Agent'='VELIQ-release'}
$tag="v$($manifest.version)"
$body=@{tag_name=$tag;target_commitish=$commit;name="VELIQ $($manifest.version)";body="Сборка $build ($($commit.Substring(0,12)))."}|ConvertTo-Json
$rel=Invoke-RestMethod -Method Post -Uri "https://api.github.com/repos/$Repository/releases" -Headers $headers -Body ([Text.Encoding]::UTF8.GetBytes($body)) -ContentType 'application/json; charset=utf-8'
$upload=$rel.upload_url -replace '\{.*\}$',''
foreach($asset in @(@($setup,'VELIQ-Setup.exe','application/octet-stream'),@($signed,'veliq-release.json','application/json'))){
 [void](Invoke-RestMethod -Method Post -Uri ($upload+'?name='+$asset[1]) -Headers $headers -InFile $asset[0] -ContentType $asset[2])
}
Write-Host "RELEASE_PUBLISHED $tag build=$build sha256=$($manifest.setup_sha256) url=$($rel.html_url)"
