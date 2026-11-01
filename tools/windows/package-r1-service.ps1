# Build an unsigned, service-only Windows test artifact. Never installs or starts it.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedCommit,
    [string]$OutputDirectory=(Join-Path $PSScriptRoot '..\..\bin\r1-service')
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'R1_PACKAGE_WINDOWS_REQUIRED; run on Windows x64 with Git and Go 1.25.x (https://go.dev/dl/)'
}
foreach ($tool in @('git','go')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw ('R1_PACKAGE_TOOL_REQUIRED: '+$tool+'; install Git for Windows and Go 1.25.x (https://go.dev/dl/)')
    }
}
if ($env:GOFLAGS) { throw 'R1_PACKAGE_GOFLAGS_MUST_BE_EMPTY; custom build flags are not accepted' }
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$output=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'R1_PACKAGE_OUTPUT_EXISTS; choose a new directory' }
$stage=Join-Path ([IO.Path]::GetTempPath()) ('veliq-r1-'+[Guid]::NewGuid().ToString('N'))
$savedEnvironment=@{}
foreach ($name in @('GOOS','GOARCH','GOAMD64','CGO_ENABLED','GOWORK')) {
    $savedEnvironment[$name]=[Environment]::GetEnvironmentVariable($name,'Process')
}
Push-Location $root
try {
    & git --version
    if ($LASTEXITCODE -ne 0) { throw 'R1_PACKAGE_GIT_UNAVAILABLE; reinstall Git for Windows' }
    $commit=& git rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $commit -ne $ExpectedCommit) { throw 'R1_PACKAGE_COMMIT_MISMATCH' }
    $shallow=& git rev-parse --is-shallow-repository
    if ($LASTEXITCODE -ne 0 -or $shallow -ne 'false') { throw 'R1_PACKAGE_FULL_HISTORY_REQUIRED; use checkout fetch-depth: 0' }
    $dirty=@(& git status --porcelain --untracked-files=no)
    if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) { throw 'R1_PACKAGE_TRACKED_CHANGES; commit tracked changes before packaging' }
    $sequence=& git rev-list --count HEAD
    if ($LASTEXITCODE -ne 0 -or $sequence -notmatch '^[1-9][0-9]*$') { throw 'R1_PACKAGE_BUILD_SEQUENCE_FAILED' }
    $goVersion=& go version
    if ($LASTEXITCODE -ne 0 -or $goVersion -notmatch '^go version go\S+ windows/amd64$') {
        throw 'R1_PACKAGE_GO_UNAVAILABLE; install Windows x64 Go 1.25.x from https://go.dev/dl/'
    }
    $env:GOOS='windows'; $env:GOARCH='amd64'; $env:GOAMD64='v1'; $env:CGO_ENABLED='0'; $env:GOWORK='off'
    $payload=Join-Path $stage 'payload'
    New-Item -ItemType Directory -Path $payload -Force | Out-Null
    # The actual pinned DLL compiler must pass even for a standalone build.
    $filterTests=Join-Path $stage 'filter-tests.exe'
    & go test ./platform/windows '-run' '^TestServiceWinDivertFilterInventory$'
    if ($LASTEXITCODE -ne 0) { throw 'R1_PACKAGE_FILTER_INVENTORY_FAILED' }
    & go test -c -o $filterTests ./platform/windows
    if ($LASTEXITCODE -ne 0) { throw 'R1_PACKAGE_FILTER_BUILD_FAILED' }
    & (Join-Path $PSScriptRoot 'test-windivert-filters.ps1') -TestExecutable $filterTests

    $executable=Join-Path $payload 'veliq-service.exe'
    $ldflags='-X github.com/buzzmean/neexitlag/services/client-service.BuildSequence='+$sequence
    & go build -trimpath -buildvcs=true -ldflags $ldflags -o $executable ./services/client-service/cmd/service
    if ($LASTEXITCODE -ne 0) { throw 'R1_PACKAGE_SERVICE_BUILD_FAILED' }
    # Inspect PE build metadata without executing the service entry point.
    $buildInfo=@(& go version -m $executable)
    if ($LASTEXITCODE -ne 0) { throw 'R1_PACKAGE_BUILD_METADATA_FAILED' }
    $metadata=$buildInfo -join "`n"
    foreach ($setting in @('GOOS=windows','GOARCH=amd64','CGO_ENABLED=0',('vcs.revision='+$commit))) {
        if ($metadata -notmatch ('(?m)^\s*build\s+'+[regex]::Escape($setting)+'\s*$')) {
            throw ('R1_PACKAGE_METADATA_MISMATCH: '+$setting)
        }
    }
    $modifiedMatch=[regex]::Match($metadata,'(?m)^\s*build\s+vcs.modified=(true|false)\s*$')
    if (-not $metadata.Contains($ldflags) -or -not $modifiedMatch.Success) {
        throw 'R1_PACKAGE_BUILD_FLAGS_MISSING'
    }
    $modified=$modifiedMatch.Groups[1].Value -eq 'true'
    $hash=(Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest=[ordered]@{
        schema_version=1
        artifact='VELIQ R1 service-only test build'
        source_commit=$commit
        build_sequence=[int]$sequence
        go_version=$goVersion
        target='windows/amd64'
        vcs_modified=$modified
        signed=$false
        installed=$false
        real_network_acceptance='not_tested'
        windivert_filter_gate='pinned_2.2.2_user_mode_only'
        executable=[ordered]@{name='veliq-service.exe'; sha256=$hash}
    }
    $utf8=New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $payload 'manifest.json'), ($manifest | ConvertTo-Json -Depth 4)+"`n", $utf8)
    # Drop only the machine-specific path in the first line of go version -m.
    [IO.File]::WriteAllText((Join-Path $payload 'build-info.txt'), (($buildInfo | Select-Object -Skip 1) -join "`n")+"`n", $utf8)
    Copy-Item -LiteralPath (Join-Path $root 'docs/R1_TEST_BUILD.md') -Destination (Join-Path $payload 'README.md')
    $checksums=foreach ($name in @('veliq-service.exe','manifest.json','build-info.txt','README.md')) {
        (Get-FileHash -LiteralPath (Join-Path $payload $name) -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$name
    }
    [IO.File]::WriteAllText((Join-Path $payload 'SHA256SUMS'), ($checksums -join "`n")+"`n", $utf8)
    # A concurrent checkout edit must not turn this into a mislabeled artifact.
    $afterCommit=& git rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $afterCommit -ne $commit) { throw 'R1_PACKAGE_CHECKOUT_CHANGED' }
    $afterDirty=@(& git status --porcelain --untracked-files=no)
    if ($LASTEXITCODE -ne 0 -or $afterDirty.Count -ne 0) { throw 'R1_PACKAGE_TRACKED_CHANGES_DURING_BUILD' }
    New-Item -ItemType Directory -Path (Split-Path -Parent $output) -Force | Out-Null
    if (Test-Path -LiteralPath $output) { throw 'R1_PACKAGE_OUTPUT_APPEARED_DURING_BUILD' }
    Move-Item -LiteralPath $payload -Destination $output
    Write-Host ('R1_PACKAGE_PASS commit='+$commit+' sequence='+$sequence+' sha256='+$hash+' powershell='+$PSVersionTable.PSVersion+' installed=false')
} finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name,$savedEnvironment[$name],'Process')
    }
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    Pop-Location
}
