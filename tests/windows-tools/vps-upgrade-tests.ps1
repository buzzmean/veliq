$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $root 'tools/windows/update-vps.ps1') -ExpectedCommit ('a'*40) -RunId '1'
$now=[DateTimeOffset]::UtcNow
$p=[pscustomobject]@{pass=$true;same_connection=$true;ticket_replay_rejected=$true;wrong_ticket_rejected=$true;anonymous_mtls_rejected=$true;legacy_2=$true;receipt_retry=$true;renewal_replay_rejected=$true;alpn='neexitlag/3';renewals=2;default_lease_seconds=1800;tcp_source='127.0.0.1';udp_source='127.0.0.1';deadlines=@($now.ToString('o'),$now.AddMilliseconds(1).ToString('o'),$now.AddMilliseconds(2).ToString('o'))}
Assert-UpgradeProbe $p '127.0.0.1'
$p.same_connection=$false
$rejected=$false
try { Assert-UpgradeProbe $p '127.0.0.1' } catch { $rejected=$true }
if (-not $rejected) { throw 'Replacement flows accepted as continuity' }
$rejected=$false
try { Read-UpgradeProperty ([pscustomobject]@{}) 'error' } catch { $rejected=$true }
if (-not $rejected) { throw 'Missing required evidence not rejected under StrictMode' }
if ((Quote-NativeArgument 'C:\path with space\') -cne '"C:\path with space\\"') { throw 'Trailing slash quoting failed' }
$nativeLogDirectory=Join-Path ([System.IO.Path]::GetTempPath()) ('neexitlag-upgrade-test-'+[Guid]::NewGuid().ToString('N'))
$script:LogDirectory=$nativeLogDirectory
New-Item -ItemType Directory -Path $script:LogDirectory | Out-Null
try {
    # Real Windows redirected Start-Process, no fake process adapter.
    $value=Invoke-UpgradeNative $env:ComSpec @('/d','/c','echo success') 'success'
    if ($value.Trim() -cne 'success') { throw 'Redirected stdout missing' }
    $rejected=$false
    try { Invoke-UpgradeNative $env:ComSpec @('/d','/c','exit 7') 'failure' | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Nonzero exit ignored' }
    $text=Get-Content -LiteralPath (Join-Path $root 'tools/windows/update-vps.ps1') -Raw
    $tokens=$null;$errors=$null
    [void][Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Upgrade orchestrator does not parse' }
    # Execute the REAL Prepare orchestration with local public artifact fixtures.
    # Every SSH/SCP entry point throws; no host or credentials are provided.
    $fixture=Join-Path $script:LogDirectory 'prepare-fixture'
    $WorkDirectory=$fixture
    $Mode='Prepare'; $KnownHostsFile='DOES-NOT-EXIST'; $HostAddress='127.0.0.1'
    $linux=Join-Path $fixture 'linux-1'; $win=Join-Path $fixture 'windows-1'
    New-Item -ItemType Directory -Force -Path (Join-Path $linux 'bin'),(Join-Path $linux 'deploy/vps'),$win | Out-Null
    $hashes=@{}
    foreach ($name in @('bin/relay','bin/control-plane','deploy/vps/production-upgrade.py')) {
        $file=Join-Path $linux $name
        [IO.File]::WriteAllText($file,'public test fixture')
        $hashes[$name]=(Get-FileHash -Algorithm SHA256 $file).Hash.ToLowerInvariant()
    }
    [IO.File]::WriteAllText((Join-Path $linux 'UPGRADE_MANIFEST.json'),(@{format=1;commit=('a'*40);files=$hashes}|ConvertTo-Json))
    $exe=Join-Path $win 'neexitlag-route-test-windows-amd64.exe'
    [IO.File]::WriteAllText($exe,'public executable fixture, never executed')
    [IO.File]::WriteAllText((Join-Path $win 'SHA256SUMS'),((Get-FileHash -Algorithm SHA256 $exe).Hash.ToLowerInvariant()+'  neexitlag-route-test-windows-amd64.exe'))
    function Invoke-UpgradeNative([string]$Program,[string[]]$Arguments,[string]$Label,[int]$TimeoutSeconds=120) {
        if ($Program -cne 'gh.exe' -or $Label -cne 'workflow') { throw 'Unexpected program in isolated Prepare' }
        return (@{head_sha=('a'*40);conclusion='success';name='Relay release and route test';repository=@{full_name='buzzmean/neexitlag'}}|ConvertTo-Json)
    }
    function Invoke-UpgradeSSH { throw 'Prepare reached SSH' }
    function Copy-UpgradeFile { throw 'Prepare reached SCP' }
    Invoke-VpsUpgrade
    Write-Output 'PASS: StrictMode, same-flow evidence, quoting, real redirected exit=0/nonzero, default Prepare boundary.'
} finally { Remove-Item -LiteralPath $nativeLogDirectory -Recurse -Force }
