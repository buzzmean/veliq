[CmdletBinding()]
param(
    [ValidateSet('Prepare','Preflight','Apply','Status','Rollback')][string]$Mode='Prepare',
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedCommit,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]+$')][string]$RunId,
    [string]$WorkDirectory='.e2e/vps-upgrade',
    [string]$HostAddress='2.56.177.4',
    [int]$SSHPort=22,
    [string]$KnownHostsFile="$env:USERPROFILE/.ssh/known_hosts",
    [string]$CompatibilityFile,
    [string]$BackupId,
    [string]$DeviceDirectory='.e2e/bundle/windows/device',
    [string]$TrustDirectory='.e2e/bundle/windows/trust',
    [string]$EchoTokenFile='.e2e/bundle/windows/echo.token'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'acceptance-process.ps1')

function Quote-NativeArgument([string]$Value) {
    # CommandLineToArgvW quoting, including trailing slashes in quoted paths.
    if ($Value -notmatch '[\s"]' -and $Value.Length -gt 0) { return $Value }
    return '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}
function Invoke-UpgradeNative([string]$Program,[string[]]$Arguments,[string]$Label,[int]$TimeoutSeconds=120) {
    $base=Join-Path $script:LogDirectory $Label
    $argv=($Arguments | ForEach-Object { Quote-NativeArgument $_ }) -join ' '
    # Reuse the existing tested Windows handle-retaining process wrapper.
    $p=Start-AcceptanceProcess $Program $argv $base
    try {
        $code=Wait-AcceptanceProcessExit $p ($TimeoutSeconds*1000) $base
        if ($code -ne 0) { throw "Command failed: $Label (logs retained; no secret output echoed)" }
        return [System.IO.File]::ReadAllText($base+'.stdout')
    } finally { $p.Dispose() }
}

function Read-UpgradeProperty($Object,[string]$Name) {
    $p=$Object.PSObject.Properties[$Name]
    if ($null -eq $p) { throw "Required evidence field missing: $Name" }
    return $p.Value
}
function Assert-UpgradeProbe($Proof,[string]$IP) {
    foreach ($name in @('pass','same_connection','ticket_replay_rejected','wrong_ticket_rejected','anonymous_mtls_rejected','legacy_2','receipt_retry','renewal_replay_rejected')) {
        if ((Read-UpgradeProperty $Proof $name) -cne $true) { throw "Failed live proof: $name" }
    }
    if ((Read-UpgradeProperty $Proof 'alpn') -cne 'neexitlag/3' -or (Read-UpgradeProperty $Proof 'renewals') -ne 2 -or (Read-UpgradeProperty $Proof 'default_lease_seconds') -ne 1800) { throw 'Incorrect production protocol/lease proof' }
    foreach ($name in @('tcp_source','udp_source')) { if ((Read-UpgradeProperty $Proof $name) -cne $IP) { throw 'Unexpected relay egress' } }
    $dates=@((Read-UpgradeProperty $Proof 'deadlines') | ForEach-Object { [DateTimeOffset]::Parse($_) })
    if ($dates.Count -ne 3 -or $dates[0] -ge $dates[1] -or $dates[1] -ge $dates[2]) { throw 'Renewal deadlines did not advance twice' }
}
function Invoke-UpgradeSSH([string]$Command,[string]$Label,[int]$TimeoutSeconds=120) {
    return Invoke-UpgradeNative 'ssh.exe' ($script:SSHArguments + @("root@$HostAddress",$Command)) $Label $TimeoutSeconds
}
function Copy-UpgradeFile([string]$Source,[string]$Destination,[string]$Label) {
    Invoke-UpgradeNative 'scp.exe' ($script:SCPArguments + @($Source,"root@${HostAddress}:$Destination")) $Label | Out-Null
}

function Invoke-VpsUpgrade {
if ($env:OS -ne 'Windows_NT') { throw 'Use this orchestrator on Windows; isolated Python tests run on Linux' }
$ip=$null
if (-not [System.Net.IPAddress]::TryParse($HostAddress,[ref]$ip) -or $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or $SSHPort -lt 1 -or $SSHPort -gt 65535) { throw 'Explicit IPv4 and valid SSH port required' }
$WorkDirectory=[System.IO.Path]::GetFullPath($WorkDirectory)
New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
$script:LogDirectory=Join-Path $WorkDirectory ('logs-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $script:LogDirectory | Out-Null
$bundle=Join-Path $WorkDirectory "linux-$RunId"
$windows=Join-Path $WorkDirectory "windows-$RunId"
$remote="/var/tmp/neexitlag-upgrade-$RunId-$($ExpectedCommit.Substring(0,12))"
$fixed='/var/lib/neexitlag-upgrade/production-upgrade.py'
$applyAttempted=$false
try {
    if ($Mode -ne 'Prepare') {
    foreach ($tool in @('ssh.exe','scp.exe')) { Get-Command $tool -ErrorAction Stop | Out-Null }
    $KnownHostsFile=(Resolve-Path -LiteralPath $KnownHostsFile).Path
    $sshOptions=@('-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o',"UserKnownHostsFile=$KnownHostsFile",'-o','ConnectTimeout=10','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=3')
    $script:SSHArguments=@('-p',"$SSHPort")+$sshOptions
    $script:SCPArguments=@('-P',"$SSHPort")+$sshOptions
    Invoke-UpgradeSSH 'test "$(id -u)" = 0 && test -d /etc/neexitlag && command -v python3 >/dev/null' 'ssh-preflight' | Out-Null
    if ($Mode -in @('Rollback','Status')) {
        if ($BackupId -notmatch '^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$') { throw 'Exact backup ID required' }
        $verb=$Mode.ToLowerInvariant()
        Invoke-UpgradeSSH "python3 $fixed $verb --backup-id $BackupId" $verb 240 | Write-Output
        return
    }
    }
    # Validate immutable workflow identity BEFORE trusting its files. gh uses the
    # operator's existing GitHub session; never put tokens in command arguments.
    $run=Invoke-UpgradeNative 'gh.exe' @('api',"repos/buzzmean/neexitlag/actions/runs/$RunId") 'workflow' | ConvertFrom-Json
    if ($run.head_sha -cne $ExpectedCommit -or $run.conclusion -cne 'success' -or $run.name -cne 'Relay release and route test' -or $run.repository.full_name -cne 'buzzmean/neexitlag') { throw 'Require successful official release workflow at exact commit' }
    foreach ($item in @(@('neexitlag-relay-linux-amd64',$bundle),@('neexitlag-route-test-windows-amd64',$windows))) {
        if (-not (Test-Path -LiteralPath $item[1])) {
            Invoke-UpgradeNative 'gh.exe' @('run','download',$RunId,'--repo','buzzmean/neexitlag','--name',$item[0],'--dir',$item[1]) ('download-'+$item[0]) | Out-Null
        }
    }
    $manifest=Get-Content -LiteralPath (Join-Path $bundle 'UPGRADE_MANIFEST.json') -Raw | ConvertFrom-Json
    if ($manifest.format -ne 1 -or $manifest.commit -cne $ExpectedCommit) { throw 'Manifest commit mismatch' }
    $required=@('bin/relay','bin/control-plane','deploy/vps/production-upgrade.py')
    if (@($manifest.files.PSObject.Properties).Count -ne $required.Count) { throw 'Unexpected manifest files' }
    foreach ($name in $required) {
        $hash=Read-UpgradeProperty $manifest.files $name
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $bundle $name)).Hash.ToLowerInvariant() -cne $hash) { throw 'Linux artifact checksum mismatch' }
    }
    $test=Join-Path $windows 'neexitlag-route-test-windows-amd64.exe'
    $sum=Get-Content -LiteralPath (Join-Path $windows 'SHA256SUMS') | Where-Object { $_ -match '^([0-9a-f]{64})\s+\*?neexitlag-route-test-windows-amd64\.exe$' }
    if (@($sum).Count -ne 1 -or (Get-FileHash -Algorithm SHA256 -LiteralPath $test).Hash.ToLowerInvariant() -cne ($sum -split '\s+')[0]) { throw 'Windows artifact checksum mismatch' }
    if ($Mode -eq 'Prepare') { Write-Output "PREPARED $ExpectedCommit. No SSH/SCP performed. Logs: $script:LogDirectory"; return }
    if ([string]::IsNullOrWhiteSpace($CompatibilityFile)) { throw 'Explicit reviewed fleet compatibility JSON required' }
    $CompatibilityFile=(Resolve-Path -LiteralPath $CompatibilityFile).Path
    # Validate every LOCAL prerequisite before attempting a remote mutation.
    if ($Mode -eq 'Apply') {
        $DeviceDirectory=(Resolve-Path -LiteralPath $DeviceDirectory).Path
        $TrustDirectory=(Resolve-Path -LiteralPath $TrustDirectory).Path
        $EchoTokenFile=(Resolve-Path -LiteralPath $EchoTokenFile).Path
        foreach ($p in @((Join-Path $DeviceDirectory 'identity.json'),(Join-Path $DeviceDirectory 'device.pem'),(Join-Path $TrustDirectory 'trust.json'),(Join-Path $TrustDirectory 'ca.pem'),(Join-Path $TrustDirectory 'cp-ca.pem'),$EchoTokenFile)) { if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { throw 'Existing enrolled identity/trust/echo token missing; bootstrap is forbidden' } }
    }
    $remote=(Invoke-UpgradeSSH "umask 077; mktemp -d /var/tmp/neexitlag-upgrade-$RunId-XXXXXXXXXXXX" 'stage-directory').Trim()
    if ($remote -notmatch '^/var/tmp/neexitlag-upgrade-[0-9]+-[A-Za-z0-9]{12}$') { throw 'Invalid private staging path' }
    Invoke-UpgradeSSH "mkdir -m 0700 $remote/bin $remote/deploy; mkdir -m 0700 $remote/deploy/vps" 'stage-layout' | Out-Null
    foreach ($name in $required) { Copy-UpgradeFile (Join-Path $bundle $name) "$remote/$name" ('stage-'+($name -replace '[/\.]','-')) }
    Copy-UpgradeFile (Join-Path $bundle 'UPGRADE_MANIFEST.json') "$remote/UPGRADE_MANIFEST.json" 'stage-manifest'
    Copy-UpgradeFile $CompatibilityFile "$remote/compatibility.json" 'stage-compatibility'
    $command="python3 $remote/deploy/vps/production-upgrade.py"
    $arguments="--bundle $remote --expected-commit $ExpectedCommit --compatibility $remote/compatibility.json"
    Invoke-UpgradeSSH "$command preflight $arguments" 'preflight' 180 | Write-Output
    if ($Mode -eq 'Preflight') { return }
    $applyAttempted=$true
    $result=Invoke-UpgradeSSH "$command apply $arguments" 'apply' 540 | ConvertFrom-Json
    $BackupId=Read-UpgradeProperty $result 'id'
    if ($BackupId -notmatch '^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$' -or $result.phase -cne 'pending-verification') { throw 'Unexpected server transaction result' }
    Write-Output "Pending upgrade backup: $BackupId (10-minute independent rollback watchdog armed)"
    $report=Join-Path $script:LogDirectory 'relay-proof.json'
    $probe=@('--upgrade-check','--relay',"${HostAddress}:4433",'--target',"${HostAddress}:40000",'--tcp-target',"${HostAddress}:40000",'--control-plane',"https://${HostAddress}:8443",'--relay-id','VPS-01','--state',$DeviceDirectory,'--trust',(Join-Path $TrustDirectory 'trust.json'),'--ca',(Join-Path $TrustDirectory 'ca.pem'),'--cp-ca',(Join-Path $TrustDirectory 'cp-ca.pem'),'--echo-token-file',$EchoTokenFile,'--expected-egress',$HostAddress,'--report',$report)
    Invoke-UpgradeNative $test $probe 'real-relay-proof' 100 | Out-Null
    Assert-UpgradeProbe (Get-Content -LiteralPath $report -Raw | ConvertFrom-Json) $HostAddress
    Copy-UpgradeFile $report "$remote/relay-proof.json" 'stage-proof'
    Invoke-UpgradeSSH "python3 $fixed commit --backup-id $BackupId --probe-report $remote/relay-proof.json" 'commit' 120 | Write-Output
    $applyAttempted=$false
    Write-Output "PASS: exact $ExpectedCommit; real mTLS/tickets/replay /3+legacy /2; fixed TCP+UDP across two renewals. Logs: $script:LogDirectory"
} catch {
    # Catchable failures rollback now. SSH/process loss is covered by the remote
    # watchdog and persistent boot guard. Neither path restores stale DB/replay.
    if ($applyAttempted -and $BackupId -match '^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$') {
        try { Invoke-UpgradeSSH "python3 $fixed rollback --backup-id $BackupId --automatic" 'automatic-rollback' 240 | Write-Output }
        catch { Write-Warning 'Remote rollback not confirmed. Watchdog remains armed; inspect root-only status. Incompatible downgrade stops services.' }
    }
    throw
}

}
# Dot sourcing exposes the real orchestrator for isolated regression tests.
if ($MyInvocation.InvocationName -eq '.') { return }
Invoke-VpsUpgrade
