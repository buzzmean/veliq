[CmdletBinding()]
param(
    [ValidateRange(20, 240)][int]$Seconds = 90,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')

function Get-Field($Object, [string]$Name) {
    if ($null -ne $Object) {
        $property = $Object.PSObject.Properties[$Name]
        if ($null -ne $property) { return ,$property.Value }
    }
}

function Get-OriginClass([string]$HostName) {
    $name = $HostName.ToLowerInvariant().TrimEnd('.')
    if ($name -match '(^|\.)googlevideo\.com$') { return 'youtube_cdn' }
    if ($name -match '(^|\.)(youtube\.com|ytimg\.com|ggpht\.com|youtube-nocookie\.com|youtubekids\.com|youtu\.be|youtubei\.googleapis\.com|youtube\.googleapis\.com|youtubeembeddedplayer\.googleapis\.com|yt3\.googleusercontent\.com|wide-youtube\.l\.google\.com|youtube-ui\.l\.google\.com|ytimg\.l\.google\.com|jnn-pa\.googleapis\.com)$') { return 'youtube' }
    if ($name -match '(^|\.)(doubleclick\.net|play\.google\.com|dns\.google|cloudflare-dns\.com|googleapis\.com|google\.com|googleusercontent\.com|gstatic\.com)$') { return 'shared' }
    $address = $null
    if (!$name -or [Net.IPAddress]::TryParse($name, [ref]$address) -or $name -match 'opaque|^\(') { return 'opaque' }
    return 'other'
}

function Write-Evidence([string]$Kind, $Data) {
    $line = [ordered]@{ kind = $Kind; at_utc = [DateTime]::UtcNow.ToString('o'); data = $Data }
    $writer.WriteLine(($line | ConvertTo-Json -Depth 10 -Compress))
}

function Get-RelayBuckets($Relay) {
    $buckets = @{}
    foreach ($row in (Get-Field $Relay 'minutes')) {
        if ($null -eq $row) { continue }
        $minute = Get-Field $row 'minute_utc'
        $domain = Get-Field $row 'domain'
        $id = '{0}|{1}|{2}' -f $minute, (Get-Field $row 'profile_id'), $domain
        $buckets[$id] = @{
            Class = Get-OriginClass $domain
            Opens = Get-Field $row 'tunnels_opened'
            RX = Get-Field $row 'received_bytes'
            TX = Get-Field $row 'sent_bytes'
        }
    }
    return $buckets
}

function Get-RelayBucketDeltas($Baseline, $Current) {
    $named = 0
    $shared = 0
    foreach ($id in $Current.Keys) {
        $value = $Current[$id]
        $old = $Baseline[$id]
        if ($null -eq $old) { $old = @{ Opens = 0; RX = 0; TX = 0 } }
        if ($value.Opens -gt $old.Opens -or $value.RX -gt $old.RX -or $value.TX -gt $old.TX) {
            if ($value.Class -in @('youtube', 'youtube_cdn')) { $named++ }
            if ($value.Class -in @('shared', 'opaque')) { $shared++ }
        }
    }
    return @{ Named = $named; Shared = $shared }
}

if (!(Get-Process -Name chrome -ErrorAction SilentlyContinue)) { throw 'Нужна уже открытая сессия Google Chrome.' }
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$sessionId = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$fileName = 'YOUTUBE-LOCAL-BETA-{0}-{1}.jsonl' -f [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmssZ'), $sessionId
$outputPath = Join-Path $OutputDirectory $fileName
$stream = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew)
$writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
$writer.AutoFlush = $true

$sequence = [uint64]0
$decisionGap = $false
$sampleFailures = 0
$last = $null
$base = $null
$sameRun = $true
$namedRelayObserved = $false
$sharedRelayObserved = $false
$namedDNSRelayObserved = $false

try {
    $base = Invoke-ServiceIPCOnce 'browser.youtube.local.status'
    if ((Get-Field $base 'active') -ne $true) { throw 'Режим YouTube без VPS должен быть активен в VELIQ.' }
    $baseDecision = Invoke-ServiceIPCOnce 'browser.youtube.decisions'
    $sequence = [uint64](Get-Field $baseDecision 'latest_seq')
    $servicePid = Get-Field $baseDecision 'service_pid'
    $baseNative = Invoke-ServiceIPCOnce 'browser.native.status'
    $relayBase = Get-RelayBuckets (Get-Field $baseNative 'relay_usage')
    $startUTC = [DateTime]::UtcNow
    Write-Evidence 'start' ([ordered]@{
        build = Get-Field $baseDecision 'build'
        initial_status = $base
        attribution = 'HOST_AND_CHROME_PROCESS; NO_TAB_ID_IN_VELIQ'
    })
    Write-Host 'START. В уже открытом Chrome запустите видео и один раз перемотайте. Запомните, пошли ли кадры после перемотки.'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        try {
            $last = Invoke-ServiceIPCOnce 'browser.youtube.local.status'
            $decisions = Invoke-ServiceIPCOnce 'browser.youtube.decisions'
            $native = Invoke-ServiceIPCOnce 'browser.native.status'
        } catch {
            $sampleFailures++
            Write-Evidence 'ipc_error' @{ sample = $sampleFailures }
            Start-Sleep -Seconds 1
            continue
        }
        if ((Get-Field $last 'active') -ne $true -or
            (Get-Field $last 'generation') -ne (Get-Field $base 'generation') -or
            (Get-Field $decisions 'service_pid') -ne $servicePid) { $sameRun = $false }
        $fresh = @((Get-Field $decisions 'events') | Where-Object { (Get-Field $_ 'seq') -gt $sequence })
        foreach ($event in $fresh) {
            $current = [uint64](Get-Field $event 'seq')
            if ($current -ne ($sequence + 1)) { $decisionGap = $true }
            $sequence = $current
            Write-Evidence 'cdn_decision' ([ordered]@{
                seq = $current
                connection_id = Get-Field $event 'connection_id'
                phase = Get-Field $event 'phase'
                stage = Get-Field $event 'stage'
                reason = Get-Field $event 'reason'
                local_admission = Get-Field $event 'local_admission'
                strategy = Get-Field $event 'strategy'
            })
        }
        $dns = Get-Field $native 'browser_dns'
        $relay = Get-Field $native 'relay_usage'
        $deltas = Get-RelayBucketDeltas $relayBase (Get-RelayBuckets $relay)
        $namedDNSRelay = @( (Get-Field $dns 'records') | Where-Object {
            (Get-Field $_ 'path') -eq 'AUTHENTICATED_RELAY_DOH' -and
            (Get-OriginClass (Get-Field $_ 'domain')) -in @('youtube', 'youtube_cdn') -and
            [DateTime](Get-Field $_ 'at') -ge $startUTC
        }).Count
        if ($deltas.Named) { $namedRelayObserved = $true }
        if ($deltas.Shared) { $sharedRelayObserved = $true }
        if ($namedDNSRelay) { $namedDNSRelayObserved = $true }
        # Do not treat bounded rings, rolling minute buckets, or process-wide
        # DNS totals as per-tab evidence. Keep only attributable categories.
        Write-Evidence 'sample' ([ordered]@{
            elapsed_ms = $timer.ElapsedMilliseconds
            local_status = $last
            native_lost = Get-Field $native 'lost'
            native_truncated = Get-Field $native 'truncated'
            browser_dns_queries = Get-Field $dns 'queries'
            browser_dns_vps = Get-Field $dns 'relay_doh'
            relay_truncated = Get-Field $relay 'truncated'
            relay_video_connections_omitted = Get-Field $relay 'video_connections_omitted'
            relay_all_tunnels_opened = Get-Field $relay 'tcp_tunnels_opened'
            named_youtube_relay_buckets_increased = $deltas.Named
            shared_or_opaque_relay_buckets_increased = $deltas.Shared
            named_youtube_relay_dns_records = $namedDNSRelay
        })
        Start-Sleep -Seconds 1
    } while ($timer.Elapsed.TotalSeconds -lt $Seconds)

    $firstRx = Get-Field $base 'local_cdn_rx'
    $lastRx = Get-Field $last 'local_cdn_rx'
    $firstDns = Get-Field $base 'local_dns_queries'
    $lastDns = Get-Field $last 'local_dns_queries'
    $rx = $null
    $localDns = $null
    if ($sameRun -and $null -ne $firstRx -and $null -ne $lastRx -and $lastRx -ge $firstRx) { $rx = [uint64]$lastRx - [uint64]$firstRx }
    if ($sameRun -and $null -ne $firstDns -and $null -ne $lastDns -and $lastDns -ge $firstDns) { $localDns = [uint64]$lastDns - [uint64]$firstDns }
    Write-Evidence 'summary' ([ordered]@{
        local_cdn_rx_bytes = $rx
        named_local_dns_queries = $localDns
        decision_gap = $decisionGap
        ipc_sample_failures = $sampleFailures
        original_generation = $sameRun
        named_youtube_relay_increase_observed = $namedRelayObserved
        named_youtube_relay_dns_observed = $namedDNSRelayObserved
        shared_or_opaque_relay_increase_observed = $sharedRelayObserved
        playback_and_seek = 'USER_OBSERVATION_REQUIRED'
        youtube_tab_vps = 'UNKNOWN_SHARED_CHROME_DOH_AND_WINDOWS_DNS_HAVE_NO_TAB_ATTRIBUTION'
    })
} finally {
    $writer.Dispose()
}
Write-Host "SAVED $outputPath"
