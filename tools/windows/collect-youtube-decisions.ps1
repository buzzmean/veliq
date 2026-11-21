#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(10, 600)][int]$DurationSeconds = 120,
    [string]$OutputDirectory = (Join-Path $env:LOCALAPPDATA 'VELIQ\Diagnostics')
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

function Read-CdnDecisions {
    $snapshot = Invoke-ServiceIPCOnce 'browser.youtube.decisions'
    if ($snapshot.schema -ne 1) { throw 'Unsupported YouTube decision schema' }
    return $snapshot
}

function Write-CdnRow($Row) {
    $writer.WriteLine(($Row | ConvertTo-Json -Depth 6 -Compress))
    $writer.Flush()
}

$baseline = Read-CdnDecisions
$lastSeq = [uint64]$baseline.latest_seq
$null = [IO.Directory]::CreateDirectory($OutputDirectory)
$filename = 'YouTube-decisions-{0}-{1}.jsonl' -f $env:COMPUTERNAME, [DateTime]::UtcNow.ToString("yyyyMMdd-HHmmss-fff'Z'")
$path = Join-Path $OutputDirectory $filename
$stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try {
    $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
    try {
        Write-CdnRow ([ordered]@{
            kind = 'start_signal'; utc = [DateTimeOffset]::UtcNow.ToString('o')
            schema = 1; build = $baseline.build; service_pid = $baseline.service_pid
            after_seq = $lastSeq; duration_seconds = $DurationSeconds
        })
        Write-Host 'START'
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $evidenceLost = $false
        do {
            Start-Sleep -Milliseconds 500
            $snapshot = Read-CdnDecisions
            if ($snapshot.service_pid -ne $baseline.service_pid -or $snapshot.build -ne $baseline.build -or [uint64]$snapshot.latest_seq -lt $lastSeq) {
                throw 'VELIQ service changed during capture'
            }
            if ([uint64]$snapshot.omitted -gt $lastSeq) {
                Write-CdnRow @{ kind = 'gap'; after_seq = $lastSeq; omitted_through = $snapshot.omitted }
                $evidenceLost = $true
            }
            foreach ($event in $snapshot.events) {
                if ([uint64]$event.seq -gt $lastSeq) {
                    Write-CdnRow @{ kind = 'cdn_decision'; event = $event }
                    $lastSeq = [uint64]$event.seq
                }
            }
        } while ($clock.Elapsed.TotalSeconds -lt $DurationSeconds)
        Write-CdnRow @{ kind = 'done'; utc = [DateTimeOffset]::UtcNow.ToString('o'); last_seq = $lastSeq; evidence_lost = $evidenceLost }
    } finally {
        $writer.Dispose()
    }
} finally {
    $stream.Dispose()
}
Write-Host "SAVED $path"
