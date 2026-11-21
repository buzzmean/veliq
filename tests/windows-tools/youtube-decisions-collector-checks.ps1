$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Join-Path ([IO.Path]::GetTempPath()) ('veliq-cdn-decisions-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
try {
    $collector = Join-Path $root 'collect-youtube-decisions.ps1'
    Copy-Item (Join-Path $PSScriptRoot '..\..\tools\windows\collect-youtube-decisions.ps1') $collector
    $fake = @'
Set-StrictMode -Version Latest
$script:reads = 0
function Invoke-ServiceIPCOnce([string]$Method) {
    if ($Method -ne 'browser.youtube.decisions') { throw 'UNEXPECTED_IPC' }
    $script:reads++
    if ($script:reads -eq 1) {
        return [pscustomobject]@{ schema = 1; build = 'fixture'; service_pid = 7; latest_seq = 2; omitted = 0; events = @() }
    }
    return [pscustomobject]@{
        schema = 1; build = 'fixture'; service_pid = 7; latest_seq = 52; omitted = 4
        events = @(
            foreach ($seq in 5..52) {
                [pscustomobject]@{ seq = $seq; connection_id = 1; stage = 'RELAY'; phase = 'OPENED'; reason = 'ORIGIN_SILENT' }
            }
        )
    }
}
'@
    [IO.File]::WriteAllText((Join-Path $root 'common.ps1'), $fake)
    & $collector -DurationSeconds 10 -OutputDirectory $root
    $file = Get-ChildItem -LiteralPath $root -Filter '*.jsonl'
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    if ($bytes[0] -ne 123) { throw 'JSONL_MUST_HAVE_NO_BOM' }
    $rows = @(Get-Content -LiteralPath $file.FullName | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    if ($rows.Count -ne 51 -or $rows[0].kind -ne 'start_signal' -or $rows[0].after_seq -ne 2) { throw 'BAD_CAPTURE_BASELINE' }
    if ($rows[1].kind -ne 'gap' -or $rows[1].omitted_through -ne 4) { throw 'MISSING_EVIDENCE_GAP' }
    foreach ($seq in 5..52) {
        $row = $rows[$seq - 3]
        if ($row.kind -ne 'cdn_decision' -or $row.event.seq -ne $seq -or $row.event.connection_id -ne 1 -or $row.event.reason -ne 'ORIGIN_SILENT') {
            throw 'CDN_DECISION_CHANGED_OR_OUT_OF_ORDER'
        }
    }
    if ($rows[-1].kind -ne 'done' -or $rows[-1].last_seq -ne 52 -or !$rows[-1].evidence_lost) { throw 'BAD_CAPTURE_SUMMARY' }
    Write-Host 'PASS YouTube decision collector cursor, omitted events and JSONL'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
