[CmdletBinding()]
param(
 [string]$BinaryDirectory=(Join-Path $PSScriptRoot '..\..\bin\windows-e2e'),
 [ValidateRange(60,90)][int]$LeaseSeconds=60,
 [string]$ReportDirectory=(Join-Path $PSScriptRoot '..\..\bin\lease-acceptance')
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Isolated native Windows runtime acceptance. Does not stop/reconfigure the
# installed service, access production credentials, or contact/provision a VPS.
New-Item -ItemType Directory -Force $ReportDirectory|Out-Null
$ReportDirectory=(Resolve-Path $ReportDirectory).Path
$oldLease=$env:NEEXITLAG_ACCEPTANCE_LEASE_SECONDS
$started=[DateTime]::UtcNow
function Invoke-LeaseCheck([string]$Name,[string]$Binary,[string]$Pattern,[int]$TimeoutSeconds){
 if(!(Test-Path -LiteralPath $Binary -PathType Leaf)){throw "Missing acceptance binary: $Binary. Run build-e2e.ps1 or download the exact-head Windows artifact."}
 $stdout=Join-Path $ReportDirectory "$Name.stdout.log"
 $stderr=Join-Path $ReportDirectory "$Name.stderr.log"
 $process=Start-Process -FilePath (Resolve-Path $Binary).Path -ArgumentList @('-test.v',"-test.run=$Pattern",'-test.count=1',"-test.timeout=$($TimeoutSeconds)s") -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -NoNewWindow
 try {
  [void]$process.Handle
  if(!$process.WaitForExit(($TimeoutSeconds+10)*1000)){ $process.Kill();$process.WaitForExit();throw "$Name timeout; see $stdout and $stderr" }
  $process.WaitForExit();$process.Refresh();$code=$process.ExitCode
  if($null -eq $code -or $code -ne 0){throw "$Name failed (exit=$code); see $stdout and $stderr"}
  $text=Get-Content -LiteralPath $stdout -Raw
  if($text -notmatch '(?m)^PASS\s*$' -or $text -match 'no tests to run'){throw "$Name did not execute a passing test"}
  Write-Host "$Name PASS: $stdout"
 } finally {$process.Dispose()}
}
try {
 $env:NEEXITLAG_ACCEPTANCE_LEASE_SECONDS=[string]$LeaseSeconds
 Invoke-LeaseCheck 'lease-continuity' (Join-Path $BinaryDirectory 'lease-acceptance.exe') '^TestAcceleratedLeaseAcceptance$' (3*$LeaseSeconds+15)
 Remove-Item Env:\NEEXITLAG_ACCEPTANCE_LEASE_SECONDS -ErrorAction SilentlyContinue
 Invoke-LeaseCheck 'authorization-and-recovery' (Join-Path $BinaryDirectory 'lease-acceptance.exe') '^TestLease|^TestProtectedUDP' 90
 Invoke-LeaseCheck 'native-capture' (Join-Path $BinaryDirectory 'capture-acceptance.exe') '^TestUDPForwardNative|^TestTCPNativePipe|^TestTCPAuthorization' 90
 @{pass=$true;scope='isolated native Windows QUIC/TCP/UDP and capture fixtures; not VPS/WinDivert Internet acceptance';lease_seconds=$LeaseSeconds;elapsed_seconds=([DateTime]::UtcNow-$started).TotalSeconds}|ConvertTo-Json|Set-Content (Join-Path $ReportDirectory 'summary.json') -Encoding UTF8
 Write-Host 'PASS: same established TCP/UDP across two renewals; authorization failure, recovery and native capture regressions. No Discord session required.'
} catch {
 @{pass=$false;error=$_.Exception.Message;elapsed_seconds=([DateTime]::UtcNow-$started).TotalSeconds}|ConvertTo-Json|Set-Content (Join-Path $ReportDirectory 'summary.json') -Encoding UTF8
 throw
} finally {$env:NEEXITLAG_ACCEPTANCE_LEASE_SECONDS=$oldLease}
