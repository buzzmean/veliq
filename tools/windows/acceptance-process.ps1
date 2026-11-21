# Start-Process may return an ID-associated Process on Windows. Retain its native
# handle before exit; do not let a nullable/unavailable ExitCode become a failure.
function Start-AcceptanceProcess([string]$Exe,[string]$Arguments,[string]$Report) {
 $process=Start-Process -FilePath $Exe -ArgumentList $Arguments -PassThru -RedirectStandardOutput ($Report+'.stdout') -RedirectStandardError ($Report+'.stderr')
 try {[void]$process.Handle} catch {
  Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
  throw "Cannot retain client process handle; stdout/stderr: $Report.stdout / $Report.stderr : $($_.Exception.Message)"
 }
 return $process
}
function Wait-AcceptanceProcessExit($Process,[int]$TimeoutMS,[string]$Report) {
 if(!$Process.WaitForExit($TimeoutMS)) {
  Stop-Process -Id $Process.Id -ErrorAction SilentlyContinue
  throw "Test client timeout; report/stdout/stderr retained at $Report"
 }
 # The timed overload alone need not finish redirected output processing. The
 # process has already terminated, so this completes waiting without a new race.
 [void]$Process.WaitForExit()
 $Process.Refresh()
 $code=$Process.ExitCode
 if($null -eq $code -or $code -isnot [int]) {
  throw "Client exit code unavailable after complete wait; report/stdout/stderr retained at $Report"
 }
 return $code
}
