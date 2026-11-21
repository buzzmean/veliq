#requires -Version 5.1
# Side-effect-free owner tooling preflight. No SSH/install/activation.
function Assert-TrackedCheckout([string]$Repository) {
 $dirty=@(& git -C $Repository status --porcelain --untracked-files=no)
 if($LASTEXITCODE -ne 0){throw 'TRACKED_CHECKOUT_CHECK_FAILED'}
 if($dirty.Count){throw 'CLEAN_TRACKED_CHECKOUT_REQUIRED; tracked files changed; user diagnostics/untracked files are ignored'}
}
function Resolve-OwnerPython {
 foreach($name in @('python','python3','py')) {
  foreach($candidate in @(Get-Command $name -CommandType Application -All -ErrorAction SilentlyContinue)) {
   # Do not invoke the Microsoft Store application execution alias.
   if($candidate.Source -match '(?i)[\\/]Microsoft[\\/]WindowsApps[\\/]'){continue}
   $prefix=@();if($name -eq 'py'){$prefix=@('-3')}
   # PS5.1 legacy native argv strips embedded double quotes. Python single
   # quotes survive CommandLineToArgvW without an extra shell/escape layer.
   $probe=@($prefix)+@('-c',"import sys; print('VELIQ_PYTHON_READY' if sys.version_info >= (3,9) else 'PYTHON_TOO_OLD')")
   try {
    $answer=@(& $candidate.Source @probe 2>$null)
    if($LASTEXITCODE -eq 0 -and ($answer -contains 'VELIQ_PYTHON_READY')){
     return [pscustomobject]@{File=$candidate.Source;Prefix=$prefix}
    }
   } catch { }
  }
 }
 throw 'PYTHON_3_REQUIRED; install: winget install --exact --id Python.Python.3.12 --source winget ; then open a new PowerShell window (Microsoft Store aliases are not Python)'
}
