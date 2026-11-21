[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ProfileId)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
$plan=Invoke-ServiceIPC 'auto.plan' @{profile_id=$ProfileId}
if(!$plan.needs_trial){Write-Host ('AUTO: '+$plan.status);exit 0}
$reports=Join-Path $env:LOCALAPPDATA ('VELIQ\auto-proof\'+$plan.lease)
# Standard-user process. All privileged capture remains in the authenticated
# service. The tester creates only an isolated, birth-scoped browser subtree.
& (Join-Path $PSScriptRoot 'strategy-tester-v2.ps1') -AppPath $plan.application -Preset $plan.preset -URL $plan.url -ReportDirectory $reports -TimeoutSeconds 15 -Automatic -CandidateIds @($plan.candidates)
$result=Invoke-ServiceIPC 'auto.commit' @{profile_id=$ProfileId;lease=$plan.lease}
Write-Host ('AUTO: '+$result.status+'; proof='+$reports)
