$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\..\tools\windows\simultaneous-checks.ps1')
$path=Join-Path $PSScriptRoot '..\..\tools\windows\acceptance-chrome-sites.ps1'
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
$function=$ast.Find({param($a)$a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'Observe-CDP'},$true)
Invoke-Expression $function.Extent.Text
$script:eventLoss=$false
$script:targets=@{a=@{frame='root-a';document=$null;failures=@();requests=@{}};b=@{frame='root-b';document=$null;failures=@();requests=@{}}}
function Check($Value,[string]$Message){if(!$Value){throw $Message}}
function Event([string]$Session,[string]$Method,$Params){Observe-CDP ([pscustomobject]@{sessionId=$Session;method=$Method;params=$Params})}
Event a 'Network.loadingFailed' @{requestId='old';type='Fetch';errorText='service stopped before stage'}
Check ($script:targets.a.failures.Count -eq 0) 'Previous-stage failure contaminated restart trial'
Event a 'Network.requestWillBeSent' @{requestId='new'}
Event b 'Network.loadingFailed' @{requestId='new';type='Fetch';errorText='other tab'}
Check ($script:targets.a.failures.Count -eq 0) 'Other CDP session contaminated origin'
Event a 'Network.loadingFailed' @{requestId='new';type='Fetch';errorText='ERR_CONNECTION_CLOSED'}
Check ($script:targets.a.failures.Count -eq 1) 'Real current-stage API failure hidden'
function Origin([string]$URL){([Uri]$URL).GetLeftPart([UriPartial]::Authority)}
Event a 'Network.responseReceived' @{type='XHR';requestId='new';response=@{url='https://api.openai.com/?credential=never-log';status=503;protocol='h2'}}
Check ($script:targets.a.failures.Count -eq 2 -and $script:targets.a.failures[1].error -eq 'APPLICATION_HTTP_ERROR') 'HTTP API/server failure hidden as page PASS'
Event a 'Network.responseReceived' @{type='Document';frameId='root-a';requestId='doc';response=@{url='https://vk.com/?private=never-log';status=200;protocol='h2'}}
Check (!$script:targets.a.document.finished) 'HTTP headers alone were called completed page'
Check ($script:targets.a.document.origin -eq 'https://vk.com') 'URL query leaked to evidence'
Event b 'Network.loadingFinished' @{requestId='doc'}
Check (!$script:targets.a.document.finished) 'Other tab completed this document'
Event a 'Network.loadingFinished' @{requestId='doc'}
Check $script:targets.a.document.finished 'Exact finished document not recorded'
for($i=0;$i -lt 2050;$i++){Event a 'Network.requestWillBeSent' @{requestId=('bounded-'+$i)}}
Check ($script:eventLoss -and $script:targets.a.requests.Count -eq 2048) 'Instrumentation bound silently dropped evidence'
$strings=@($tokens|Where-Object{$_.Kind -in @('StringLiteral','StringExpandable')}|ForEach-Object{$_.Text}) -join "`n"
Check ($strings -notmatch '--no-sandbox|--ignore-certificate-errors|--disable-quic|--proxy-pac-url') 'Public acceptance bypasses production policy/TLS'
Write-Host 'PASS Chrome CDP multi-tab correlation, HTTP completion, restart boundary, API failures, bounds and no TLS/PAC bypass'
