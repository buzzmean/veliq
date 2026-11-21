$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\..\tools\windows\tcp-web-checks.ps1')
function Fixture {
 return @{
 report=@{pid=42;exe='C:\tcp-selected.exe';creation_time=7;attempts=@(@{success=$true;tls=$true;protocol='HTTP/2.0';response_source='2.56.177.4';destination='2.56.177.4:40443'})}
 evidence=@{flows=@(@{pid=42;exe='C:\tcp-selected.exe';creation_time=7;protocol='tcp';ip_version='IPv4';destination='2.56.177.4:40443';selected_route='RELAY';relay_id='VPS-01';counters=@{captured_packets=10;captured_bytes=500;relayed_packets=5;relayed_bytes=100;relay_reply_packets=5;relay_reply_bytes=200;direct_packets=0;direct_bytes=0}})}
 }
}
function Check($f){Assert-TcpWebProof $f.report $f.evidence 42 'C:\tcp-selected.exe' 'RELAY' '2.56.177.4' 'http2' 1}
$f=Fixture;Check $f
foreach($mutation in @(
 {param($f) $f.report.attempts[0].success=$false},
 {param($f) $f.report.attempts[0].tls=$false},
 {param($f) $f.report.attempts[0].protocol='HTTP/1.1'},
 {param($f) $f.report.attempts[0].response_source='198.51.100.5'},
 {param($f) $f.evidence.flows[0].selected_route='DIRECT'},
 {param($f) $f.evidence.flows[0].relay_id='wrong'},
 {param($f) $f.evidence.flows[0].counters.relayed_bytes=0},
 {param($f) $f.evidence.flows[0].counters.relay_reply_packets=0},
 {param($f) $f.evidence.flows[0].counters.direct_packets=1},
 {param($f) $f.evidence.flows[0].pid=43}
)){$f=Fixture;& $mutation $f;$rejected=$false;try{Check $f}catch{$rejected=$true};if(!$rejected){throw 'False TCP/HTTPS PASS'}}
Write-Host 'PASS TCP/web evidence rejects failed identity, source, route, protocol and counters'
# Extract only pure browser-proof functions; do not launch browser/IPC in fixtures.
$browser=Join-Path $PSScriptRoot '..\..\tools\windows\acceptance-browser.ps1'
$parseTokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $browser).Path,[ref]$parseTokens,[ref]$parseErrors)
foreach($name in @('Sign-WebMessage','Assert-BrowserObservation')){$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true);if($null -eq $function){throw "Missing browser function $name"};. ([ScriptBlock]::Create($function.Extent.Text))}
$key='controlled-test-key-1234567890';$nonce='0123456789abcdef'
$signature=Sign-WebMessage $key ("request`nGET`n/observe`n"+$nonce)
if($signature -cne 'aa45927a066164e4415974f61789d21245722f9339869ff1f59a2d551fd84fc6'){throw 'Cross-language HMAC encoding changed'}
function BrowserFixture {
 $o=[pscustomobject]@{nonce=$nonce;source='2.56.177.4';protocol='HTTP/2.0';tls=$true;proof=''}
 $o.proof=Sign-WebMessage $key ("response`n$nonce`n2.56.177.4`nHTTP/2.0`ntrue")
 return $o
}
$o=BrowserFixture;Assert-BrowserObservation $o $key $nonce $true '2.56.177.4'
foreach($mutation in @(
 {param($o) $o.PSObject.Properties.Remove('proof')},
 {param($o) $o.proof='forged'},
 {param($o) $o.source='198.51.100.2'},
 {param($o) $o.nonce='another-nonce'},
 {param($o) $o.tls='true'},
 {param($o) $o.protocol='HTTP/3.0'}
)){$o=BrowserFixture;& $mutation $o;$rejected=$false;try{Assert-BrowserObservation $o $key $nonce $true '2.56.177.4'}catch{$rejected=$true};if(!$rejected){throw 'False browser source/TLS/HMAC PASS'}}
Write-Host 'PASS browser proof: cross-language HMAC and missing/forged/source/nonce/TLS/protocol rejection'
