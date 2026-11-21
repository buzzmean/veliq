[CmdletBinding()]
param(
 [string]$VpsPublicIP='2.56.177.4',
 [Parameter(Mandatory=$true)][string]$HttpURL,
 [Parameter(Mandatory=$true)][string]$HttpsURL,
 [Parameter(Mandatory=$true)][string]$EndpointCA,
 [Parameter(Mandatory=$true)][string]$TokenFile,
 [string]$Binaries=(Join-Path $PSScriptRoot '..\..\bin\windows-e2e'),
 [string]$ReportDirectory=(Join-Path $PSScriptRoot '..\..\.e2e\tcp-web'),
 [ValidateRange(5,12)][int]$Count=10
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'acceptance-checks.ps1')
. (Join-Path $PSScriptRoot 'acceptance-process.ps1')
. (Join-Path $PSScriptRoot 'tcp-web-checks.ps1')
Assert-Administrator
$VpsPublicIP=Assert-VpsIPv4 $VpsPublicIP
foreach($value in @($HttpURL,$HttpsURL,$TokenFile,$EndpointCA,$ReportDirectory)){if($value.Contains('"')){throw 'Quote in argument'}}
foreach($value in @($HttpURL,$HttpsURL)){$u=[Uri]$value;$address=$null;if(![Net.IPAddress]::TryParse($u.Host,[ref]$address)){throw 'Use public IPv4 literal for controlled TCP proof; browser DNS is separate'};[void](Assert-VpsIPv4 $u.Host)}
if(([Uri]$HttpURL).Scheme -ne 'http' -or ([Uri]$HttpsURL).Scheme -ne 'https'){throw 'HTTP and HTTPS URLs required'}
$selected=(Resolve-Path (Join-Path $Binaries 'tcp-selected.exe')).Path;$control=(Resolve-Path (Join-Path $Binaries 'tcp-control.exe')).Path
$EndpointCA=(Resolve-Path $EndpointCA).Path;$TokenFile=(Resolve-Path $TokenFile).Path
New-Item -ItemType Directory -Force $ReportDirectory|Out-Null;$ReportDirectory=(Resolve-Path $ReportDirectory).Path
$run=[Guid]::NewGuid().ToString('N');$selectedId='!tcp-selected-'+$run;$controlId='!tcp-control-'+$run
$children=[Collections.Generic.List[object]]::new();$results=[Collections.Generic.List[object]]::new();$original=Invoke-ServiceIPC 'status'
function Launch-TCP([string]$Exe,[string]$Label,[string]$URL,[string]$Mode,[int]$N){
 $path=Join-Path $ReportDirectory "$run-$Label.json"
 $arguments="-url `"$URL`" -mode $Mode -token-file `"$TokenFile`" -ca `"$EndpointCA`" -count $N -interval 300ms -report `"$path`""
 $p=Start-AcceptanceProcess $Exe $arguments $path;$child=[pscustomobject]@{process=$p;report=$path;exe=$Exe};$children.Add($child);return $child
}
function Complete-TCP($Child,[int]$N){$code=Wait-AcceptanceProcessExit $Child.process (($N*11000)+15000) $Child.report;if($code -ne 0){throw "Client exit=$code; inspect $($Child.report) and stdout/stderr"};return Get-Content $Child.report -Raw|ConvertFrom-Json}
$routesBefore=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'|Select-Object InterfaceIndex,NextHop,RouteMetric|Sort-Object InterfaceIndex,NextHop|ConvertTo-Json -Compress
try {
 [void](Invoke-ServiceIPC 'profile.set' @{id=$selectedId;name='TCP selected';executables=@($selected);mode='MANUAL';relay_id='VPS-01';custom=$true})
 [void](Invoke-ServiceIPC 'profile.set' @{id=$controlId;name='TCP direct control';executables=@($control);mode='DIRECT';custom=$true})
 [void](Invoke-ServiceIPC 'optimize' @{enabled=$true})
 [void](Wait-AcceptanceReadiness -TimeoutMS 30000 -GetSnapshot {Invoke-ServiceIPC 'acceptance.readiness' @{relay_id='VPS-01'}} -Evaluate {param($s)
  $missing=@();$transport=$s.PSObject.Properties['relay_transport'];if($null -eq $transport -or !$transport.Value.connected -or !$transport.Value.flow_open){$missing+='authenticated relay session/open ACK (TCP destination is proven by warm-up)'}
  if(!$s.connected -or !$s.optimizing -or !$s.backend.ready -or !$s.backend.capabilities.tcp){$missing+='TCP backend'}
  if(@($s.profiles|Where-Object{$_.id -eq $selectedId -and $_.mode -eq 'MANUAL' -and $_.relay_id -eq 'VPS-01' -and $_.executables -contains $selected}).Count -ne 1){$missing+='selected effective profile'}
  if(@($s.profiles|Where-Object{$_.id -eq $controlId -and $_.mode -eq 'DIRECT' -and $_.executables -contains $control}).Count -ne 1){$missing+='control effective profile'}
  return [pscustomobject]@{ready=($missing.Count -eq 0);missing=$missing}
 })
 foreach($stage in @(@('http',$HttpURL,'http'),@('https',$HttpsURL,'http'),@('http2',$HttpsURL,'http2'),@('websocket',$HttpsURL,'websocket'))){
  $label=$stage[0];$url=$stage[1];$mode=$stage[2]
  $warmA=Launch-TCP $selected "$label-warm-selected" $url $mode 2;$warmB=Launch-TCP $control "$label-warm-control" $url $mode 2
  $warmReportA=Complete-TCP $warmA 2;$warmReportB=Complete-TCP $warmB 2
  $warmEvidenceA=Invoke-ServiceIPC 'capture.diagnostics' @{pid=$warmA.process.Id};$warmEvidenceB=Invoke-ServiceIPC 'capture.diagnostics' @{pid=$warmB.process.Id}
  Assert-TcpWebProof $warmReportA $warmEvidenceA $warmA.process.Id $selected 'RELAY' $VpsPublicIP $label 2
  Assert-TcpWebProof $warmReportB $warmEvidenceB $warmB.process.Id $control 'DIRECT' $VpsPublicIP $label 2
  $a=Launch-TCP $selected "$label-selected" $url $mode $Count;$b=Launch-TCP $control "$label-control" $url $mode $Count
  $ra=Complete-TCP $a $Count;$rb=Complete-TCP $b $Count
  $ea=Invoke-ServiceIPC 'capture.diagnostics' @{pid=$a.process.Id};$eb=Invoke-ServiceIPC 'capture.diagnostics' @{pid=$b.process.Id}
  # Persist before assertions, including successful-looking JSON that fails routing.
  $proof=@{stage=$label;selected=$ra;control=$rb;selected_capture=$ea;control_capture=$eb}
  $proof|ConvertTo-Json -Depth 20|Set-Content (Join-Path $ReportDirectory "$run-$label-proof.json") -Encoding UTF8
  Assert-TcpWebProof $ra $ea $a.process.Id $selected 'RELAY' $VpsPublicIP $label $Count
  Assert-TcpWebProof $rb $eb $b.process.Id $control 'DIRECT' $VpsPublicIP $label $Count
  Assert-AcceptanceOverlap $ra $rb
  $results.Add(@{stage=$label;status='PASS'});Write-Host "PASS $label simultaneous RELAY/DIRECT"
 }
 $routesAfter=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'|Select-Object InterfaceIndex,NextHop,RouteMetric|Sort-Object InterfaceIndex,NextHop|ConvertTo-Json -Compress
 if($routesBefore -ne $routesAfter){throw 'Default route changed'}
} catch {
 $message=$_.Exception.Message;$status=$null;$capture=@();try{$status=Invoke-ServiceIPC 'status'}catch{}
 foreach($child in $children){try{$capture+=@{pid=$child.process.Id;exe=$child.exe;report=$child.report;capture=(Invoke-ServiceIPC 'capture.diagnostics' @{pid=$child.process.Id})}}catch{}}
 @{error=$message;status=$status;clients=$capture;stages=$results}|ConvertTo-Json -Depth 20|Set-Content (Join-Path $ReportDirectory "$run-FAIL.json") -Encoding UTF8
 throw
} finally {
 foreach($child in $children){if(!$child.process.HasExited){Stop-Process -Id $child.process.Id -ErrorAction SilentlyContinue}}
 foreach($id in @($selectedId,$controlId)){try{[void](Invoke-ServiceIPC 'profile.delete' @{id=$id})}catch{Write-Warning $_}}
 try{[void](Invoke-ServiceIPC 'optimize' @{enabled=$original.optimizing})}catch{Write-Warning $_}
}
