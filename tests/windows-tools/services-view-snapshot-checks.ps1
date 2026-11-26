#requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$path=Join-Path $PSScriptRoot '../../tools/windows/services-view-snapshot.ps1'
$tokens=$null;$parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'PARSE_FAILED'}
foreach($name in @('Read-ViewField','Read-ViewBytes','Invoke-ViewRead','Get-ViewSample')){
 $fn=$ast.Find({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
 if(!$fn){throw ('FUNCTION_MISSING '+$name)}
 Invoke-Expression $fn.Extent.Text
}
$status=[pscustomobject]@{connected=$true;optimizing=$true;profiles=@([pscustomobject]@{id='x';secret='SECRET'});token='SECRET';routes=@(
 [pscustomobject]@{id='DIRECT';status='healthy';observed_at=[DateTimeOffset]::UtcNow.ToString('o')},
 [pscustomobject]@{id='relay';status='healthy';observed_at=[DateTimeOffset]::UtcNow.ToString('o')},
 [pscustomobject]@{id='stale';status='healthy';observed_at=[DateTimeOffset]::UtcNow.AddSeconds(-120).ToString('o')}
)}
$capture=[pscustomobject]@{truncated=$true;flows=@([pscustomobject]@{process_group='chatgpt-desktop';selected_route='BLOCK';relay_required_blocked=$true;exe='SECRET';destination='SECRET'})}
$sample=Get-ViewSample 1 $status $capture
if($sample.Profiles -ne 1 -or $sample.FreshRelays -ne 1 -or $sample.CodexBlocked -ne 1 -or !$sample.Truncated){throw 'BAD_PROJECTION'}
if(($sample|ConvertTo-Json) -match 'SECRET|destination|exe|token'){throw 'SECRET_LEAK'}
$missing=Get-ViewSample 2 $null $null
if($missing.Profiles -ne 'UNKNOWN' -or $missing.Flows -ne 'UNKNOWN' -or $missing.CodexBlocked -ne 'UNKNOWN'){throw 'MISSING_DATA_BECAME_ZERO'}
$denied=$false;try{Invoke-ViewRead 'profile.set'|Out-Null}catch{$denied=$true}
if(!$denied){throw 'MUTATION_METHOD_ACCEPTED'}

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
public static class ServicesViewPipeFixture {
 static byte[] Read(Stream s,int count){var b=new byte[count];int offset=0;while(offset<count){int n=s.Read(b,offset,count-offset);if(n==0)throw new IOException("closed");offset+=n;}return b;}
 public static Task Serve(string pipe,string scenario){
  var server=new NamedPipeServerStream(pipe,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous);
  return Task.Run(async()=>{using(server){await server.WaitForConnectionAsync();var h=Read(server,4);if(BitConverter.IsLittleEndian)Array.Reverse(h);var raw=Encoding.UTF8.GetString(Read(server,BitConverter.ToInt32(h,0)));
   if(!Regex.IsMatch(raw,"\\\"token\\\"\\s*:\\s*\\\"fixture\\\""))throw new Exception("authentication missing");
   var id=Regex.Match(raw,"\\\"id\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"").Groups[1].Value;
   if(scenario=="stall"){await Task.Delay(2600);return;}
   if(scenario=="bad-id")id="wrong";
   var body=Encoding.UTF8.GetBytes("{\"version\":1,\"id\":\""+id+"\",\"ok\":"+(scenario=="reject"?"false":"true")+",\"data\":{\"value\":7},\"error\":\"SECRET\"}");
   var size=BitConverter.GetBytes(scenario=="oversize"?65537:body.Length);if(BitConverter.IsLittleEndian)Array.Reverse(size);server.Write(size,0,4);
   if(scenario!="oversize")server.Write(body,0,body.Length);
  }});
 }
}
'@
$fixtureToken=Join-Path ([IO.Path]::GetTempPath()) ('veliq-view-'+[Guid]::NewGuid().ToString('N')+'.token')
[IO.File]::WriteAllText($fixtureToken,'fixture')
try {
 foreach($scenario in @('ok','bad-id','reject','oversize','stall')){
  $pipe='veliq-view-fixture-'+[Guid]::NewGuid().ToString('N')
  $task=[ServicesViewPipeFixture]::Serve($pipe,$scenario)
  $watch=[Diagnostics.Stopwatch]::StartNew()
  $result=Invoke-ViewRead 'status' $fixtureToken $pipe
  if($scenario -eq 'ok'){
   if(!$result.ok -or $result.data.value -ne 7){throw ('ROUNDTRIP_FAILED '+$result.error_code)}
  }else{
   if($result.ok -or $result.error_code -match 'SECRET'){throw ('REJECTION_FAILED '+$scenario)}
   if($scenario -eq 'stall' -and ($result.error_code -ne 'IPC_TIMEOUT' -or $watch.Elapsed.TotalSeconds -gt 4)){throw 'TIMEOUT_NOT_BOUNDED'}
  }
  [void]$task.GetAwaiter().GetResult()
 }
}finally{Remove-Item -LiteralPath $fixtureToken -Force}
Write-Output 'PASS services-view projection, freshness, missing data, mutation denial, authenticated frames and bounded timeout'
