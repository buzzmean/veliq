# Portable fixture for the actual PowerShell IPC framing/timeout client. No Windows capture is simulated.
param([string]$WorkDirectory=(Join-Path $PSScriptRoot '..\..\work\ps-ipc'))
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\..\tools\windows\common.ps1')
New-Item -ItemType Directory -Force $WorkDirectory|Out-Null
$token=Join-Path (Resolve-Path $WorkDirectory).Path 'fixture.token'
[IO.File]::WriteAllText($token,('a'*64))
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
public static class PipeFixture {
 static async Task<byte[]> Read(Stream stream,int length){var b=new byte[length];int offset=0;while(offset<length){int n=await stream.ReadAsync(b,offset,length-offset);if(n==0)throw new IOException("closed");offset+=n;}return b;}
 public static Task Serve(string scenario){
  var server=new NamedPipeServerStream("neexitlag-v1",PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous);
  return Task.Run(async()=>{using(server){await server.WaitForConnectionAsync();var h=await Read(server,4);if(BitConverter.IsLittleEndian)Array.Reverse(h);var length=BitConverter.ToInt32(h,0);using(var doc=JsonDocument.Parse(await Read(server,length))){var root=doc.RootElement;if(root.GetProperty("token").GetString()!=new string('a',64)||root.GetProperty("version").GetInt32()!=1)throw new Exception("bad request");if(scenario=="stall"){await Task.Delay(7000);return;}var id=scenario=="bad-id"?"wrong":root.GetProperty("id").GetString();var b=Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new {version=1,id=id,ok=true,data=new {message="fixture"}}));var header=BitConverter.GetBytes(b.Length);if(BitConverter.IsLittleEndian)Array.Reverse(header);await server.WriteAsync(header,0,4);await server.WriteAsync(b,0,b.Length);}}});
 }
}
'@
try {
 $task=[PipeFixture]::Serve('ok')
 $reply=Invoke-ServiceIPC 'fixture.status' $null $token
 if($reply.message -ne 'fixture'){throw 'IPC response did not round trip'}
 [void]$task.GetAwaiter().GetResult()
 Write-Output 'PASS actual PowerShell IPC frame round trip'
 $task=[PipeFixture]::Serve('bad-id');$rejected=$false
 try{Invoke-ServiceIPC 'fixture.status' $null $token|Out-Null}catch{$rejected=$_.Exception.Message -like '*ID mismatch*'}
 [void]$task.GetAwaiter().GetResult();if(!$rejected){throw 'Mismatched response ID accepted'}
 Write-Output 'PASS IPC response ID mismatch rejection'
 $task=[PipeFixture]::Serve('stall');$watch=[Diagnostics.Stopwatch]::StartNew();$rejected=$false
 try{Invoke-ServiceIPC 'fixture.status' $null $token|Out-Null}catch{$rejected=$_.Exception.Message -like '*timeout*'}
 if(!$rejected -or $watch.Elapsed.TotalSeconds -gt 10){throw 'IPC timeout did not bound stalled response'}
 [void]$task.GetAwaiter().GetResult()
 Write-Output 'PASS bounded IPC timeout'
} finally {Remove-Item $token -Force}
