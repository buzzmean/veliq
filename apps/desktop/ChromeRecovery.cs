using System.Diagnostics;
using System.Text.Json;
using System.Net;
namespace Neexitlag.Desktop;

// A standard-user child of the installed service binary; it never loads the
// service manifest, driver or credentials. Only its inherited stdin config pipe
// is writable by this GUI. EOF stops it. The PAC's secondary port stays stable.
internal sealed class ChromeRecovery : IDisposable {
 sealed class Saved { public string Program {get;set;}="";public string MetadataToken {get;set;}="";public int ProcessId {get;set;}public long CreationTime {get;set;} public string Address {get;set;}="";public BrowserRecoverySettings Settings {get;set;}=new(); }
 static readonly JsonSerializerOptions Json=new(){PropertyNamingPolicy=JsonNamingPolicy.SnakeCaseLower,PropertyNameCaseInsensitive=true};
 static string State=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"VELIQ","chrome-recovery.json");
 Process? process;Task? stderr;Saved? saved;string metadataToken="";
 readonly SemaphoreSlim startGate=new(1,1),protocolGate=new(1,1);
 public string Address {get;private set;}="";
 public bool Running=>process is {} p&&!p.HasExited;
 static string InstalledProgram=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"VELIQ","veliq-service.exe");
 public async Task StartAsync(CancellationToken ct){await startGate.WaitAsync(ct);try{await StartCoreAsync(ct);}finally{startGate.Release();}}
 async Task StartCoreAsync(CancellationToken ct){
  if(Running)return;
  if(File.Exists(State)&&new FileInfo(State).Length>262144)throw new ChromeActivationException("Chrome recovery state exceeds bound");
  if(File.Exists(State))saved=JsonSerializer.Deserialize<Saved>(await File.ReadAllTextAsync(State,ct),Json);
  var program=InstalledProgram;
  if(!File.Exists(program))throw new ChromeActivationException("VELIQ Chrome recovery requires the installed service executable");
  ushort port=0;
  if(saved is {} previous){
   if(!Path.GetFullPath(previous.Program).Equals(Path.GetFullPath(program),StringComparison.OrdinalIgnoreCase)||!IPEndPoint.TryParse(previous.Address,out var endpoint)||!IPAddress.Loopback.Equals(endpoint.Address))throw new ChromeActivationException("Invalid owned Chrome recovery state");
   port=checked((ushort)endpoint.Port);
  }
  DisposeProcess();
  var info=new ProcessStartInfo(program){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
  info.ArgumentList.Add("--chrome-recovery");info.ArgumentList.Add("--recovery-port="+port);
  process=Process.Start(info)??throw new ChromeActivationException("Chrome recovery process failed to start");
  stderr=DrainAsync(process.StandardError);
  using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(8));
  var first=await ReadAsync(timeout.Token);
  if(!first.TryGetProperty("address",out var address)||!IPEndPoint.TryParse(address.GetString(),out var local)||!IPAddress.Loopback.Equals(local.Address)||local.Port==0)throw new ChromeActivationException("Invalid Chrome recovery listener acknowledgement");
  if(!first.TryGetProperty("metadata_token",out var token)||token.GetString() is not string secret||secret.Length!=64)throw new ChromeActivationException("Invalid recovery metadata acknowledgement");
  metadataToken=secret;Address=local.ToString();
  if(saved is {} existing)await ConfigureAsync(existing.Settings,ct);
 }
 public async Task ConfigureAsync(BrowserRecoverySettings cfg,CancellationToken ct){await protocolGate.WaitAsync(ct);try{await ConfigureCoreAsync(cfg,ct);}finally{protocolGate.Release();}}
 async Task ConfigureCoreAsync(BrowserRecoverySettings cfg,CancellationToken ct){
  if(!Running)throw new ChromeActivationException("Chrome recovery listener is not running");
  using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(8));
  await process!.StandardInput.WriteLineAsync(JsonSerializer.Serialize(cfg,Json).AsMemory(),timeout.Token);await process.StandardInput.FlushAsync(timeout.Token);
  var ack=await ReadAsync(timeout.Token);
  if(!ack.TryGetProperty("ready",out var ready)||ready.ValueKind!=JsonValueKind.True)throw new ChromeActivationException("Chrome recovery configuration rejected");
  saved=new(){Program=InstalledProgram,Address=Address,Settings=cfg,MetadataToken=metadataToken,ProcessId=process.Id,CreationTime=process.StartTime.ToUniversalTime().ToFileTimeUtc()};
  Directory.CreateDirectory(Path.GetDirectoryName(State)!);
  var pending=State+".tmp";await File.WriteAllTextAsync(pending,JsonSerializer.Serialize(saved,Json),ct);File.Move(pending,State,true);
 }
 async Task<JsonElement> ReadAsync(CancellationToken ct){
  var reader=process!.StandardOutput;var value=new System.Text.StringBuilder();
  var one=new char[1];
  while(value.Length<65536){var n=await reader.ReadAsync(one.AsMemory(),ct);if(n==0)throw new ChromeActivationException("Chrome recovery exited before acknowledgement");if(one[0]=='\n')return JsonSerializer.Deserialize<JsonElement>(value.ToString());if(one[0]!='\r')value.Append(one[0]);}
  throw new ChromeActivationException("Chrome recovery acknowledgement exceeded bound");
 }
 static async Task DrainAsync(StreamReader reader){try{var buffer=new char[1024];while(await reader.ReadAsync(buffer)>0){}}catch(IOException){}catch(ObjectDisposedException){} }
 void DisposeProcess(){
  if(process is not {} p)return;
  try{p.StandardInput.Close();if(!p.HasExited&&!p.WaitForExit(2000))p.Kill(entireProcessTree:true);}catch(InvalidOperationException){}finally{p.Dispose();process=null;Address="";}
 }
 public async Task<BrowserTransportSnapshot> SnapshotAsync(CancellationToken ct){
  await protocolGate.WaitAsync(ct);
  try{
   if(!Running)throw new ChromeActivationException("Chrome recovery process unavailable");
   using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(3));
   await process!.StandardInput.WriteLineAsync("{\"op\":\"status\"}".AsMemory(),timeout.Token);await process.StandardInput.FlushAsync(timeout.Token);
   var reply=await ReadAsync(timeout.Token);
   return reply.Deserialize<BrowserTransportSnapshot>(Json)??throw new ChromeActivationException("Invalid recovery metadata");
  }finally{protocolGate.Release();}
 }

 public void Dispose()=>DisposeProcess();
}
