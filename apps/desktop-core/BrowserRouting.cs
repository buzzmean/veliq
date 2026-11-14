using System.Collections.ObjectModel;
namespace Neexitlag.Desktop;
public sealed class ChromeActivationException(string message, string phase = "chrome.activation", string code = "CHROME_ACTIVATION_FAILED") : Exception(message) {
 public string Phase {get;}=phase; public string Code {get;}=code;
}
public sealed class BrowserRecoverySettings {public string CheckTarget {get;set;}="";public string CheckToken {get;set;}="";public string GuardFile {get;set;}="";public string Primary {get;set;}="";public string Executable {get;set;}="";public string ProfileId {get;set;}="";public string[] ProtectedDomains {get;set;}=[];public bool Strict {get;set;}}
public sealed class BrowserLaunch {public string RecoveryProgram {get;set;}="";public BrowserRecoverySettings RecoverySettings {get;set;}=new();public IEnumerable<string> UserArguments()=>Arguments.Where(p=>!p.StartsWith("--proxy-",StringComparison.Ordinal)&&p!="--no-proxy-server");public string[] RecoveryArguments {get;set;}=[]; public string HealthUrl {get;set;}=""; public string[] Arguments {get;set;}=[]; public string Address {get;set;}=""; public string Scope {get;set;}=""; }
public sealed class BrowserTransportSnapshot {public BrowserSilentActivation SilentActivation {get;set;}=new(); public bool PolicyReady {get;set;} public string ReadinessState {get;set;}="";public string LastError {get;set;}="";public string RecoveryAddress {get;set;}="";public string[] ReadyProfiles {get;set;}=[];public Dictionary<string,ulong> Failures {get;set;}=[];public bool Listening {get;set;}public bool Truncated {get;set;}public ulong Lost {get;set;}BrowserConnection[] records=[];public BrowserConnection[] Records {get=>records;set=>records=value??[];}}
public sealed class BrowserOwner {public uint Pid {get;set;} public ulong CreationTime {get;set;} public string Exe {get;set;}="";public string ProfileId {get;set;}="";}
public sealed class BrowserPlan {public FlowPolicyEvidence Policy {get;set;}=new();public string Probe {get;set;}="";public int HttpStatus {get;set;}}
public sealed class BrowserConnection {public string EvidenceSource {get;set;}="";public DateTimeOffset Started {get;set;}
 public string OpenFailure {get;set;}="";public ulong Id {get;set;}public BrowserOwner Owner {get;set;}=new();public string Domain {get;set;}="";public BrowserPlan Plan {get;set;}=new();public string Result {get;set;}="";public ulong SentBytes {get;set;}public ulong ReceivedBytes {get;set;}public bool Active {get;set;}
 public bool DirectPlusApplied {get;set;}
 public string Route=>(Result=="UPSTREAM_OPEN_FAILED"||Result=="ORIGIN_PLAN_FAILED"||Result=="BLOCK")?"BLOCK":Plan.Policy.Action=="DIRECT_PLUS"&&!DirectPlusApplied?"DIRECT+ (не подтверждён)" :Plan.Policy.Action=="RELAY_REQUIRED"?"RELAY_REQUIRED · "+Plan.Policy.RelayId:Plan.Policy.Action;
 public string Reason=>Plan.Policy.Reason;
 public string Outcome=>OpenFailure!=""?"OPEN: "+OpenFailure:Plan.Probe is "HTTP_SUCCESS" or "DNS_RELAY_HTTP_VERIFIED"?$"Origin HTTP {Plan.HttpStatus}; страница Chrome не проверена":(SentBytes>0&&ReceivedBytes>0?"Есть обмен; ":"")+"Origin probe: "+Plan.Probe+"; результат страницы не измерен";
 public string Traffic=>$"↑ {Text.Bytes(SentBytes)} / ↓ {Text.Bytes(ReceivedBytes)}";
}
public sealed partial class DesktopViewModel {
 public ObservableCollection<BrowserConnection> BrowserDomains {get;}=[];
 BrowserTransportSnapshot primaryBrowser=new();
 public string ChromePolicyState {get;private set;}="Chrome: policy ещё не настроена";
 public void ApplyBrowser(BrowserTransportSnapshot status){primaryBrowser=status;ApplyBrowserRecords(status);var next=!Optimizing?"Chrome: прямая сеть (оптимизация выключена)":browserHealth.FirstOrDefault(row=>row.Name=="Chrome") is {} chrome?"Chrome — "+chrome.State:"Chrome: "+status.SilentActivation.Notice;if(ChromePolicyState!=next){ChromePolicyState=next;Changed(nameof(ChromePolicyState));}}
 void ApplyBrowserRecords(BrowserTransportSnapshot status){
  // Only actual transport records are shown; no assumed success from TCP ACKs.
  Replace(BrowserDomains,status.Records.OrderByDescending(r=>r.Started).ThenByDescending(r=>r.Id).Take(32));
  foreach(var app in Applications)app.ApplyBrowserRecords(status);
 }
 public void ApplyRecovery(BrowserTransportSnapshot recovery){
  BrowserConnection[] original=Available?primaryBrowser.Records:[];
  ApplyBrowserRecords(new(){Listening=primaryBrowser.Listening&&Available||recovery.Listening,Records=original.Concat(recovery.Records.Where(r=>r.EvidenceSource=="RECOVERY_DIRECT"&&r.Plan.Policy.Action=="DIRECT")).ToArray(),Lost=primaryBrowser.Lost+recovery.Lost,Truncated=primaryBrowser.Truncated||recovery.Truncated});
 }
 public async Task VerifyChromeAsync(Profile profile,BrowserLaunch launch,CancellationToken ct=default){
  if(!launch.HealthUrl.StartsWith("http://neexitlag-health.invalid/ready/",StringComparison.Ordinal))throw new ChromeActivationException(Text.Get("ChromeActivationFailed"));
  for(int i=0;i<225;i++){
   try{var proof=await client.Call<System.Text.Json.JsonElement>("browser.confirm",new{profile_id=profile.Id,health_url=launch.HealthUrl},ct);if(!proof.TryGetProperty("ready",out var ready)||ready.ValueKind!=System.Text.Json.JsonValueKind.True)throw new ChromeActivationException(Text.Get("ChromeActivationFailed"));return;}
   catch(ServiceException e) when(e.Failure==ServiceFailure.Rejected){await Task.Delay(200,ct);}
  }
  var diagnostics=await ChromeStatusAsync(ct);
  throw new ChromeActivationException(Text.Get("ChromeActivationFailed")+" "+string.Join(", ",diagnostics.Failures.Where(p=>p.Value>0).Select(p=>p.Key).Take(8)));
 }
 public async Task ActivatePreparedChromeAsync(Profile original,BrowserLaunch launch,Func<Task> probe,Func<Task> launchUserChrome,CancellationToken ct=default,Action<string>? phase=null){
  await probe();
  phase?.Invoke("browser.confirm");
  await VerifyChromeAsync(original,launch,ct);
  phase?.Invoke("profile.set");
  await CommitChromeAsync(original,ct);
  phase?.Invoke("chrome.launch");
  await launchUserChrome();
 }
 public async Task RestoreOptimizationAsync(bool enabled,CancellationToken ct=default){
  var status=await client.Call<Snapshot>("optimize",new{enabled},ct);
  if(status.Optimizing!=enabled)throw new ChromeActivationException(Text.Get("ChromeRollbackFailed"));
  await RefreshAsync(ct);
 }
 public async Task CommitChromeAsync(Profile original,CancellationToken ct=default){
  var copy=original.Copy();copy.Mode="AUTO";copy.PolicyData ??= new();copy.PolicyData["browser_transport"]=System.Text.Json.JsonSerializer.SerializeToElement("");
  await client.Call<Profile[]>("profile.set",copy,ct);
  var status=await client.Call<Snapshot>("optimize",new{enabled=true},ct);
  if(!status.Optimizing)throw new ChromeActivationException(Text.Get("ChromeActivationFailed"));
  if(!status.Settings.Automatic)throw new ChromeActivationException(Text.Get("ChromeAutomaticDisabled"));
  await RefreshAsync(ct);
 }
 public async Task RestoreChromeAsync(Profile original,CancellationToken ct=default){
  if(NativeBrowser(original)){await EnableNativeBrowserAsync(original,ct);return;}
  var copy=original.Copy();if(copy.Mode=="AUTO"){
   copy.Mode="DIRECT";
   if(copy.PolicyData is {} data && data.TryGetValue("rules",out var rules) && rules.ValueKind==System.Text.Json.JsonValueKind.Array && rules.GetArrayLength()>0){
    data["browser_recovery_rules"]=rules.Clone();data["rules"]=System.Text.Json.JsonSerializer.SerializeToElement(Array.Empty<object>());
   }
  }
  await client.Call<Profile[]>("profile.set",copy,ct);await RefreshAsync(ct);
 }
 public Task<BrowserTransportSnapshot> ChromeStatusAsync(CancellationToken ct=default)=>client.Call<BrowserTransportSnapshot>("browser.status",cancellationToken:ct);
 public Task<ProcessIdentity[]> ChromeProcessesAsync(string exe,CancellationToken ct=default)=>client.Call<ProcessIdentity[]>("processes",new{executables=new[]{exe}},ct);
 public Task<BrowserLaunch> PrepareChromeAsync(Profile profile,string directory,CancellationToken ct=default,string recoveryAddress=""){
  if(!profile.Executables.Any(p=>string.Equals(p.Replace('\\','/').Split('/').Last(),"chrome.exe",StringComparison.OrdinalIgnoreCase)))throw new InvalidOperationException(Text.Get("SelectChromeAuto"));
  return client.Call<BrowserLaunch>("browser.prepare",new{profile_id=profile.Id,directory,recovery_address=recoveryAddress},ct);
 }
}

public sealed partial class ApplicationRow {
 internal void ApplyBrowserRecords(BrowserTransportSnapshot status){
  if(!status.Listening||Profile.Mode!="AUTO"||!Profile.Executables.Any(p=>p.Replace('\\','/').Split('/').Last().Equals("chrome.exe",StringComparison.OrdinalIgnoreCase)))return;
  var live=status.Records.Where(r=>r.Owner.ProfileId==Profile.Id&&r.Active&&(r.SentBytes>0||r.ReceivedBytes>0)).ToArray();
  var previous=DisplayValues();
  route=live.Length==0?Text.Get("NoData"):string.Join(", ",live.Select(r=>r.Route).Distinct());
  UserStatus=Text.Get("ChromeRoutesByDomain")+" · "+route;
  if(status.Truncated||status.Lost>0)UserStatus=Text.Get("PartialRouteEvidence")+" "+UserStatus;
  Tcp=route;NotifyDisplayChanges(previous);
 }
}
