using Microsoft.Win32;
using System.Text.Json;
namespace Neexitlag.Desktop;
// Current-user Chrome platform policy only. Never WinINET/WinHTTP/system proxy.
internal static class ChromePolicy {
 const string Key=@"Software\Policies\Google\Chrome";
 internal static string? TestStatePath;
 static string State=>TestStatePath??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"VELIQ","chrome-proxy-policy.json");
 internal static string CreateValue(string[] args){
  var pac=args.Single(p=>p.StartsWith("--proxy-pac-url=",StringComparison.Ordinal)).Substring("--proxy-pac-url=".Length);
  return JsonSerializer.Serialize(new{ProxyMode="pac_script",ProxyPacUrl=pac,ProxyPacMandatory=true});
 }
 internal static void Install(string[] args,string[]? recoveryArgs=null){
  var json=CreateValue(args);
  Write(new Owned{Value=json,OnlineValue=recoveryArgs is null?null:json,RecoveryValue=recoveryArgs is null?null:CreateValue(recoveryArgs),WasOptimizing=recoveryArgs is not null});
 }
 static void Write(Owned value){
  var json=value.Value;
  Check();
  using var current=Registry.CurrentUser.CreateSubKey(Key);
  var oldState=File.Exists(State)?File.ReadAllText(State):null;
  value.PreviousValue=current.GetValue("ProxySettings") as string;
  // Persist ownership before changing the registry. There is no preexisting
  // policy to overwrite: foreign settings are always refused, never copied.
  Directory.CreateDirectory(Path.GetDirectoryName(State)!);
  var pending=State+".tmp";File.WriteAllText(pending,JsonSerializer.Serialize(value));File.Move(pending,State,true);
  try{current.SetValue("ProxySettings",json,RegistryValueKind.String);BrowserNativePolicy.RequestRefresh();}
  catch{if(oldState is null)File.Delete(State);else File.WriteAllText(State,oldState);throw;}
 }
 internal static void Check(){
  using(var machine=Registry.LocalMachine.OpenSubKey(Key))if(new[]{"ProxySettings","ProxyMode","ProxyPacUrl","ProxyServer"}.Any(p=>machine?.GetValue(p)is not null))throw new InvalidOperationException(Text.Get("ChromeProxyManaged"));
  using var current=Registry.CurrentUser.OpenSubKey(Key);
  var present=current?.GetValue("ProxySettings");
  if(present is not null && present is not string)throw new InvalidOperationException(Text.Get("ChromeProxyManaged"));
  var previous=present as string;
  Owned? owned=null;
  if(File.Exists(State))owned=JsonSerializer.Deserialize<Owned>(File.ReadAllText(State));
  var recognized=owned is not null&&new[]{owned.Value,owned.OnlineValue,owned.RecoveryValue,owned.PreviousValue}.Any(v=>v is not null&&v==previous);
  if(previous is not null&&!recognized||new[]{"ProxyMode","ProxyPacUrl","ProxyServer"}.Any(p=>current?.GetValue(p)is not null))throw new InvalidOperationException(Text.Get("ChromeProxyManaged"));
 }
 internal static string ClosedGuard(Profile profile){
  var domains=new List<string>{"chatgpt.com","openai.com","oaistatic.com","oaiusercontent.com","chat.com"};bool strict=false;
  foreach(var key in new[]{"rules","browser_recovery_rules"})if(profile.PolicyData is {} data && data.TryGetValue(key,out var rules) && rules.ValueKind==JsonValueKind.Array){
   foreach(var rule in rules.EnumerateArray()){
    if(rule.TryGetProperty("action",out var action)&&action.GetString()=="DIRECT")continue;
    if(!rule.TryGetProperty("domains",out var names)||names.ValueKind!=JsonValueKind.Array||names.GetArrayLength()==0){strict=true;continue;}
    foreach(var name in names.EnumerateArray())if(name.GetString() is string host)domains.Add(host);
   }
  }
  var script="var guarded="+JsonSerializer.Serialize(domains)+";var strict="+(strict?"true":"false")+";function FindProxyForURL(url,host){host=host.toLowerCase().replace(/\\.$/,'');for(var i=0;i<guarded.length;i++){var d=guarded[i].toLowerCase().replace(/\\.$/,'');if(host===d||host.slice(-(d.length+1))==='.'+d)return 'PROXY fail-closed.neexitlag.invalid:9';}return strict?'PROXY fail-closed.neexitlag.invalid:9':'DIRECT';}";
  return "data:application/x-ns-proxy-autoconfig;base64,"+Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(script));
 }
 internal static void Guard(Profile profile)=>Install(["--proxy-pac-url="+ClosedGuard(profile)]);
 internal static string RecoveryPAC(string data){
  const string prefix="data:application/x-ns-proxy-autoconfig;base64,";
  if(!data.StartsWith(prefix,StringComparison.Ordinal))throw new InvalidOperationException("Owned inline Chrome PAC required");
  var script=System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(data[prefix.Length..]));
  const string marker="// NEEXITLAG_RECOVERY_V1";
  if(script.Contains(marker,StringComparison.Ordinal))return data;
  if(!script.Contains("var protectedSuffixes=",StringComparison.Ordinal)){if(script.Contains("var guarded=",StringComparison.Ordinal))return data;throw new InvalidOperationException(Text.Get("ChromeActivationFailed"));}
  script+="\n"+marker+"\nFindProxyForURL=(function(online){return function(url,host){host=host.toLowerCase().replace(/\\.$/,'');if(strictProxy)return online(url,host);for(var i=0;i<protectedSuffixes.length;i++){var d=protectedSuffixes[i].toLowerCase().replace(/\\.$/,'');if(host===d||host.slice(-(d.length+1))==='.'+d)return online(url,host);}return 'DIRECT';};})(FindProxyForURL);";
  return prefix+Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(script));
 }
 internal static void Recover(){
  if(!File.Exists(State))return;
  Check();
  var owned=JsonSerializer.Deserialize<Owned>(File.ReadAllText(State))??throw new InvalidOperationException("Chrome ownership state missing");
  using var parsed=JsonDocument.Parse(owned.Value);
  var pac=RecoveryPAC(parsed.RootElement.GetProperty("ProxyPacUrl").GetString()!);
  Install(["--proxy-pac-url="+pac]);
 }
 internal static bool Applied{get{if(!File.Exists(State))return false;var owned=JsonSerializer.Deserialize<Owned>(File.ReadAllText(State));using var key=Registry.CurrentUser.OpenSubKey(Key);return Equals(key?.GetValue("ProxySettings"),owned?.Value);}}
 internal static bool Monitored=>File.Exists(State)&&JsonSerializer.Deserialize<Owned>(File.ReadAllText(State))?.OnlineValue is not null;
 internal static bool Suspended=>File.Exists(State)&&JsonSerializer.Deserialize<Owned>(File.ReadAllText(State))?.Temporary==true;
 internal static void Suspend(bool wasOptimizing){
  if(!Monitored)return;
  var owned=JsonSerializer.Deserialize<Owned>(File.ReadAllText(State))!;
  if(owned.Temporary||owned.RecoveryValue is null)return;
  owned.Temporary=true;owned.WasOptimizing=wasOptimizing||owned.WasOptimizing;SaveState(owned);
 }
 static void SaveState(Owned owned){Check();var pending=State+".tmp";File.WriteAllText(pending,JsonSerializer.Serialize(owned));File.Move(pending,State,true);}
 internal static void RecordOptimization(bool enabled){
  if(!Monitored||Suspended)return;
  var owned=JsonSerializer.Deserialize<Owned>(File.ReadAllText(State))!;
  if(owned.WasOptimizing==enabled)return;
  Check();owned.WasOptimizing=enabled;
  var pending=State+".tmp";File.WriteAllText(pending,JsonSerializer.Serialize(owned));File.Move(pending,State,true);
 }
 internal static bool Resume(){
  var owned=JsonSerializer.Deserialize<Owned>(File.ReadAllText(State))!;
  if(!owned.Temporary||owned.OnlineValue is null)return false;
  owned.Temporary=false;SaveState(owned);return owned.WasOptimizing;
 }
 internal static void Remove(){
  if(!File.Exists(State))return;
  var owned=JsonSerializer.Deserialize<Owned>(File.ReadAllText(State))?.Value;
  using var current=Registry.CurrentUser.OpenSubKey(Key,true);
  if(current?.GetValue("ProxySettings") is object actual&&(!Equals(actual,owned)))throw new InvalidOperationException(Text.Get("ChromeProxyManaged"));
  current?.DeleteValue("ProxySettings",false);BrowserNativePolicy.RequestRefresh();File.Delete(State);
 }
 sealed class Owned {public string Value{get;set;}="";public string? PreviousValue{get;set;}public string? OnlineValue{get;set;}public string? RecoveryValue{get;set;}public bool Temporary{get;set;}public bool WasOptimizing{get;set;}}
}
