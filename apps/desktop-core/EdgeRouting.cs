using System.Collections.ObjectModel;
using System.Text.Json;
namespace Veliq.Desktop;

public sealed class EdgeTransportStatus {
 public BrowserSilentActivation SilentActivation {get;set;}=new();
 public int ActivationVersion {get;set;}
 public bool RollbackGuardActive {get;set;}
 public bool Listening {get;set;} public bool PolicyReady {get;set;} public bool Truncated {get;set;} public ulong Lost {get;set;}
 public string TransportMode {get;set;}=""; public string PacNonceReadiness {get;set;}=""; public bool OwnedGuardInstalled {get;set;}
 public string ReadinessState {get;set;}=""; public string PendingProfile {get;set;}="";
 public string LastError {get;set;}=""; public string RecoveryAddress {get;set;}=""; public string[] ReadyProfiles {get;set;}=[];
 public BrowserConnection[] Records {get;set;}=[];
 public BrowserTransportSnapshot Snapshot()=>new(){Listening=Listening,RecoveryAddress=RecoveryAddress,ReadyProfiles=ReadyProfiles,Records=Records,Truncated=Truncated,Lost=Lost};
}
public sealed class EdgeDomainRow(BrowserConnection connection) {
 public string Domain=>connection.Domain; public string Route=>connection.Route; public string Reason=>connection.Reason;
 public string Outcome=>connection.Outcome.Replace("страница Chrome", "страница Edge", StringComparison.Ordinal);
}
public sealed partial class DesktopViewModel {
 public ObservableCollection<EdgeDomainRow> EdgeDomains {get;}=[];
 public string EdgeState {get;private set;}="Edge: не настроен";
 public async Task<Profile?> EnsureEdgeProfileAsync(IReadOnlyList<InstalledBrowser> installed,CancellationToken ct=default){
  var edge=installed.FirstOrDefault(b=>b.Id=="edge"&&b.AutoSupported);
  if(edge is null)return null;
  var existing=await client.Call<Profile[]>("profiles",cancellationToken:ct);
  if(existing.Any(BrowserCatalog.IsEdge))return null;
  await RequireEdgeServiceAsync(ct);
  if(!await AddApplicationAsync(edge.ExePath,ct))return null;
  return Applications.Select(a=>a.Profile).FirstOrDefault(BrowserCatalog.IsEdge);
 }
 public async Task RequireEdgeServiceAsync(CancellationToken ct=default){
  var status=await EdgeStatusAsync(ct);
  if(status.ActivationVersion<3)throw new EdgeActivationException("edge.status","EDGE_IPC_UNSUPPORTED","Сначала обновите службу вместе с GUI: нужна служба с исправленным nonce и автоматическим guarded откатом при отказе (activation_version=3).");
 }
 public Task<BrowserLaunch> PrepareEdgeAsync(Profile profile,string directory,string recovery,CancellationToken ct=default){
  if(!BrowserCatalog.IsEdge(profile))throw new InvalidOperationException("Выберите профиль Microsoft Edge");
  return EdgeCall<BrowserLaunch>("edge.prepare",new{profile_id=profile.Id,directory,recovery_address=recovery},ct);
 }
 public Task<JsonElement> EdgePolicyAsync(Profile profile,string operation,CancellationToken ct=default)=>EdgeCall<JsonElement>("edge.policy",new{profile_id=profile.Id,operation},ct);
 public Task<EdgeTransportStatus> EdgeStatusAsync(CancellationToken ct=default)=>client.Call<EdgeTransportStatus>("edge.status",cancellationToken:ct);
 public async Task ConfirmEdgeAsync(Profile original,BrowserLaunch launch,CancellationToken ct=default){
  if(!launch.HealthUrl.StartsWith("http://neexitlag-health.invalid/ready/",StringComparison.Ordinal))throw new InvalidOperationException("Некорректная проверка готовности Edge");
  var proof=await EdgeCall<JsonElement>("edge.confirm",new{profile_id=original.Id,health_url=launch.HealthUrl},ct);
  if(!proof.TryGetProperty("ready",out var ready)||ready.ValueKind!=JsonValueKind.True)throw new InvalidOperationException("Edge PAC не подтверждён");
 }
 public async Task OptimizeEdgeAsync(CancellationToken ct=default){
  var status=await EdgeCall<Snapshot>("optimize",new{enabled=true},ct);
  if(!status.Optimizing)throw new EdgeActivationException("optimize","EDGE_OPERATION_FAILED","Служба не подтвердила включение перехвата.");
  await RefreshAsync(ct);
 }
 public async Task CommitEdgeAsync(Profile original,CancellationToken ct=default){
  var copy=original.Copy();copy.Mode="AUTO";
  copy.PolicyData ??= new();copy.PolicyData["browser_transport"]=JsonSerializer.SerializeToElement("");copy.PolicyData["app_preset"]=JsonSerializer.SerializeToElement("edge-sites");
  await EdgeCall<Profile[]>("profile.set",copy,ct);
  await RefreshAsync(ct);
 }
 public Task<System.Text.Json.JsonElement> GuardEdgeAsync(CancellationToken ct=default)=>EdgeCall<System.Text.Json.JsonElement>("edge.policy",new{operation="guard"},ct);
 public async Task<JsonElement> RestoreEdgeAsync(Profile original,CancellationToken ct=default){
  // Inline guard must protect all requests, including subresources, before native disarm.
  var applied=await EdgePolicyAsync(original,"guard",ct);
  await RestoreChromeAsync(original,ct); // existing profile-preserving transaction
  return applied;
 }
 public void ApplyEdgePolicyState(EdgeTransportStatus status){
  EdgeState=!Optimizing?"Edge: прямая сеть (оптимизация выключена)":browserHealth.FirstOrDefault(row=>row.Name=="Edge") is {} edge?"Edge — "+edge.State:status.TransportMode=="NATIVE_ARMED_PAC_GUARD"&&status.ReadinessState=="NATIVE_TUNNEL_OBSERVED"?"Edge: есть обмен через native upstream; проверка страницы и PAC отдельно":status.SilentActivation.State=="POLICY_PENDING_BROWSER_REFRESH"?"Edge: настройки записаны, ожидаем подхват браузером":status.Listening&&status.PolicyReady?"Edge: маршруты подготовлены; доступность сайтов проверяется отдельно":"Edge: подготавливаем маршруты, повторная проверка автоматически";
  if(status.Listening&&status.PolicyReady)ClearBrowserPreparationIssue();
  Changed(nameof(EdgeState));
 }
 public void ApplyEdge(BrowserTransportSnapshot status){
  Replace(EdgeDomains,status.Records.OrderByDescending(r=>r.Started).ThenByDescending(r=>r.Id).Take(32).Select(r=>new EdgeDomainRow(r)));
  EdgeState=!Optimizing?"Edge: прямая сеть (оптимизация выключена)":status.Listening?"Edge: проверяем готовность маршрутов":"Edge: подготавливаем маршруты";
  Changed(nameof(EdgeState));
  foreach(var row in Applications.Where(a=>BrowserCatalog.IsEdge(a.Profile)))row.ApplyEdgeRecords(status);
 }
}
public sealed partial class ApplicationRow {
 internal void ApplyEdgeRecords(BrowserTransportSnapshot status){
  if(!BrowserCatalog.IsEdge(Profile)||Profile.Mode!="AUTO")return;
  var live=status.Records.Where(r=>r.Owner.ProfileId==Profile.Id&&r.Active&&(r.SentBytes>0||r.ReceivedBytes>0)).ToArray();
  route=live.Length==0?Text.Get("NoData"):string.Join(", ",live.Select(r=>r.Route).Distinct());
  UserStatus="Edge · маршруты по доменам · "+route;
  if(status.Truncated||status.Lost>0)UserStatus=Text.Get("PartialRouteEvidence")+" "+UserStatus;
  Tcp=route;Changed("");
 }
}
