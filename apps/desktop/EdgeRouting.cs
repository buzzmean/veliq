using System.Diagnostics;
using System.Text.Json;
using System.Windows;
namespace Veliq.Desktop;

public partial class MainWindow {
 readonly EdgeRoutingRecovery edgeRecovery=new();
 bool edgeActivating,edgeMonitoring,edgeLifetimeHook,edgeNeedsActivation;
 static bool EdgePending(Profile p)=>p.PolicyData is {} data&&data.TryGetValue("app_preset",out var value)&&value.ValueKind==JsonValueKind.String&&value.GetString()=="edge-sites-pending";
 static bool EdgeSites(Profile p)=>BrowserCatalog.IsEdge(p)&&p.PolicyData is {} data&&data.TryGetValue("app_preset",out var v)&&v.ValueKind==JsonValueKind.String&&v.GetString()=="edge-sites";
 async Task EnsureEdgeCoverageAsync(IReadOnlyList<InstalledBrowser> installed){
  if(!edgeLifetimeHook){Closed+=(_,_)=>edgeRecovery.Dispose();edgeLifetimeHook=true;}
  try{
   var created=await model.EnsureEdgeProfileAsync(installed,lifetime.Token);
   if(created is not null){await ActivateEdgeSites(created);return;}
   // Existing MANUAL/DIRECT/custom profiles remain unchanged. Previously opted-in
   // AUTO resumes only after its own policy/readiness has been verified.
   foreach(var row in model.Applications.Where(r=>(EdgeSites(r.Profile)||EdgePending(r.Profile))&&r.Profile.Mode=="AUTO").ToArray()){
    var status=await model.EdgeStatusAsync(lifetime.Token);
    await edgeRecovery.StartAsync(lifetime.Token);
    if(!edgeRecovery.Configured||status.RecoveryAddress!=edgeRecovery.Address||!status.Listening||!status.PolicyReady||!status.ReadyProfiles.Contains(row.Profile.Id))await ActivateEdgeSites(row.Profile.Copy());
   }
  }catch(Exception error)when(!lifetime.IsCancellationRequested){model.ReportActionFailure(EdgeErrors.Wrap("edge.prepare",error));}
 }
 async void OpenEdgeSites(object sender,RoutedEventArgs args)=>await Execute(async()=>{
  var profile=EdgeProfileSelection.Select((AppGrid.SelectedItem as ApplicationRow)?.Profile,model.Applications.Select(r=>r.Profile));
  profile ??= await model.EnsureEdgeProfileAsync(BrowserDiscovery.Installed(),lifetime.Token);
  if(profile is null)throw new EdgeActivationException("edge.prepare","EDGE_PROFILE_NOT_FOUND","Установленный Microsoft Edge не найден.");
  await model.OptimizeAsync(true,lifetime.Token);
  if(!await ActivateEdgeSites(profile))return;
  // The regular optimization transaction still validates BOTH browser lanes.
  try{await model.OptimizeEdgeAsync(lifetime.Token);}catch(Exception error){var failure=EdgeErrors.Wrap("optimize",error);await model.RecordEdgeFailureAsync(profile,failure,lifetime.Token);throw failure;}
 });
 async void DisableEdgeSites(object sender,RoutedEventArgs args)=>await Execute(async()=>{
  var profiles=model.Applications.Where(r=>EdgeSites(r.Profile)||EdgePending(r.Profile)).Select(r=>r.Profile.Copy()).ToArray();
  // The service owns its journal even if the application profile was deleted.
  var applied=await model.GuardEdgeAsync(lifetime.Token);
  foreach(var p in profiles)applied=DesktopViewModel.NativeBrowser(p)?await model.DisableNativeBrowserAsync(p,lifetime.Token):await model.RestoreEdgeAsync(p,lifetime.Token);
  edgeRecovery.Dispose();edgeNeedsActivation=true;model.ApplyEdgePolicyState(new());
  var ordinary=applied.TryGetProperty("ordinary_direct",out var allowed)&&allowed.ValueKind==JsonValueKind.True;
  model.SetNotice("Рабочий PAC Edge заменён защитным: "+(ordinary?"обычные сайты DIRECT; защищённые домены закрыты до успешной активации.":"строгие/custom ограничения сохранены.")+" ProxySettings остаётся ради защиты всех запросов, включая подресурсы. Чужая политика и Chrome не изменены. Новая политика применяется браузером без управления его процессами.");
 });
 async Task<bool> ActivateEdgeSites(Profile original){
  if(edgeActivating)return false;edgeActivating=true;
  var phase="edge.prepare";
  try{
   var ticket=model.CaptureBrowserPreparation();
   await model.RequireEdgeServiceAsync(lifetime.Token);
   model.CheckBrowserPreparation(ticket);
   var exe=original.Executables.FirstOrDefault(p=>p.Replace('\\','/').Split('/').Last().Equals("msedge.exe",StringComparison.OrdinalIgnoreCase));
   if(exe is null||!Path.IsPathFullyQualified(exe)||!File.Exists(exe))throw new EdgeActivationException(phase,"EDGE_CONFIGURATION_INVALID","Требуется полный путь установленного Edge.");
   phase="edge.recovery";await edgeRecovery.StartAsync(lifetime.Token);
   model.CheckBrowserPreparation(ticket);
   phase="edge.prepare";
   var directory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Microsoft","Edge","User Data");
   var launch=await model.PrepareEdgeAsync(original,directory,edgeRecovery.Address,lifetime.Token);
   model.CheckBrowserPreparation(ticket);
   launch.RecoverySettings.Executable=exe;
   await edgeRecovery.ConfigureAsync(launch.RecoverySettings,lifetime.Token);
   model.CheckBrowserPreparation(ticket);
   phase="edge.silent.apply";await model.ApplySilentBrowserAsync(original,true,lifetime.Token);
   BrowserNativePolicy.RequestRefresh();silentPolicyRefreshRequested=true;
   edgeNeedsActivation=false;model.SetNotice(BrowserSilentActivation.PendingNotice);return true;
  }catch(BrowserPreparationDeferredException error){model.ReportBrowserPreparationFailure(error,phase);return false;}
  catch(Exception error){
   // Failed prepare/apply never removes an existing owned guard or kills a browser.
   var failure=EdgeErrors.Wrap(phase,error);model.ReportActionFailure(failure);throw failure;
  }finally{edgeActivating=false;}
 }
 async Task MonitorEdgeTransportAsync(){
 if(!model.Available || model.Activation?.Status.CapturePermitted==false || !model.Optimizing || model.Snapshot?.Connected!=true)return;
  if(model.Applications.Any(a=>BrowserCatalog.IsEdge(a.Profile)&&DesktopViewModel.NativeBrowser(a.Profile)))return;
  if(edgeActivating||edgeMonitoring||edgeNeedsActivation||!model.Applications.Any(r=>EdgeSites(r.Profile)&&r.Profile.Mode=="AUTO"))return;
  edgeMonitoring=true;
  try{
   // Recovery remains an owner-user process; it survives service loss and can
   // release only ordinary domains authorized by the service-owned guard file.
   await edgeRecovery.StartAsync(lifetime.Token);
   if(!edgeRecovery.Configured){
    edgeRecovery.Dispose();edgeNeedsActivation=true;
    model.ApplyEdgePolicyState(new(){LastError="Recovery не настроен после сброса локального состояния. Нажмите «Оптимизировать» для повторной проверки Edge."});
    return;
   }
   if(!model.Available){model.ApplyEdge(await edgeRecovery.SnapshotAsync(lifetime.Token));return;}
   var status=await model.EdgeStatusAsync(lifetime.Token);var snapshot=status.Snapshot();
   var recovery=await edgeRecovery.SnapshotAsync(lifetime.Token);
   snapshot.Records=snapshot.Records.Concat(recovery.Records.Where(r=>r.EvidenceSource=="RECOVERY_DIRECT"&&r.Plan.Policy.Action=="DIRECT")).ToArray();
   snapshot.Lost+=recovery.Lost;snapshot.Truncated|=recovery.Truncated;
   model.ApplyEdge(snapshot);model.ApplyEdgePolicyState(status);
   if(!status.Listening)model.SetNotice("Служба Edge CONNECT недоступна: ordinary DIRECT recovery, protected-домены закрыты.");
   else if(!status.PolicyReady&&model.Applications.Any(r=>EdgeSites(r.Profile)&&r.Profile.Mode=="AUTO")){
    foreach(var p in model.Applications.Where(r=>EdgeSites(r.Profile)&&r.Profile.Mode=="AUTO").Select(r=>r.Profile.Copy()).ToArray())await model.RestoreEdgeAsync(p,lifetime.Token);
    model.SetNotice("Edge PAC изменён или недоступен: AUTO остановлен для Edge; Chrome не изменён.");
   }
  }catch(Exception error)when(!lifetime.IsCancellationRequested){model.ReportActionFailure(EdgeErrors.Wrap("edge.recovery",error));}
  finally{edgeMonitoring=false;}
 }
}
