using System.Diagnostics;
using System.Text.Json;
using System.Windows;
namespace Veliq.Desktop;
public partial class MainWindow {
 readonly ChromeRecovery chromeRecovery=new();
 bool chromeActivating,chromeMonitoring;
 string chromeActivationPhase="chrome.activation";
 static bool IsChrome(Profile profile)=>profile.Executables.Any(p=>p.Replace('\\','/').Split('/').Last().Equals("chrome.exe",StringComparison.OrdinalIgnoreCase));
 async void DisableChromeSites(object sender,RoutedEventArgs e)=>await Execute(async()=>{
  var profiles=model.Applications.Where(r=>r.Profile.Mode=="AUTO"&&IsChrome(r.Profile)).Select(r=>r.Profile.Copy()).ToArray();
  var silent=await model.ChromeStatusAsync(lifetime.Token);
  if(profiles.Length==0) {if(silent.SilentActivation.ConfiguredProfiles.Length==0)ChromePolicy.Recover();}
  else{if(silent.SilentActivation.ConfiguredProfiles.Length>0)await model.GuardSilentChromeAsync(profiles[0],lifetime.Token);else ChromePolicy.Guard(profiles[0]);foreach(var profile in profiles){if(DesktopViewModel.NativeBrowser(profile))await model.DisableNativeBrowserAsync(profile,lifetime.Token);else await model.RestoreChromeAsync(profile,lifetime.Token);}}
  model.SetNotice(Text.Get("ChromeSitesRemoved"));
 });
 async void OpenChromeSites(object sender,RoutedEventArgs e){
  if(AppGrid.SelectedItem is not ApplicationRow row){ShowMessage("SelectApplication");return;}
  await Execute(async()=>{await EnableOptimizationAsync();if(model.BrowserPreparationAllowed)await ActivateChromeSites(row);});
 }
 // Clean install: give Chrome a profile and run the normal PAC activation with no manual
 // steps. Failure here must not block the rest of the optimization (Telegram, Claude...).
 // Returns a notice about installed browsers VELIQ cannot route automatically, or null.
 async Task<string?> EnsureBrowserCoverageAsync(){
  var installed=BrowserDiscovery.Installed();
  try{
   var created=await model.EnsureChromeProfileAsync(installed,lifetime.Token);
   var pending=created??model.Applications.Select(r=>r.Profile).FirstOrDefault(model.StartupChromeNeedsActivation);
   if(pending is not null){
    var row=model.Applications.FirstOrDefault(r=>r.Profile.Id==pending.Id);
    if(row is not null)await ActivateChromeSites(row);
   }
  }catch(Exception error)when(!lifetime.IsCancellationRequested){
   model.SetNotice(Text.Get("ChromeAutoSetupFailed")+" "+error.Message);
  }
  await EnsureEdgeCoverageAsync(installed);
  var gaps=BrowserCatalog.NotCovered(installed);
  return gaps.Length==0?null:Text.Get("BrowsersNotCovered")+" "+string.Join(", ",gaps)+".";
 }
 async Task EnableOptimizationAsync(){
  await model.EnsureStartupBrowserProfilesAsync(BrowserDiscovery.Installed(),lifetime.Token);
  await BrowserOptimizationSequence.RunAsync(()=>model.OptimizeAsync(true,lifetime.Token),()=>model.Optimizing,()=>model.Snapshot?.Settings.Automatic==true,()=>Task.CompletedTask,()=>PrepareNativeBrowsersAsync());
 }
 async Task EnableOptimizationCoreAsync()=>await EnableOptimizationAsync();
 async Task<bool> ActivateChromeSites(ApplicationRow row){
  if(chromeActivating)throw new ChromeActivationException("Chrome activation already running", "chrome.activation", "CHROME_ACTIVATION_BUSY");chromeActivating=true;chromeActivationPhase="chrome.activation";
  try{return await ActivateChromeSitesCore(row);}
  catch(BrowserPreparationDeferredException error){model.ReportBrowserPreparationFailure(error,"chrome.prepare");return false;}
  catch(Exception error){
   var code=error is ChromeActivationException own && own.Code!="CHROME_ACTIVATION_FAILED"?own.Code:chromeActivationPhase switch {
    "browser.silent.apply" or "chrome.policy.check" or "chrome.policy.install"=>"CHROME_POLICY_FAILED",
    "chrome.recovery"=>"CHROME_RECOVERY_START_FAILED", "browser.prepare"=>"CHROME_PREPARE_FAILED",
    "chrome.browser_probe" or "browser.confirm"=>"CHROME_READINESS_NOT_OBSERVED",
    _=>"CHROME_ACTIVATION_FAILED"};
   throw new ChromeActivationException(chromeActivationPhase+": "+code+". "+Text.Get("ChromeActivationFailed"),chromeActivationPhase,code);
  }finally{chromeActivating=false;}
 }
 async Task MonitorChromeTransportAsync(bool wasOptimizing){
 if(!model.Available || model.Activation?.Status.CapturePermitted==false || !model.Optimizing || model.Snapshot?.Connected!=true)return;
  await MonitorEdgeTransportAsync();
  if(model.Applications.Any(a=>IsChrome(a.Profile)&&DesktopViewModel.NativeBrowser(a.Profile)))return;
  if(chromeActivating||chromeMonitoring)return;
  if(model.Available){var silent=await model.ChromeStatusAsync(lifetime.Token);if(silent.SilentActivation.ConfiguredProfiles.Length>0){
    await chromeRecovery.StartAsync(lifetime.Token);
    model.ApplyBrowser(silent);model.SetNotice(silent.SilentActivation.Notice);return;
  }}
  if(!ChromePolicy.Monitored)return;
  chromeMonitoring=true;
  try{
   try{await chromeRecovery.StartAsync(lifetime.Token);model.ApplyRecovery(await chromeRecovery.SnapshotAsync(lifetime.Token));}
   catch(Exception error)when(!lifetime.IsCancellationRequested && error is (IOException or System.ComponentModel.Win32Exception or UnauthorizedAccessException or OperationCanceledException or ChromeActivationException or JsonException)){model.ApplyRecovery(new());model.SetNotice(Text.Get("ChromeRecoveryUnavailable"));}
   if(!model.Available){ChromePolicy.Suspend(wasOptimizing);return;}
   if(!ChromePolicy.Applied){
    foreach(var p in model.Applications.Where(r=>r.Profile.Mode=="AUTO"&&IsChrome(r.Profile)).Select(r=>r.Profile.Copy()).ToArray()){ChromePolicy.Guard(p);await model.RestoreChromeAsync(p,lifetime.Token);}
    model.SetNotice(Text.Get("ChromeActivationFailed"));return;
   }
   var status=await model.ChromeStatusAsync(lifetime.Token);
   if(!status.Listening){
    ChromePolicy.Suspend(model.Optimizing);
    // The stable PAC already has the owner-scoped recovery CONNECT endpoint.
    // Native capture never sees opaque ordinary bypass traffic; guarded origins
    // have no secondary endpoint. Do not toggle policy or disable other apps.
    model.SetNotice(Text.Get("ChromeRecoveryActive"));
   }else if(ChromePolicy.Suspended){
    var resume=ChromePolicy.Resume();
    if(resume&&!model.Optimizing)await model.RestoreOptimizationAsync(true,lifetime.Token);
   }else{ChromePolicy.RecordOptimization(model.Optimizing);}
  }finally{chromeMonitoring=false;}
 }
 async Task<bool> ActivateChromeSitesCore(ApplicationRow row){
  var original=row.Profile.Copy();
  var exe=original.Executables.FirstOrDefault(p=>p.Replace('\\','/').Split('/').Last().Equals("chrome.exe",StringComparison.OrdinalIgnoreCase));
  if(exe is null||!Path.IsPathFullyQualified(exe)||!File.Exists(exe))throw new InvalidOperationException(Text.Get("SelectChromeAuto"));
  var ticket=model.CaptureBrowserPreparation();
  chromeActivationPhase="chrome.recovery";
  await chromeRecovery.StartAsync(lifetime.Token);
  model.CheckBrowserPreparation(ticket);
  chromeActivationPhase="browser.prepare";
  var directory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Google","Chrome","User Data");
  var launch=await model.PrepareChromeAsync(original,directory,lifetime.Token,chromeRecovery.Address);
  model.CheckBrowserPreparation(ticket);
  launch.RecoverySettings.Executable=exe;
  await chromeRecovery.ConfigureAsync(launch.RecoverySettings,lifetime.Token);
  model.CheckBrowserPreparation(ticket);
  chromeActivationPhase="browser.silent.apply";
  await model.ApplySilentBrowserAsync(original,false,lifetime.Token);
  BrowserNativePolicy.RequestRefresh();silentPolicyRefreshRequested=true;
  model.SetNotice(BrowserSilentActivation.PendingNotice);
  return true;
 }
}
