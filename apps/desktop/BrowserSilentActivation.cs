namespace Veliq.Desktop;
public partial class MainWindow {
 bool silentPolicyRefreshRequested;
 async Task EnsureSilentBrowserLanesAsync(){
  if(!model.BrowserPreparationAllowed)return;
  foreach(var p in model.Applications.Select(a=>a.Profile.Copy()).Where(p=>model.NativeBrowserCandidate(p)&&!DesktopViewModel.NativeBrowser(p)).ToArray()){
   if(!model.BrowserPreparationAllowed)return;
   if(BrowserCatalog.IsEdge(p)){
    var status=await model.EdgeStatusAsync(lifetime.Token);
    if(status.Listening&&status.PolicyReady&&status.SilentActivation.ConfiguredProfiles.Contains(p.Id))continue;
    await ActivateEdgeSites(p);
   }else{
    var status=await model.ChromeStatusAsync(lifetime.Token);
    if(status.Listening&&status.PolicyReady&&status.SilentActivation.ConfiguredProfiles.Contains(p.Id))continue;
    var row=model.Applications.FirstOrDefault(a=>a.Profile.Id==p.Id);
    if(row is not null)await ActivateChromeSites(row);
   }
  }
  // Refresh requests user GP processing only, not browser navigation or restart.
  if(!silentPolicyRefreshRequested){BrowserNativePolicy.RequestRefresh();silentPolicyRefreshRequested=true;}
 }
}
