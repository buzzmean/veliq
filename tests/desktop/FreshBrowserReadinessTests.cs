using System.Text.Json;
using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;

public sealed class FreshBrowserReadinessTests
{
 sealed class Service : IServiceClient {
  public readonly PickerService Inner=new();
  public BrowserTransportSnapshot Chrome=new(); public EdgeTransportStatus Edge=new(){ActivationVersion=3};
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default) => method switch {
   "browser.status"=>Task.FromResult((T)(object)Chrome), "edge.status"=>Task.FromResult((T)(object)Edge),
   _=>Inner.Call<T>(method,payload,cancellationToken)
  };
 }
 [Fact] public async Task ActiveCaptureRegistersMissingEdgeAndChromeAsStagingDirectWithoutDeferralOrPolicy(){
  var directory=Path.Combine(Path.GetTempPath(),"veliq-fresh-browser-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
  try{
   var installed=new[]{new InstalledBrowser("chrome","Chrome",Path.Combine(directory,"chrome.exe"),true),new InstalledBrowser("edge","Edge",Path.Combine(directory,"msedge.exe"),true)};
   foreach(var b in installed)await File.WriteAllBytesAsync(b.ExePath,[0]);
   var service=new Service();service.Inner.State.Optimizing=true;var vm=new DesktopViewModel(service);await vm.RefreshAsync();
   var prepared=await vm.PrepareFreshBrowserProfilesAsync(installed);
   Assert.Equal(2,prepared.Length);Assert.All(prepared,p=>Assert.Equal("DIRECT",p.Mode));
   Assert.Contains(prepared,BrowserCatalog.IsEdge);Assert.Equal(2,vm.Applications.Count);
   Assert.DoesNotContain(service.Inner.Calls,c=>c.Method.Contains("policy")||c.Method=="optimize"||c.Method.Contains("native.enable"));
   var again=await vm.PrepareFreshBrowserProfilesAsync(installed);Assert.Equal(prepared.Select(p=>p.Id),again.Select(p=>p.Id));
   Assert.Equal(2,service.Inner.Calls.Count(c=>c.Method=="profile.set"));
  }finally{Directory.Delete(directory,true);}
 }
 [Fact] public async Task ReadinessRequiresAutoListenerPolicyAndSameProfileOwnerProof(){
  var s=new Service();s.Inner.State.Profiles=[new(){Id="chrome",Mode="DIRECT",Executables=[@"C:\Apps\chrome.exe"]}];var vm=new DesktopViewModel(s);
  s.Chrome=new(){Listening=true,PolicyReady=true,ReadyProfiles=["chrome"]};
  Assert.Equal("BROWSER_AUTO_NOT_COMMITTED",(await Assert.ThrowsAsync<ChromeActivationException>(()=>vm.VerifyFreshBrowserAsync("chrome",false))).Code);
  s.Inner.State.Profiles[0].Mode="AUTO";
  foreach(var status in new[]{new BrowserTransportSnapshot(),new(){Listening=true,ReadyProfiles=["chrome"]},new(){Listening=true,PolicyReady=true,ReadyProfiles=["other"]}}){
   s.Chrome=status;await Assert.ThrowsAsync<ChromeActivationException>(()=>vm.VerifyFreshBrowserAsync("chrome",false));
  }
  s.Chrome=new(){Listening=true,PolicyReady=true,ReadyProfiles=["chrome"]};await vm.VerifyFreshBrowserAsync("chrome",false);
  s.Edge=new(){Listening=true,PolicyReady=true,ReadyProfiles=["chrome"]};await vm.VerifyFreshBrowserAsync("chrome",true);
 }
 [Fact] public async Task ReportContainsOnlySafeStatusNotMessagesPacRecordsOrNonce(){
  var s=new Service();s.Chrome=new(){LastError="secret-key-or-nonce",ReadinessState="secret",Records=[new(){Domain="private.example"}]};
  s.Edge=new(){LastError="edge.confirm: EDGE_READINESS_NOT_OBSERVED",ReadinessState="WAITING_FOR_BROWSER_REQUEST"};
  var report=JsonSerializer.Serialize(await new DesktopViewModel(s).FreshBrowserDiagnosticsAsync());
  Assert.DoesNotContain("secret",report);Assert.DoesNotContain("private.example",report);Assert.Contains("EDGE_READINESS_NOT_OBSERVED",report);Assert.Contains("UNKNOWN",report);Assert.Contains("WAITING_FOR_BROWSER_REQUEST",report);
 }
 sealed class ActivationService : IServiceClient {
  public readonly FakeService Inner=new();public bool Proof;public BrowserTransportSnapshot Status=new();
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){
   if(method=="browser.confirm"){
    Inner.Calls.Add((method,payload));return Task.FromResult((T)(object)JsonSerializer.SerializeToElement(new{ready=Proof}));
   }
   if(method=="profile.set"){
    Assert.True(Proof);Inner.State.Profiles=[((Profile)payload!).Copy()];
   }
   if(method=="optimize")Inner.State.Optimizing=true;
   if(method=="browser.status")return Task.FromResult((T)(object)Status);
   return Inner.Call<T>(method,payload,cancellationToken);
  }
 }
 [Fact] public async Task ExplicitChromeActivationPromotesExistingDirectOnlyAfterPACProof(){
  var s=new ActivationService();var p=new Profile{Id="existing-chrome",Mode="DIRECT",Executables=[@"C:\Apps\chrome.exe"]};
  s.Inner.State.Profiles=[p.Copy()];s.Inner.State.Settings.Automatic=true;var vm=new DesktopViewModel(s);var phases=new List<string>();
  await vm.ActivatePreparedChromeAsync(p,new(){HealthUrl="http://neexitlag-health.invalid/ready/test"},
   ()=>{s.Proof=true;s.Status=new(){Listening=true,PolicyReady=true,ReadyProfiles=[p.Id]};return Task.CompletedTask;},
   ()=>{Assert.Equal("AUTO",Assert.Single(s.Inner.State.Profiles).Mode);return Task.CompletedTask;},phase:phases.Add);
  await vm.VerifyFreshBrowserAsync(p.Id,false);
  Assert.Equal("DIRECT",p.Mode);Assert.Equal(new[]{"browser.confirm","profile.set","chrome.launch"},phases);
  Assert.Equal(new[]{"browser.confirm","profile.set","optimize"},s.Inner.Calls.Take(3).Select(c=>c.method));
 }
 [Fact] public async Task NoBrowsersCannotProduceVacuousPass(){
  var vm=new DesktopViewModel(new Service());Assert.Equal("BROWSER_NOT_INSTALLED",(await Assert.ThrowsAsync<ChromeActivationException>(()=>vm.PrepareFreshBrowserProfilesAsync([]))).Code);
 }
}
