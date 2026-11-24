using System.Text.Json;
using Veliq.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class BrowserSilentActivationTests {
 sealed class Service:IServiceClient {
  public readonly PickerService Inner=new();public bool Reject;
  public Service(){Inner.State.Optimizing=true;Inner.State.Connected=true;Inner.State.Settings.Automatic=true;}
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){
   if(method is "browser.silent.apply" or "edge.silent.apply"){
    Inner.Calls.Add((method,payload));
    if(Reject)throw new ServiceException(ServiceFailure.Rejected,"POLICY_FAILED");
    return Task.FromResult((T)(object)JsonSerializer.SerializeToElement(new{state="POLICY_PENDING_BROWSER_REFRESH"}));
   }
   if(method=="profile.set"){
    Inner.Calls.Add((method,payload));var next=((Profile)payload!).Copy();Inner.State.Profiles=[next];return Task.FromResult((T)(object)Inner.State.Profiles);
   }
   if(method=="browser.status")return Task.FromResult((T)(object)new BrowserTransportSnapshot{Listening=true,PolicyReady=true,SilentActivation=new(){ConfiguredProfiles=["browser"],State="POLICY_PENDING_BROWSER_REFRESH"}});
   if(method=="edge.status")return Task.FromResult((T)(object)new EdgeTransportStatus{ActivationVersion=3,Listening=true,PolicyReady=true,SilentActivation=new(){ConfiguredProfiles=["browser"],State="POLICY_PENDING_BROWSER_REFRESH"}});
   return Inner.Call<T>(method,payload,cancellationToken);
  }
 }
 [Theory][InlineData(false)][InlineData(true)]
 public async Task QuietApplyCommitsAutoWithoutProofLaunchOrOptimize(bool edge){
  var s=new Service();var p=new Profile{Id="browser",Mode="DIRECT",Executables=[edge?"msedge.exe":"chrome.exe"]};s.Inner.State.Profiles=[p];var vm=new DesktopViewModel(s);vm.Apply(s.Inner.State);
  await vm.ApplySilentBrowserAsync(p,edge);await vm.VerifyFreshBrowserAsync(p.Id,edge);
  Assert.Equal("AUTO",Assert.Single(s.Inner.State.Profiles).Mode);
  Assert.DoesNotContain(s.Inner.Calls,c=>c.Method is "browser.confirm" or "edge.confirm" or "optimize");
  Assert.Equal("profile.set",s.Inner.Calls[0].Method);
  Assert.Equal(edge?"edge.silent.apply":"browser.silent.apply",s.Inner.Calls[1].Method);
  Assert.Equal("DIRECT",p.Mode);
 }
 [Fact]public async Task FailedPolicyApplyPreservesModeAndApplications(){
  var s=new Service{Reject=true};var p=new Profile{Id="browser",Mode="DIRECT",Executables=["chrome.exe"]};s.Inner.State.Profiles=[p];var vm=new DesktopViewModel(s);await vm.RefreshAsync();
  await Assert.ThrowsAsync<ServiceException>(()=>vm.ApplySilentBrowserAsync(p,false));
  Assert.Equal("DIRECT",Assert.Single(s.Inner.State.Profiles).Mode);Assert.Single(vm.Applications);
  var changes=s.Inner.Calls.Where(c=>c.Method=="profile.set").ToArray();Assert.Equal(2,changes.Length);Assert.Equal("AUTO",((Profile)changes[0].Payload!).Mode);Assert.Equal("DIRECT",((Profile)changes[1].Payload!).Mode);
 }
 [Fact]public void PendingIsNotUptakeOrPagePass(){
  var p=new BrowserSilentActivation{State="POLICY_PENDING_BROWSER_REFRESH"};Assert.Contains("следующем запуске",p.Notice);
  p.State="PAC_REQUEST_OBSERVED";p.ApplyToRequestMs=72;Assert.Contains("72",p.Notice);Assert.Contains("не проверка",p.Notice);
 }
}
