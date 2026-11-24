using Veliq.Desktop;
using System.Text.Json;
using Xunit;
namespace NeExitLag.Tests;
public class EdgeRoutingTests {
 [Fact] public async Task EdgeCleanInstallCreatesOnePendingDirectProfileAndLeavesChromeUntouched(){
  var dir=Path.Combine(Path.GetTempPath(),"veliq-edge-"+Guid.NewGuid());Directory.CreateDirectory(dir);
  var exe=Path.Combine(dir,"msedge.exe");await File.WriteAllBytesAsync(exe,[0]);
  try{
   var service=new PickerService{State=new(){Profiles=[new(){Id="chrome",Mode="AUTO",Executables=[@"C:\Chrome\chrome.exe"],LocalStrategyId="baseline"}]}};
   var vm=new DesktopViewModel(new VersionedEdgeService(service,3));
   var list=new[]{new InstalledBrowser("edge","Microsoft Edge",exe,true)};
   var created=await vm.EnsureEdgeProfileAsync(list);Assert.NotNull(created);Assert.Equal("DIRECT",created!.Mode);Assert.Equal("edge-sites-pending",created.PolicyData!["app_preset"].GetString());
   Assert.Equal(Path.GetFullPath(exe),Assert.Single(created.Executables));
   Assert.Null(await vm.EnsureEdgeProfileAsync(list));
   Assert.Single(service.Calls,c=>c.Method=="profile.set");
   Assert.Equal("AUTO",service.State.Profiles.Single(p=>p.Id=="chrome").Mode);
   Assert.Equal("baseline",service.State.Profiles.Single(p=>p.Id=="chrome").LocalStrategyId);
  }finally{Directory.Delete(dir,true);}
 }
 [Theory][InlineData("AUTO")][InlineData("MANUAL")][InlineData("DIRECT")][InlineData("DIRECT_PLUS")]
 public async Task ExistingEdgeProfileIsNotReplacedOrSilentlyConverted(string mode){
  var service=new PickerService{State=new(){Profiles=[new(){Id="mine",Mode=mode,Executables=[@"D:\Edge\msedge.exe"],RelayId="VPS-01"}]}};
  var vm=new DesktopViewModel(service);
  Assert.Null(await vm.EnsureEdgeProfileAsync([new("edge","Microsoft Edge",@"C:\Edge\msedge.exe",true)]));
  Assert.DoesNotContain(service.Calls,c=>c.Method=="profile.set");Assert.Equal(mode,service.State.Profiles[0].Mode);
 }
 [Fact]public async Task EdgePreparationCannotAcceptChromeProfile(){
  var service=new PickerService();var vm=new DesktopViewModel(service);
  await Assert.ThrowsAsync<InvalidOperationException>(async()=>await vm.PrepareEdgeAsync(new(){Executables=[@"C:\Chrome\chrome.exe"]},"dir","127.0.0.1:1"));
  Assert.Empty(service.Calls);
 }
 [Fact]public void ChromeIdentificationAndPolicyLaunchArgumentsRemainUnchanged(){
  var chrome=new Profile{Executables=[@"C:\Chrome\chrome.exe"]};var edge=new Profile{Executables=[@"C:\Edge\msedge.exe"]};
  Assert.True(BrowserCatalog.IsChrome(chrome));Assert.False(BrowserCatalog.IsEdge(chrome));
  Assert.True(BrowserCatalog.IsEdge(edge));Assert.False(BrowserCatalog.IsChrome(edge));
  Assert.Equal(new[]{"--no-first-run"},new BrowserLaunch{Arguments=["--proxy-pac-url=inline","--no-first-run"]}.UserArguments());
 }
 sealed class VersionedEdgeService(PickerService inner,int version) : IServiceClient {
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default)=>method=="edge.status"?Task.FromResult((T)(object)new EdgeTransportStatus{ActivationVersion=version}):inner.Call<T>(method,payload,cancellationToken);
 }
 [Fact]public async Task OldServiceCannotReceiveUnrecognizedPendingAutoProfile(){
  var picker=new PickerService();var vm=new DesktopViewModel(new VersionedEdgeService(picker,2));
  await Assert.ThrowsAsync<EdgeActivationException>(()=>vm.EnsureEdgeProfileAsync([new("edge","Microsoft Edge",@"C:\Edge\msedge.exe",true)]));
  Assert.DoesNotContain(picker.Calls,c=>c.Method=="profile.set");
 }
 sealed class EdgeCalls : IServiceClient {
  public readonly PickerService Base=new();public readonly List<string> Order=[];public readonly List<string> PolicyOperations=[];public bool RejectGuard,Ready=true;
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){
   Order.Add(method);
   if(method=="edge.policy")PolicyOperations.Add(JsonSerializer.SerializeToElement(payload).GetProperty("operation").GetString()!);
   if(method=="edge.policy"&&RejectGuard)return Task.FromException<T>(new ServiceException(ServiceFailure.Rejected));
   if(method=="edge.policy"||method=="edge.confirm")return Task.FromResult((T)(object)JsonSerializer.SerializeToElement(new{applied=true,ready=Ready}));
   return Base.Call<T>(method,payload,cancellationToken);
  }
 }
 [Fact]public async Task FailedGuardNeverDisarmsEdgeOrMutatesChrome(){
  var service=new EdgeCalls{RejectGuard=true};var vm=new DesktopViewModel(service);
  await Assert.ThrowsAsync<EdgeActivationException>(()=>vm.RestoreEdgeAsync(new(){Id="edge",Mode="AUTO",Executables=[@"C:\Edge\msedge.exe"]}));
  Assert.Equal(new[]{"edge.policy"},service.Order);Assert.Empty(service.Base.Calls);
 }
 [Fact]public async Task EdgeCommitUsesExplicitMarkerAndDoesNotStartGlobalCapture(){
  var service=new EdgeCalls();var vm=new DesktopViewModel(service);
  var original=new Profile{Id="edge",Mode="DIRECT",Executables=[@"C:\Edge\msedge.exe"],PolicyData=new(){["app_preset"]=JsonSerializer.SerializeToElement("openai-web")}};
  await vm.CommitEdgeAsync(original);
  var saved=(Profile)service.Base.Calls.Single(c=>c.Method=="profile.set").Payload!;
  Assert.Equal("edge-sites",saved.PolicyData!["app_preset"].GetString());Assert.Equal("AUTO",saved.Mode);
  Assert.Equal("openai-web",original.PolicyData!["app_preset"].GetString());Assert.Equal("DIRECT",original.Mode);
  Assert.DoesNotContain(service.Order,m=>m=="optimize"||m=="browser.prepare"||m=="browser.confirm");
 }
 [Fact]public async Task FalseEdgeReadinessCannotPublishAuto(){
  var service=new EdgeCalls{Ready=false};var vm=new DesktopViewModel(service);
  await Assert.ThrowsAsync<InvalidOperationException>(()=>vm.ConfirmEdgeAsync(new(){Id="edge"},new(){HealthUrl="http://neexitlag-health.invalid/ready/nonce"}));
  Assert.Equal(new[]{"edge.confirm"},service.Order);
 }

 [Fact]public void EdgeOriginResultDoesNotClaimPagePassOrReferToChrome(){
  var row=new EdgeDomainRow(new(){Plan=new(){Probe="DNS_RELAY_HTTP_VERIFIED",HttpStatus=200}});
  Assert.Contains("страница Edge не проверена",row.Outcome);Assert.DoesNotContain("Chrome",row.Outcome);
 }

 [Fact]public void EdgeButtonFindsUniqueProfileWithoutRowSelectionOrWithChromeSelected(){
  var chrome=new Profile{Id="chrome",Executables=[@"C:\Chrome\chrome.exe"]};var edge=new Profile{Id="edge",Mode="DIRECT",Executables=[@"C:\Edge\msedge.exe"]};
  Assert.Equal("edge",EdgeProfileSelection.Select(null,[chrome,edge])!.Id);
  Assert.Equal("edge",EdgeProfileSelection.Select(chrome,[chrome,edge])!.Id);
  Assert.Equal("DIRECT",edge.Mode);
  Assert.Throws<EdgeActivationException>(()=>EdgeProfileSelection.Select(null,[edge,new(){Id="edge-two",Executables=[@"D:\Edge\msedge.exe"]}]));
 }
 [Fact]public void EdgeFailureRetainsMethodAndSafeCodeWithoutReflectingSecrets(){
  var e=EdgeErrors.Wrap("edge.policy",new ServiceException(ServiceFailure.Rejected,"edge.policy: EDGE_POLICY_ACCESS_DENIED token=do-not-print"));
  Assert.Contains("edge.policy",e.Message);Assert.Contains("EDGE_POLICY_ACCESS_DENIED",e.Message);Assert.DoesNotContain("do-not-print",e.Message);
  Assert.Equal("EDGE_IPC_ACCESS_DENIED",EdgeErrors.Wrap("edge.prepare",new ServiceException(ServiceFailure.AccessDenied)).Code);
  Assert.Equal("EDGE_IPC_UNSUPPORTED",EdgeErrors.Wrap("edge.prepare",new ServiceException(ServiceFailure.Rejected,"unsupported IPC method edge.prepare")).Code);
 }

 [Fact]public async Task GuardRollbackCallsServiceWithoutAnyExistingProfile(){
  var service=new EdgeCalls();var vm=new DesktopViewModel(service);await vm.GuardEdgeAsync();
  Assert.Equal(new[]{"edge.policy"},service.Order);Assert.Equal(new[]{"guard"},service.PolicyOperations);Assert.Empty(service.Base.Calls);
 }

 [Fact]public async Task ManualMsedgePickerCannotPublishPendingAutoToOldService(){
  var dir=Path.Combine(Path.GetTempPath(),"veliq-old-edge-"+Guid.NewGuid());Directory.CreateDirectory(dir);var exe=Path.Combine(dir,"msedge.exe");await File.WriteAllBytesAsync(exe,[0]);
  try{var picker=new PickerService();var vm=new DesktopViewModel(new VersionedEdgeService(picker,2));Assert.False(await vm.AddApplicationAsync(exe));Assert.DoesNotContain(picker.Calls,c=>c.Method=="profile.set");Assert.Empty(vm.Error);Assert.Equal("EDGE_IPC_UNSUPPORTED",vm.LastGuiFailure!.Code);Assert.DoesNotContain("EDGE_IPC_UNSUPPORTED",vm.Notice);}finally{Directory.Delete(dir,true);}
 }

}
