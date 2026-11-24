using Veliq.Desktop;
using Xunit;
namespace Veliq.Tests;
public class BrowserRoutingTests {
 [Fact]public void DNSRecoveryProvesOriginOnlyNotBrowserPage(){
  var record=new BrowserConnection{Plan=new(){Probe="DNS_RELAY_HTTP_VERIFIED",HttpStatus=200,Policy=new(){Action="RELAY_REQUIRED",RelayId="VPS-01"}}};
  Assert.Contains("страница Chrome не проверена",record.Outcome);Assert.DoesNotContain("PASS",record.Outcome);
 }

 [Fact]public void NoFakePageSuccessOrNativeTransformFromConnect(){
  var model=new DesktopViewModel(new FakeService());
  var record=new BrowserConnection{Id=1,Domain="www.youtube.com",Plan=new(){Policy=new(){Action="DIRECT_PLUS"},Probe="NOT_PROBED"},Result="TCP_ESTABLISHED_HTTP_RESULT_UNKNOWN"};
  model.ApplyBrowser(new(){Records=[record]});
  Assert.Contains("не подтверждён",model.BrowserDomains[0].Route);
  Assert.DoesNotContain("PASS",record.Outcome);
  record.DirectPlusApplied=true;Assert.Equal("DIRECT_PLUS",record.Route);
  record.Plan.Probe="HTTP_SUCCESS";record.Plan.HttpStatus=200;Assert.Contains("страница Chrome не проверена",record.Outcome);
 }
 [Fact]public void FailedProtectedOpenDisplaysBlock(){
  var record=new BrowserConnection{Result="UPSTREAM_OPEN_FAILED",Plan=new(){Policy=new(){Action="RELAY_REQUIRED",RelayId="VPS-01"}}};Assert.Equal("BLOCK",record.Route);
 }
 [Fact]public void ChromeSummaryDoesNotInventOneBrowserWideWinner(){
  var model=new DesktopViewModel(new FakeService());
  model.Apply(new(){Profiles=[new(){Id="chrome",Name="Chrome",Mode="AUTO",Executables=[@"C:\Apps\chrome.exe"]}]});
  BrowserConnection Flow(string domain,string action,bool local=false)=>new(){Domain=domain,Owner=new(){ProfileId="chrome"},Active=true,SentBytes=100,ReceivedBytes=100,DirectPlusApplied=local,Plan=new(){Policy=new(){Action=action,RelayId=action=="RELAY_REQUIRED"?"VPS-01":""}}};
  model.ApplyBrowser(new(){Listening=true,Records=[Flow("chatgpt.com","RELAY_REQUIRED"),Flow("www.youtube.com","DIRECT_PLUS",true),Flow("example.org","DIRECT")]});
  var row=model.Applications.Single();Assert.Contains("по сайтам",row.UserStatus);Assert.Contains("RELAY_REQUIRED",row.Route);Assert.Contains("DIRECT_PLUS",row.Route);Assert.Contains("DIRECT",row.Route);
 }
 [Fact]public void InactiveBrowserTransportAcceptsNullOptionalRecords(){
  var value=System.Text.Json.JsonSerializer.Deserialize<BrowserTransportSnapshot>("{\"listening\":false,\"records\":null}",WireJson.Options)!;
  var model=new DesktopViewModel(new FakeService());model.ApplyBrowser(value);Assert.Empty(model.BrowserDomains);
 }

 [Fact]public async Task ChromePrepareDoesNotPublishAUTOOrEnableCapture(){
  var service=new BrowserService();var vm=new DesktopViewModel(service);
  var p=new Profile{Id="chrome",Mode="DIRECT_PLUS",Executables=[@"C:\Apps\chrome.exe"]};
  var launch=await vm.PrepareChromeAsync(p,@"C:\Users\test\Chrome");
  Assert.Single(service.Fake.Calls);Assert.Equal("browser.prepare",service.Fake.Calls[0].method);
  Assert.Equal("DIRECT_PLUS",p.Mode);Assert.NotEmpty(launch.HealthUrl);
 }
 [Fact]public async Task ChromeCommitDoesNotIgnoreRejectedProfileOrFailedOptimize(){
  var service=new BrowserService();var vm=new DesktopViewModel(service);
  var p=new Profile{Id="chrome",Mode="DIRECT",Executables=[@"C:\Apps\chrome.exe"]};
  service.Fake.Failure=new ServiceException(ServiceFailure.Rejected);
  await Assert.ThrowsAsync<ServiceException>(()=>vm.CommitChromeAsync(p));
  Assert.DoesNotContain(service.Fake.Calls,c=>c.method=="optimize");
  service.Fake.Failure=null;service.Fake.Calls.Clear();service.Fake.State.Optimizing=false;
  await Assert.ThrowsAsync<ChromeActivationException>(()=>vm.CommitChromeAsync(p));
  Assert.Equal(new[]{"profile.set","optimize"},service.Fake.Calls.Select(c=>c.method));
 }
 [Fact]public async Task ChromeRollbackRestoresOrdinaryDIRECTInsteadOfBrokenUnactivatedAUTO(){
  var service=new BrowserService();var vm=new DesktopViewModel(service);
  var p=new Profile{Id="chrome",Mode="AUTO",Executables=[@"C:\Apps\chrome.exe"],LocalStrategyId="working-youtube"};
  await vm.RestoreChromeAsync(p);
  var sent=(Profile)service.Fake.Calls.Single(c=>c.method=="profile.set").payload!;
  Assert.Equal("DIRECT",sent.Mode);Assert.Equal("working-youtube",sent.LocalStrategyId);Assert.Equal("AUTO",p.Mode);
  Assert.DoesNotContain(service.Fake.Calls,c=>c.method=="optimize");
 }

 [Fact]public async Task ChromeGuardedRecoveryPreservesDomainRulesForReactivation(){
  var service=new BrowserService();var vm=new DesktopViewModel(service);
  var p=new Profile{Id="chrome",Mode="AUTO",Executables=[@"C:\Apps\chrome.exe"],PolicyData=new(){["rules"]=System.Text.Json.JsonSerializer.SerializeToElement(new[]{new{ id="private",domains=new[]{"private.example"},action="RELAY_REQUIRED",relay_id="VPS-01"}})}};
  await vm.RestoreChromeAsync(p);
  var sent=(Profile)service.Fake.Calls.Single(c=>c.method=="profile.set").payload!;
  Assert.Equal(0,sent.PolicyData!["rules"].GetArrayLength());Assert.Equal("private.example",sent.PolicyData["browser_recovery_rules"][0].GetProperty("domains")[0].GetString());
  Assert.Equal(1,p.PolicyData["rules"].GetArrayLength());
 }

 [Fact]public async Task RealChromeTabsLaunchOnlyAfterPolicyProofAndCaptureCommit(){
  var service=new BrowserService();service.Fake.State.Optimizing=true;service.Fake.State.Settings.Automatic=true;
  var vm=new DesktopViewModel(service);var p=new Profile{Id="chrome",Mode="DIRECT",Executables=[@"C:\Apps\chrome.exe"]};
  var launch=new BrowserLaunch{HealthUrl="http://neexitlag-health.invalid/ready/nonce"};
  await vm.ActivatePreparedChromeAsync(p,launch,
   ()=>{Assert.DoesNotContain(service.Fake.Calls,c=>c.method=="profile.set"||c.method=="optimize");return Task.CompletedTask;},
   ()=>{Assert.Contains(service.Fake.Calls,c=>c.method=="browser.confirm");Assert.Contains(service.Fake.Calls,c=>c.method=="profile.set");Assert.Contains(service.Fake.Calls,c=>c.method=="optimize");return Task.CompletedTask;});
  Assert.Equal(new[]{"browser.confirm","profile.set","optimize"},service.Fake.Calls.Take(3).Select(c=>c.method));
 }
 [Fact]public async Task FailedPolicyProbeNeverPublishesAUTOOrLaunchesUserTabs(){
  var service=new BrowserService();var vm=new DesktopViewModel(service);bool launched=false;
  await Assert.ThrowsAsync<IOException>(()=>vm.ActivatePreparedChromeAsync(new(),new(),()=>throw new IOException("probe failed"),()=>{launched=true;return Task.CompletedTask;}));
  Assert.False(launched);Assert.Empty(service.Fake.Calls);
 }

 [Fact]public async Task FalseReadinessACKNeverLaunchesTabsOrPublishesAUTO(){
  var service=new BrowserService{ConfirmReady=false};var vm=new DesktopViewModel(service);bool launched=false;
  await Assert.ThrowsAsync<ChromeActivationException>(()=>vm.ActivatePreparedChromeAsync(new(){Id="chrome"},new(){HealthUrl="http://neexitlag-health.invalid/ready/nonce"},()=>Task.CompletedTask,()=>{launched=true;return Task.CompletedTask;}));
  Assert.False(launched);Assert.Single(service.Fake.Calls);Assert.Equal("browser.confirm",service.Fake.Calls[0].method);
 }

 [Fact]public void UserChromeLaunchCannotFreezeOnlinePACAndOverrideLiveRecoveryPolicy(){
  var launch=new BrowserLaunch{Arguments=[@"--user-data-dir=C:\Users\test\Chrome","--proxy-pac-url=data:old-inline-pac","--proxy-bypass-list=<-loopback>","--no-proxy-server","--no-first-run"]};
  Assert.Equal(new[]{@"--user-data-dir=C:\Users\test\Chrome","--no-first-run"},launch.UserArguments());
 }
 [Fact]public void RecoveryShowsOnlyRealDirectEvidenceAndDropsUnavailablePrimaryClaims(){
  var vm=new DesktopViewModel(new FakeService());
  vm.ApplyBrowser(new(){Listening=true,Records=[new(){Domain="chatgpt.com",Active=true,Plan=new(){Policy=new(){Action="RELAY_REQUIRED"}}}]});
  vm.ApplyRecovery(new(){Listening=true,Records=[new(){Domain="ordinary.example",EvidenceSource="RECOVERY_DIRECT",SentBytes=31,ReceivedBytes=64,Plan=new(){Policy=new(){Action="DIRECT"},Probe="RECOVERY_DIRECT_SOCKET"}},new(){Domain="forged.example",EvidenceSource="RECOVERY_DIRECT",Plan=new(){Policy=new(){Action="RELAY_REQUIRED"}}}]});
  var record=Assert.Single(vm.BrowserDomains);Assert.Equal("ordinary.example",record.Domain);Assert.Equal("DIRECT",record.Route);Assert.DoesNotContain("PASS",record.Outcome);
 }
 sealed class BrowserService:IServiceClient{
  public FakeService Fake=new();public bool ConfirmReady=true;
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){
   if(method=="browser.confirm"){Fake.Calls.Add((method,payload));return Task.FromResult((T)(object)System.Text.Json.JsonSerializer.SerializeToElement(new{ready=ConfirmReady}));}
   if(method=="browser.prepare"){Fake.Calls.Add((method,payload));return Task.FromResult((T)(object)new BrowserLaunch{HealthUrl="http://neexitlag-health.invalid/ready/nonce"});}
   return Fake.Call<T>(method,payload,cancellationToken);
  }
 }
}
