using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class HomePresentationTests {
 [Fact] public void HomeShowsServerAndStateLeadNotBrowserPreparation(){
  var vm=new DesktopViewModel(new PickerService());
  vm.Apply(new(){Connected=true,Optimizing=true,Primary="DIRECT",Routes=[new(){Id="DIRECT",Status="healthy",RttMs=68.3,ObservedAt=DateTimeOffset.UtcNow},new(){Id="hel-01",Status="healthy",RttMs=71.9,ObservedAt=DateTimeOffset.UtcNow}]},[]);
  Assert.Equal("hel-01",vm.Server);Assert.Equal("hel-01, 71,9 мс",vm.GoSub);
  Assert.StartsWith("Маршруты построены",vm.HomeLead);
  vm.Apply(new(){Optimizing=false},[]);
  Assert.Equal("выключено",vm.GoSub);Assert.StartsWith("Нажмите кнопку",vm.HomeLead);
 }
 [Fact] public void UnusedSecondBrowserDoesNotKeepPreparing(){
  System.Text.Json.JsonElement native=System.Text.Json.JsonSerializer.SerializeToElement("native");
  var vm=new DesktopViewModel(new PickerService());
  vm.Apply(new(){Optimizing=true,Profiles=[new(){Id="chrome",Name="Chrome",Mode="AUTO",Executables=["chrome.exe"],PolicyData=new(){{"browser_transport",native}}},new(){Id="edge",Name="Edge",Mode="AUTO",Executables=["msedge.exe"],PolicyData=new(){{"browser_transport",native}}}]},[]);
  vm.ApplyNativeBrowserReadiness(new(){State="AUTHORITY_REQUEST_OBSERVED",CaptureReady=true,Optimizing=true,AuthorityTransport=new(){SystemProxyApplied=true,Profiles=[new(){ProfileId="chrome",Requests=1,Exchanges=1}]}});
  Assert.Contains("подтверждён",vm.BrowserReadinessText);
 }
}
