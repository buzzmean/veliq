using Neexitlag.Desktop;
using Xunit;
public class ServiceConnectionTests {
 [Fact]public void EnabledCaptureWithoutRelayDoesNotClaimWorkingHome(){
  var vm=new DesktopViewModel(new NeExitLag.Tests.PickerService());
  vm.Apply(new(){Connected=false,Optimizing=true,ConnectionReason="RELAY_NOT_CONNECTED"},[]);
  Assert.Contains("Нет готового",vm.OptimizationStatus);
  Assert.DoesNotContain("заблокированное открывается",vm.HomeLead);
  vm.Apply(new(){Connected=true,Optimizing=true,ConnectionReason="CAPTURE_NOT_READY"},[]);
  Assert.Equal("Захват трафика ещё не готов",vm.OptimizationStatus);
  vm.Apply(new(){Connected=true,Optimizing=true,BrowserPolicy=new(){ChromeConfigured=true,ChromeReady=false}},[]);
  Assert.Equal("Подготавливаем браузер…",vm.OptimizationStatus);
  Assert.DoesNotContain("заблокированное открывается",vm.HomeLead);
 }
 [Fact]public void SuccessfulIpcDoesNotMeanConnected(){
  Assert.NotEqual(Text.Get("Connected"),ServiceConnectionText.Describe(new(){Connected=false,Optimizing=false}));
  Assert.NotEqual(Text.Get("Connected"),ServiceConnectionText.Describe(new(){Connected=true,Optimizing=false}));
  Assert.Equal(Text.Get("Connected"),ServiceConnectionText.Describe(new(){Connected=true,Optimizing=true}));
 }
 [Fact]public void DriverFailureIsNotPresentedAsNetworkSuccess(){Assert.Contains("WinDivert",ServiceConnectionText.Describe(new(){ConnectionReason="CAPTURE_START_FAILED"}));}
}
public class BrowserExplicitModeTests {
 [Fact]public async Task DirectModeDoesNotAutomaticallyReenableNativeSiteRouting(){
  var s=new NeExitLag.Tests.PickerService();var p=new Profile{Id="chrome",Mode="AUTO",Executables=["chrome.exe"],PolicyData=new(){["browser_transport"]=System.Text.Json.JsonSerializer.SerializeToElement("native")}};
  s.State.Profiles=[p];var model=new DesktopViewModel(s);await model.RefreshAsync();
  Assert.True(await model.SetProfileAsync(p,"DIRECT",null));
  var saved=(Profile)Assert.Single(s.Calls,c=>c.Method=="profile.set").Payload!;Assert.Equal("DIRECT",saved.Mode);Assert.False(model.NativeBrowserCandidate(saved));Assert.Equal("AUTO",p.Mode);
 }
}
