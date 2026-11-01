using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class BrowserReadinessTests {
 [Fact] public void NativeReadyDoesNotDependOnPACOrPretendPageWasVerified(){
  var vm=new DesktopViewModel(new PickerService());vm.Apply(new(){Optimizing=true,Profiles=[new(){Id="chrome",Name="Chrome",Mode="AUTO",Executables=["chrome.exe"],PolicyData=new(){{"browser_transport",System.Text.Json.JsonSerializer.SerializeToElement("native")}}}]},[]);
  vm.ApplyNativeBrowserReadiness(new(){State="PREPARING"});Assert.Contains("не подтверждена",vm.BrowserReadinessText);
  vm.ApplyNativeBrowserReadiness(new(){State="READY_NEW_CONNECTIONS",CaptureReady=true});Assert.Contains("не подтверждена",vm.BrowserReadinessText);
  vm.ApplyNativeBrowserReadiness(new(){State="READY_NEW_CONNECTIONS",CaptureReady=true,Optimizing=true,NativeOnlyState="NATIVE_ONLY_OBSERVED",Profiles=[new(){ProfileId="chrome",NativeOnly=new(){BidirectionalExchanges=1,SentBytes=100,ReceivedBytes=200}}]});Assert.Contains("подтверждён",vm.BrowserReadinessText);Assert.Contains("отдельно",vm.BrowserReadinessText);
  vm.ApplyNativeBrowserReadiness(new(){State="READY_NEW_CONNECTIONS",CaptureReady=true,Optimizing=true,Profiles=[new(){ProfileId="chrome",NativeOnly=new(){SentBytes=100}}]});Assert.Contains("Ожидаем новые соединения",vm.BrowserReadinessText);
  vm.Apply(new(){Optimizing=false},[]);Assert.Contains("обычную сеть",vm.BrowserReadinessText);
 }
 [Fact] public void PreparationJournalRetainsSafeNativeCauseWithoutExceptionPayload(){
  var vm=new DesktopViewModel(new PickerService());vm.Apply(new(){Optimizing=true},[]);
  vm.ReportBrowserPreparationFailure(new ServiceException(ServiceFailure.Rejected,"NATIVE_CAPTURE_START_FAILED secret=private"),"browser.native.enable");
  Assert.Equal("NATIVE_CAPTURE_START_FAILED",vm.LastGuiFailure!.Code);
  Assert.DoesNotContain("private",vm.Notice);Assert.DoesNotContain("NATIVE_",vm.Notice);Assert.Empty(vm.Error);
 }
}
