using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class BrowserReadinessTests {
 [Fact] public async Task EmptyNativeWireSnapshotDoesNotBreakReadinessPolling(){
  var vm=new DesktopViewModel(new EmptyNativeStatusService());
  vm.Apply(new(){Connected=true,Optimizing=true,Profiles=[new(){Id="chrome",Mode="AUTO",Executables=["chrome.exe"],PolicyData=new(){{"browser_transport",System.Text.Json.JsonSerializer.SerializeToElement("native")}}}]},[]);
  await vm.ObserveNativeBrowsersAsync();
  Assert.DoesNotContain("подтверждён",vm.BrowserReadinessText);
  Assert.Empty(vm.BrowserDomains);
 }
 sealed class EmptyNativeStatusService : IServiceClient {
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){
   var json=method=="browser.native.status" ? """{"state":"AUTHORITY_REQUEST_OBSERVED","capture_ready":true,"optimizing":true,"authority_transport":{"system_proxy_applied":true,"profiles":null},"records":null}""" : """{"listening":false,"records":null}""";
   return Task.FromResult(System.Text.Json.JsonSerializer.Deserialize<T>(json,WireJson.Options)!);
  }
 }
 [Fact] public void ReadinessNeedsCurrentAuthorityProofAndNeverRawTLSBytes(){
  var vm=new DesktopViewModel(new PickerService());vm.Apply(new(){Optimizing=true,Profiles=[new(){Id="chrome",Name="Chrome",Mode="AUTO",Executables=["chrome.exe"],PolicyData=new(){{"browser_transport",System.Text.Json.JsonSerializer.SerializeToElement("native")}}}]},[]);
  vm.ApplyNativeBrowserReadiness(new(){State="PREPARING"});Assert.Contains("Подготавливаем",vm.BrowserReadinessText);
  vm.ApplyNativeBrowserReadiness(new(){State="READY_NEW_CONNECTIONS",CaptureReady=true});Assert.Contains("Подготавливаем",vm.BrowserReadinessText);
  vm.ApplyNativeBrowserReadiness(new(){State="READY_NEW_CONNECTIONS",CaptureReady=true,Optimizing=true,NativeOnlyState="NATIVE_ONLY_OBSERVED",Profiles=[new(){ProfileId="chrome",NativeOnly=new(){BidirectionalExchanges=1,SentBytes=100,ReceivedBytes=200}}]});Assert.Contains("Подготавливаем",vm.BrowserReadinessText);
  vm.ApplyNativeBrowserReadiness(new(){State="AUTHORITY_REQUEST_OBSERVED",CaptureReady=true,Optimizing=true,AuthorityTransport=new(){SystemProxyApplied=true,Profiles=[new(){ProfileId="chrome",Requests=1,Exchanges=1}]}});Assert.Contains("подтверждён",vm.BrowserReadinessText);
  vm.ApplyNativeBrowserReadiness(new(){State="READY_NEW_CONNECTIONS",CaptureReady=true,Optimizing=true,Profiles=[new(){ProfileId="chrome",NativeOnly=new(){SentBytes=100}}]});Assert.Contains("Подготавливаем",vm.BrowserReadinessText);
  vm.Apply(new(){Optimizing=false},[]);Assert.Contains("обычную сеть",vm.BrowserReadinessText);
 }
 [Fact] public void PreparationJournalRetainsSafeNativeCauseWithoutExceptionPayload(){
  var vm=new DesktopViewModel(new PickerService());vm.Apply(new(){Optimizing=true},[]);
  vm.ReportBrowserPreparationFailure(new ServiceException(ServiceFailure.Rejected,"NATIVE_CAPTURE_START_FAILED secret=private"),"browser.native.enable");
  Assert.Equal("NATIVE_CAPTURE_START_FAILED",vm.LastGuiFailure!.Code);
  Assert.DoesNotContain("private",vm.Notice);Assert.DoesNotContain("NATIVE_",vm.Notice);Assert.Empty(vm.Error);
 }
}
