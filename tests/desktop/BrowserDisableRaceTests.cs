using System.Text.Json;
using Veliq.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class BrowserDisableRaceTests {
 sealed class DelayedService:IServiceClient {
  public readonly TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously);
  public readonly TaskCompletionSource Release=new(TaskCreationOptions.RunContinuationsAsynchronously);
  public readonly List<string> Calls=[];
  public Snapshot State=new(){Connected=true,Optimizing=true,Settings=new(){Automatic=true},Profiles=[new(){Id="browser",Mode="DIRECT",Executables=["chrome.exe"]}]};
  public async Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){
   Calls.Add(method);
   if(method=="profile.set"){Entered.TrySetResult();await Release.Task.WaitAsync(cancellationToken);return (T)(object)new[]{((Profile)payload!).Copy()};}
   if(method=="optimize"){State.Optimizing=JsonSerializer.SerializeToElement(payload).GetProperty("enabled").GetBoolean();return(T)(object)State;}
   object result=method switch{"status"=>State,"processes"=>Array.Empty<ProcessIdentity>(),"capture.diagnostics"=>new CaptureEvidence(),"browser.status"=>new BrowserTransportSnapshot(),_=>throw new InvalidOperationException(method)};
   return(T)result;
  }
 }
 [Theory][InlineData(false)][InlineData(true)]
 public async Task DisabledDuringPrepareCannotApplyPACOrRollBackUserState(bool reenable){
  var s=new DelayedService();var vm=new DesktopViewModel(s);vm.Apply(s.State);
  var prepare=vm.ApplySilentBrowserAsync(s.State.Profiles[0],false);
  await s.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
  await vm.OptimizeAsync(false);
  if(reenable)await vm.OptimizeAsync(true);
  s.Release.SetResult();
  await Assert.ThrowsAsync<BrowserPreparationDeferredException>(()=>prepare);
  Assert.DoesNotContain("browser.silent.apply",s.Calls);
  Assert.Equal(1,s.Calls.Count(m=>m=="profile.set"));
 }
 [Fact]public async Task BrowserStartupFailureIsNeutralAndClearsOnSuccess(){
  var service=new FakeService();var vm=new DesktopViewModel(service);await vm.RefreshAsync();var row=vm.Applications[0];
  await vm.ObserveAuxiliaryAsync(()=>throw new ChromeActivationException("private runtime value"),"browser.startup");
  Assert.Empty(vm.Error);Assert.DoesNotContain("ChromeActivationException",vm.Notice);Assert.DoesNotContain("browser.startup",vm.Notice);Assert.DoesNotContain("private",vm.Notice);Assert.Same(row,vm.Applications[0]);
  await vm.ObserveAuxiliaryAsync(()=>Task.CompletedTask,"browser.startup");Assert.Empty(vm.Notice);
  Assert.Equal("browser.startup",vm.LastGuiFailure!.Phase); // historical diagnostic retained
 }
 [Fact]public async Task DisabledModeNeverStartsBrowserMutation(){
  var s=new DelayedService();s.State.Optimizing=false;var vm=new DesktopViewModel(s);vm.Apply(s.State);
  await Assert.ThrowsAsync<BrowserPreparationDeferredException>(()=>vm.ApplySilentBrowserAsync(s.State.Profiles[0],false));Assert.Empty(s.Calls);
 }

 sealed class ActivatedService:IServiceClient {
  readonly FakeService core=new();
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default)=>method=="activation.status"?Task.FromResult((T)(object)new ActivationView{State="ACTIVATED",HasIdentity=true}):core.Call<T>(method,payload,cancellationToken);
 }
 [Fact]public async Task BrowserFailureCannotInvalidateSuccessfulDeviceActivation(){
  var vm=new DesktopViewModel(new ActivatedService());await vm.RefreshAsync();var activation=vm.ActivationClient();await activation.RefreshAsync();var confirmed=activation.Status;
  vm.ReportActionFailure(EdgeErrors.Wrap("edge.silent.apply",new ServiceException(ServiceFailure.Rejected)));
  Assert.Same(confirmed,activation.Status);Assert.Equal("ACTIVATED",activation.Status.State);Assert.True(activation.Status.HasIdentity);
  Assert.Empty(vm.Error);Assert.DoesNotContain("Активация",vm.Notice);Assert.Equal("EDGE_OPERATION_FAILED",vm.LastGuiFailure!.Code);
 }

 [Fact]public void BrowserLabelsImmediatelyReflectDisabledStatusWithoutPollingFlap(){
  Profile[] profiles=[new(){Id="chrome",Executables=["chrome.exe"],Mode="AUTO"},new(){Id="edge",Executables=["msedge.exe"],Mode="AUTO"}];
  var vm=new DesktopViewModel(new FakeService());vm.Apply(new(){Optimizing=true,Connected=true,Profiles=profiles});
  vm.ApplyEdgePolicyState(new(){TransportMode="NATIVE_ARMED_PAC_GUARD",ReadinessState="NATIVE_TUNNEL_OBSERVED",Listening=true});
  vm.ApplyBrowser(new(){Listening=true,PolicyReady=true,SilentActivation=new(){State="PAC_REQUEST_OBSERVED"}});
  var changes=new List<string?>();vm.PropertyChanged+=(_,e)=>changes.Add(e.PropertyName);
  vm.Apply(new(){Optimizing=false,Profiles=profiles});Assert.Contains("прямая сеть",vm.EdgeState);Assert.Contains("прямая сеть",vm.ChromePolicyState);
  Assert.Contains(nameof(vm.EdgeState),changes);Assert.Contains(nameof(vm.ChromePolicyState),changes);
  changes.Clear();vm.Apply(new(){Optimizing=false,Profiles=profiles});Assert.DoesNotContain(nameof(vm.EdgeState),changes);Assert.DoesNotContain(nameof(vm.ChromePolicyState),changes);
 }
}
