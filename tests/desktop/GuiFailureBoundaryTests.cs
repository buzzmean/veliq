using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public class GuiFailureBoundaryTests {
 sealed class AuxiliaryFault(string method,Exception error) : IServiceClient {
  public FakeService Core=new();
  public Task<T> Call<T>(string m,object? p=null,CancellationToken ct=default)=>m==method?Task.FromException<T>(error):Core.Call<T>(m,p,ct);
 }
 [Theory][InlineData("browser.status")][InlineData("processes")][InlineData("capture.diagnostics")]
 public async Task OptionalDiagnosticExceptionKeepsAuthenticatedProfilesAndButtons(string method){
  var vm=new DesktopViewModel(new AuxiliaryFault(method,new InvalidOperationException("secret runtime value")));
  await vm.RefreshAsync();Assert.True(vm.Available);Assert.True(vm.CanControl);Assert.Single(vm.Applications);
  Assert.NotNull(vm.LastGuiFailure);Assert.DoesNotContain("secret",vm.Notice);Assert.Empty(vm.Error);
 }
 [Fact]public async Task CorruptChromeStateOrDeadHelperCannotEraseValidStatus(){
  var vm=new DesktopViewModel(new FakeService());await vm.RefreshAsync();var profile=vm.Applications[0].Profile;
  await vm.ObserveAuxiliaryAsync(()=>throw new System.Text.Json.JsonException("private metadata token"),"browser.monitor");
  Assert.True(vm.CanControl);Assert.Same(profile,vm.Applications[0].Profile);Assert.Equal("browser.monitor",vm.LastGuiFailure!.Phase);
  Assert.DoesNotContain("private",vm.Notice);
  vm.ReportActionFailure(new InvalidOperationException("helper stopped"));Assert.True(vm.Available);Assert.Single(vm.Applications);
 }
 [Fact]public async Task EdgePolicyFailureKeepsTechnicalCauseInJournalInsteadOfActivationError(){
  var vm=new DesktopViewModel(new FakeService());await vm.RefreshAsync();var original=vm.Applications[0];
  vm.ReportActionFailure(EdgeErrors.Wrap("edge.policy",new ServiceException(ServiceFailure.Rejected,"EDGE_POLICY_ACCESS_DENIED secret=private")));
  Assert.True(vm.CanControl);Assert.Same(original,vm.Applications[0]);Assert.Empty(vm.Error);Assert.DoesNotContain("edge.policy",vm.Notice);Assert.DoesNotContain("EDGE_",vm.Notice);Assert.DoesNotContain("private",vm.Notice);Assert.Equal("edge.policy",vm.LastGuiFailure!.Phase);Assert.Equal("EDGE_POLICY_ACCESS_DENIED",vm.LastGuiFailure.Code);
  await vm.RefreshAsync();Assert.DoesNotContain("EDGE_POLICY_ACCESS_DENIED",vm.EdgeState);Assert.Empty(vm.Notice);Assert.Single(vm.Applications);Assert.True(vm.CanControl);
 }
 [Fact]public async Task RealStatusFailureStillDisablesControls(){
  var service=new FakeService();var vm=new DesktopViewModel(service);await vm.RefreshAsync();var row=Assert.Single(vm.Applications);var relay=Assert.Single(vm.Relays);
  service.Failure=new ServiceException(ServiceFailure.Unavailable);await vm.RefreshAsync();
  Assert.False(vm.Available);Assert.False(vm.CanControl);Assert.Same(row,Assert.Single(vm.Applications));
  Assert.Same(relay,Assert.Single(vm.Relays));
  Assert.Equal(Text.Get("NoData"),row.UserStatus);
 }
 [Fact]public async Task PartialStatusRecoversProfilesFromDedicatedEndpoint(){
  var service=new PartialStatus();var vm=new DesktopViewModel(service);
  await vm.RefreshAsync();
  Assert.True(vm.CanControl);Assert.Equal("game",Assert.Single(vm.Applications).Profile.Id);
  Assert.Contains("profiles",service.Calls);
 }
 [Fact]public async Task PartialStatusCannotRemovePreviouslyVisibleProfile(){
  var service=new PartialStatus();service.OmitOnlyAfterFirstPoll=true;
  service.Profiles=[new(){Id="game",Name="Игра",Executables=["game.exe"]},new(){Id="custom",Name="Приложение",Executables=["app.exe"],Custom=true}];
  var vm=new DesktopViewModel(service);
  await vm.RefreshAsync();var rows=vm.Applications.ToArray();Assert.Equal(2,rows.Length);
  await vm.RefreshAsync();
  Assert.Equal(2,vm.Applications.Count);Assert.Same(rows[1],vm.Applications[1]);Assert.True(vm.CanControl);
  Assert.Contains("profiles",service.Calls);
 }
 sealed class PartialStatus:IServiceClient {
  readonly FakeService service=new();
  public PartialStatus(){service.State.History=System.Text.Json.JsonSerializer.SerializeToElement(new{});}
  public readonly List<string> Calls=[];
  public Profile[] Profiles {set=>service.State.Profiles=value;}
  public bool OmitOnlyAfterFirstPoll;
  int statusPolls;
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken ct=default){
   Calls.Add(method);
   if(method=="status"){
    var partial=System.Text.Json.JsonSerializer.Deserialize<Snapshot>(System.Text.Json.JsonSerializer.Serialize(service.State))!;
    if(!OmitOnlyAfterFirstPoll)partial.Profiles=[];
    else if(++statusPolls>1)partial.Profiles=partial.Profiles.Take(1).ToArray();
    return Task.FromResult((T)(object)partial);
   }
   return service.Call<T>(method,payload,ct);
  }
 }
 [Fact]public async Task RejectedActionPreservesConnectionButUnavailableIPCDoesNot(){
  var vm=new DesktopViewModel(new FakeService());await vm.RefreshAsync();
  vm.ReportActionFailure(new ServiceException(ServiceFailure.Rejected));Assert.True(vm.CanControl);Assert.Single(vm.Applications);
  vm.ReportActionFailure(new ServiceException(ServiceFailure.AccessDenied));Assert.False(vm.CanControl);
 }
}
