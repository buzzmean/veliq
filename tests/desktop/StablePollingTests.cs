using System.Text.Json;
using Neexitlag.Desktop;
using NeExitLag.Tests;
using Xunit;
public class StablePollingTests {
 [Fact] public async Task IdenticalPollDoesNotDisableButtonsOrInvalidateHome(){
 var service=new FakeService();service.State.History=JsonSerializer.SerializeToElement(new{});var vm=new DesktopViewModel(service);await vm.RefreshAsync();
 var changed=new List<string?>(); vm.PropertyChanged+=(_,e)=>changed.Add(e.PropertyName);
 var row=Assert.Single(vm.Applications);var rowEvents=0;row.PropertyChanged+=(_,_)=>rowEvents++;
 var routes=0;vm.Routes.CollectionChanged+=(_,_)=>routes++;
 service.State=JsonSerializer.Deserialize<Snapshot>(JsonSerializer.Serialize(service.State))!;
 await vm.RefreshAsync(); Assert.Empty(changed);Assert.Equal(0,rowEvents);Assert.Equal(0,routes);
 }
 [Fact] public void ChangedRouteNotifiesOnlyChangedHomeFields(){var service=new FakeService();service.State.History=JsonSerializer.SerializeToElement(new{});var vm=new DesktopViewModel(service);vm.Apply(service.State);var changed=new List<string?>();vm.PropertyChanged+=(_,e)=>changed.Add(e.PropertyName);var next=JsonSerializer.Deserialize<Snapshot>(JsonSerializer.Serialize(service.State))!;next.Optimizing=true;vm.Apply(next);Assert.Contains("OptimizeLabel",changed);Assert.DoesNotContain("",changed);Assert.DoesNotContain("Primary",changed);}
}
