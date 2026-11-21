using System.Text.Json;
using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public class HotAttachTests
{
 [Theory]
 [InlineData("HOT_ATTACH_RECONNECTING","HotAttachReconnecting")]
 [InlineData("HOT_ATTACH_INCOMPLETE","HotAttachIncomplete")]
 [InlineData("HOT_ATTACH_NETWORK_READY","OptimizationOn")]
 public void GuiShowsActualTransitionStateWithoutClaimingAppRecovery(string state,string label)
 {
  var vm=new DesktopViewModel(new FakeService());
  vm.Apply(new Snapshot{Connected=true,Optimizing=true,HotAttach=new(){Epoch=3,State=state}});
  Assert.Equal(Text.Get(label),vm.OptimizationStatus);
 }
 [Fact] public void HotAttachStatusIsOptionalForOlderService()
 {
  var snapshot=JsonSerializer.Deserialize<Snapshot>("""{"optimizing":true,"hot_attach":{"epoch":3,"state":"HOT_ATTACH_RECONNECTING","pending":2,"tcp_reset":4}}""",WireJson.Options)!;
  Assert.Equal((ulong)3,snapshot.HotAttach!.Epoch);Assert.Equal(2,snapshot.HotAttach.Pending);
  Assert.Null(JsonSerializer.Deserialize<Snapshot>("{}",WireJson.Options)!.HotAttach);
 }
}
