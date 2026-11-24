using Veliq.Desktop;
using Xunit;
namespace NeExitLag.Tests;

public sealed class RelayWarningTests
{
    [Fact]
    public async Task DecliningManualRelayLeavesProfileAndListUntouched()
    {
        var service = new FakeService(); var vm = new DesktopViewModel(service);
        await vm.RefreshAsync(); var original = service.State.Profiles[0];
        original.Mode = "DIRECT";
        var row = Assert.Single(vm.Applications); int asked = 0;
        Assert.False(await vm.SetProfileWithRelayWarningAsync(original, "MANUAL", "VPS-01", () => { asked++; return Task.FromResult(false); }));
        Assert.Equal(1, asked); Assert.Equal("DIRECT", original.Mode);
        Assert.Same(row, Assert.Single(vm.Applications));
        Assert.DoesNotContain(service.Calls, c => c.method == "profile.set");
    }

    [Fact]
    public async Task ApprovedRelayIsExplicitAndDirectNeverPrompts()
    {
        var service = new FakeService(); var vm = new DesktopViewModel(service);
        await vm.RefreshAsync(); var original = service.State.Profiles[0]; int asked = 0;
        Assert.True(await vm.SetProfileWithRelayWarningAsync(original, "MANUAL", "VPS-01", () => { asked++; return Task.FromResult(true); }));
        var sent = (Profile)Assert.Single(service.Calls, c => c.method == "profile.set").payload!;
        Assert.Equal("MANUAL", sent.Mode); Assert.Equal("VPS-01", sent.RelayId); Assert.Equal(1, asked);
        Assert.Equal("AUTO", original.Mode);
        Assert.True(await vm.SetProfileWithRelayWarningAsync(original, "DIRECT", null, () => throw new Exception("DIRECT must not prompt")));
        Assert.Contains("пинг", Text.Get("RelayWarningMessage"));
    }
}
