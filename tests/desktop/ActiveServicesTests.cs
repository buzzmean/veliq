using Veliq.Desktop;
using Xunit;

namespace NeExitLag.Tests;

public sealed class ActiveServicesTests
{
    static Profile App(string id) => new() { Id = id, Name = id, Mode = "AUTO", Executables = ["C:/Apps/" + id + ".exe"] };
    static CaptureFlow Flow(string id, string route = "DIRECT_PLUS") => new()
    {
        ProcessGroup = id, Exe = "C:/Apps/" + id + ".exe", Pid = 42, CreationTime = 100,
        IdentityCurrent = true, Active = true, LastSeen = DateTimeOffset.UtcNow, SelectedRoute = route,
        Counters = new() { DirectPlusPackets = route == "DIRECT_PLUS" ? 1UL : 0, RelayedBytes = route == "RELAY" ? 12UL : 0 }
    };

    [Fact]
    public void PresetsAndRunningDirectAppsAreNotActiveOptimizations()
    {
        var vm = new DesktopViewModel(new FakeService());
        vm.Apply(new() { Optimizing = true, Profiles = [App("closed"), App("direct"), App("local")] },
            capture: new() { Flows = [Flow("direct", "DIRECT"), Flow("local")] });
        Assert.Equal("local", Assert.Single(vm.ServiceApplications).Name);
        Assert.Equal(3, vm.Applications.Count);
        vm.ShowTechnical = true;
        Assert.Equal(3, vm.ServiceApplications.Count());
    }

    [Fact]
    public void MissingLiveIdentityAndReusedPidCannotKeepAnAppVisible()
    {
        var vm = new DesktopViewModel(new FakeService());
        var flow = Flow("app"); flow.IdentityCurrent = false;
        vm.Apply(new() { Optimizing = true, Profiles = [App("app")] },
            [new() { PID = 42, CreationTime = 101, Path = "C:/Apps/app.exe" }], new() { Flows = [flow] });
        Assert.Empty(vm.ServiceApplications);
    }

    [Fact]
    public void PositivePartialEvidenceIsShownWithoutRepeatingIncompleteWarnings()
    {
        var vm = new DesktopViewModel(new FakeService());
        vm.Apply(new() { Optimizing = true, Profiles = [App("app")] },
            capture: new() { Truncated = true, Flows = [Flow("app", "RELAY")] });
        var app = Assert.Single(vm.ServiceApplications);
        Assert.Equal(Text.Get("ProtectedRoute"), app.ServiceStatus);
    }

    [Fact]
    public void AutomaticFlowDoesNotRequireCreatingAPersistentProfile()
    {
        var vm = new DesktopViewModel(new FakeService());
        vm.Apply(new() { Optimizing = true }, capture: new() { Flows = [Flow("new-app")] });
        Assert.Equal("new-app", Assert.Single(vm.ServiceApplications).Name);
        Assert.Empty(vm.Applications);
        vm.Apply(new() { Optimizing = false }, capture: new() { Flows = [Flow("new-app")] });
        Assert.Empty(vm.ServiceApplications);
        Assert.True(vm.NoActiveServices);
    }
}
