using Veliq.Desktop;
using Xunit;

namespace Veliq.Tests;

public sealed class TechnicalDetailsCostTests
{
    static readonly Profile App = new() { Id = "app", Name = "App", Mode = "AUTO", Executables = ["C:/Apps/app.exe"] };
    static CaptureFlow Flow(ulong id = 1) => new()
    {
        FlowId = id, ProcessGroup = App.Id, Exe = App.Executables[0], Pid = 42, CreationTime = 100,
        IdentityCurrent = true, Active = true, Protocol = "tcp", IpVersion = "IPv4", SelectedRoute = "DIRECT_PLUS",
        Destination = "203.0.113.9:443", Counters = new() { DirectPlusPackets = 1, DirectPlusBytes = 4096 }
    };
    static Snapshot Status() => new() { Optimizing = true, Profiles = [App] };

    [Fact]
    public void OrdinaryModeAndSupportReportKeepSeparateDisplayCostsAndSameEvidence()
    {
        var flow = Flow();
        var capture = new CaptureEvidence { Flows = [flow] };
        var expected = new ApplicationRow(); expected.Update(App, null, capture);
        var vm = new DesktopViewModel(new FakeService());
        vm.Apply(Status(), capture: capture);
        var row = Assert.Single(vm.Applications);
        Assert.Equal(Text.Get("NoData"), row.LocalDetails);
        Assert.Contains(expected.LocalDetails, vm.SupportReport("test"));
        Assert.Equal(Text.Get("NoData"), row.LocalDetails);
        var changed = new List<string?>(); row.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        vm.ShowTechnical = true;
        Assert.Equal(expected.LocalDetails, row.LocalDetails);
        Assert.Contains(nameof(row.LocalDetails), changed);
        Assert.Same(row, Assert.Single(vm.Applications));
        vm.ShowTechnical = false;
        Assert.Equal(Text.Get("NoData"), row.LocalDetails);
        Assert.Contains(expected.LocalDetails, vm.SupportReport("test"));
    }

    [Fact]
    public void ToggleAndReportUseLatestCaptureAndNeverKeepReusedPidEvidence()
    {
        var vm = new DesktopViewModel(new FakeService());
        var flow = Flow();
        vm.Apply(Status(), capture: new() { Flows = [flow] });
        Assert.Contains("203.0.113.9:443", vm.SupportReport("test"));
        flow = Flow(2); flow.Destination = "203.0.113.10:443";
        vm.Apply(Status(), capture: new() { Flows = [flow] });
        vm.ShowTechnical = true;
        var row = Assert.Single(vm.Applications);
        Assert.Contains("203.0.113.10:443", row.LocalDetails);
        Assert.DoesNotContain("203.0.113.9:443", row.LocalDetails);
        vm.ShowTechnical = false;
        flow.IdentityCurrent = false;
        vm.Apply(Status(), [new() { PID = 42, CreationTime = 101, Path = App.Executables[0] }], new() { Flows = [flow] });
        Assert.DoesNotContain("203.0.113.10", vm.SupportReport("test"));
        vm.ShowTechnical = true;
        Assert.DoesNotContain("203.0.113.10", row.LocalDetails);
    }

    [Fact]
    public void AutomaticRowsMaterializeDetailsImmediatelyOnlyWhenRequested()
    {
        var vm = new DesktopViewModel(new FakeService());
        vm.Apply(new() { Optimizing = true }, capture: new() { Flows = [Flow()] });
        var row = Assert.Single(vm.ActiveServices);
        Assert.Equal(Text.Get("NoData"), row.LocalDetails);
        vm.ShowTechnical = true;
        Assert.Contains("203.0.113.9:443", row.LocalDetails);
        vm.ShowTechnical = false;
        Assert.Equal(Text.Get("NoData"), row.LocalDetails);
    }

    [Fact]
    public void OrdinaryRepeatedSnapshotAvoidsRichFormattingEvenIfHiddenBindingsReadDetails()
    {
        var capture = new CaptureEvidence { Flows = Enumerable.Range(1, 128).Select(i => Flow((ulong)i)).ToArray() };
        var status = Status();
        long Work(bool technical)
        {
            var vm = new DesktopViewModel(new FakeService()) { ShowTechnical = technical };
            for (int i = 0; i < 20; i++) vm.Apply(status, capture: capture);
            var start = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 50; i++) { vm.Apply(status, capture: capture); _ = vm.Applications[0].LocalDetails; }
            return GC.GetAllocatedBytesForCurrentThread() - start;
        }
        var ordinary = Work(false); var technical = Work(true);
        // A realistic hidden binding must not trigger the per-flow formatted
        // report on every poll. Compare the actual two display modes, not time.
        Assert.True(ordinary < technical / 2, $"ordinary={ordinary}; technical={technical}");
    }
}
