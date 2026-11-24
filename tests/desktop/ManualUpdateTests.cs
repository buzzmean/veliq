using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class ManualUpdateTests
{
    sealed class UpdateService : IServiceClient
    {
        public readonly FakeService Other = new();
        public UpdateSnapshot Update = new() { State = "READY", CurrentBuild = "712", AvailableBuild = 713, AvailableVersion = "0.3.713" };
        public int Installs, Retries;
        public TaskCompletionSource<UpdateSnapshot>? Pending;
        public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
        {
            if (method == "update.status") return Task.FromResult((T)(object)Update);
            if (method == "update.install")
            {
                Installs++;
                return Install<T>();
            }
            if (method == "update.retry") { Retries++; return Task.FromResult((T)(object)Update); }
            return Other.Call<T>(method, payload, cancellationToken);
        }
        async Task<T> Install<T>() => (T)(object)(Pending is null ? new UpdateSnapshot { State = "INSTALLING" } : await Pending.Task);
    }
    [Fact]
    public async Task RefreshAndReopenDoNotInstall()
    {
        var service = new UpdateService();
        var first = new DesktopViewModel(service);
        await first.RefreshAsync(); await first.RefreshAsync();
        var reopened = new DesktopViewModel(service); await reopened.RefreshAsync();
        Assert.Equal(0, service.Installs); Assert.True(reopened.ShowUpdate); Assert.True(reopened.CanUpdate);
        await reopened.ApplyUpdateAsync();
        Assert.Equal(1, service.Installs); Assert.False(reopened.CanUpdate);
    }
    [Fact]
    public async Task DoubleClickAndDownloadRetryCannotInstallTwice()
    {
        var service = new UpdateService { Pending = new() };
        var vm = new DesktopViewModel(service); await vm.RefreshAsync();
        var pending = vm.ApplyUpdateAsync(); await vm.ApplyUpdateAsync();
        Assert.Equal(1, service.Installs);
        service.Pending.SetResult(new() { State = "INSTALL_FAILED", CurrentBuild = "712", AvailableBuild = 713 }); await pending;
        Assert.True(vm.CanUpdate);
        vm.ApplyUpdate(new() { State = "DOWNLOAD_FAILED", CurrentBuild = "712", AvailableBuild = 713 }); await vm.ApplyUpdateAsync();
        Assert.Equal(1, service.Retries); Assert.Equal(1, service.Installs);
    }
    [Fact]
    public async Task ProgressClubAndDisconnectedStates()
    {
        var service = new UpdateService(); var vm = new DesktopViewModel(service); await vm.RefreshAsync();
        vm.ApplyUpdate(new() { State = "DOWNLOADING", CurrentBuild = "712", AvailableBuild = 713, DownloadedBytes = 50, TotalBytes = 100 });
        Assert.Equal(50, vm.UpdatePercent); Assert.True(vm.UpdateDownloading); Assert.False(vm.CanUpdate);
        vm.ApplyUpdate(new() { State = "DISABLED" }); Assert.False(vm.ShowUpdate);
        vm.ApplyUpdate(new() { State = "READY", CurrentBuild = "712", AvailableBuild = 713 });
        vm.SetUnavailable(new Exception()); Assert.False(vm.CanUpdate); Assert.False(vm.ShowUpdate);
    }
    [Theory]
    [InlineData("INSTALL_FAILED", "732", 732)]
    [InlineData("INSTALL_FAILED", "732", 730)]
    [InlineData("CHECK_FAILED", "732", 0)]
    [InlineData("READY", "", 733)]
    [InlineData("UP_TO_DATE", "732", 732)]
    public void CurrentOrUnknownVersionNeverOffersInstallation(string state, string current, ulong offered)
    {
        var vm = new DesktopViewModel(new UpdateService());
        vm.Apply(new Snapshot());
        vm.ApplyUpdate(new() { State = state, CurrentBuild = current, AvailableBuild = offered });
        Assert.False(vm.ShowUpdate);
        Assert.False(vm.CanUpdate);
    }
    [Fact]
    public async Task InstalledBuildClearsFailedOfferWithoutAnotherLaunch()
    {
        var service = new UpdateService();
        var vm = new DesktopViewModel(service); await vm.RefreshAsync();
        vm.ApplyUpdate(new() { State = "INSTALL_FAILED", CurrentBuild = "712", AvailableBuild = 713 });
        Assert.True(vm.CanUpdate);
        vm.ApplyUpdate(new() { State = "INSTALL_FAILED", CurrentBuild = "713", AvailableBuild = 713 });
        await vm.ApplyUpdateAsync();
        Assert.False(vm.ShowUpdate); Assert.Equal(0, service.Installs);
    }

}
