using Veliq.Desktop;
using Xunit;

namespace NeExitLag.Tests;

public sealed class BrowserStartupTests
{
    sealed class Service : IServiceClient
    {
        public readonly PickerService Inner = new();
        public bool RejectEdge, RejectProfiles;
        public int Version = 3;
        public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
        {
            if (method == "profiles" && RejectProfiles) return Task.FromException<T>(new ServiceException(ServiceFailure.Unavailable));
            if (method == "profile.set" && payload is Profile edgeProfile && BrowserCatalog.IsEdge(edgeProfile) && RejectEdge) return Task.FromException<T>(new ServiceException(ServiceFailure.Rejected,"secret=do-not-persist"));
            if (method == "edge.status")
            {
                if (RejectEdge) return Task.FromException<T>(new ServiceException(ServiceFailure.Rejected, "secret=do-not-persist"));
                return Task.FromResult((T)(object)new EdgeTransportStatus { ActivationVersion = Version });
            }
            if(method=="profile.set" && payload is Profile replacement)Inner.State.Profiles=Inner.State.Profiles.Where(p=>p.Id!=replacement.Id).ToArray();
            return Inner.Call<T>(method, payload, cancellationToken);
        }
    }

    static InstalledBrowser[] Installed(string directory) =>
    [new("chrome", "Google Chrome", Path.Combine(directory, "chrome.exe"), true),
     new("edge", "Microsoft Edge", Path.Combine(directory, "msedge.exe"), true)];

    static async Task WithInstalled(Func<InstalledBrowser[], Task> action)
    {
        var directory = Path.Combine(Path.GetTempPath(), "veliq-startup-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var installed = Installed(directory);
            foreach (var browser in installed) await File.WriteAllBytesAsync(browser.ExePath, [0]);
            await action(installed);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public Task StartupRegistersBothBrowsersOnceWithoutPolicyOptimizationOrProcessCommands() => WithInstalled(async installed =>
    {
        var service = new Service(); var vm = new DesktopViewModel(service);
        await vm.RefreshAsync();
        await Task.WhenAll(vm.EnsureStartupBrowserProfilesAsync(installed), vm.EnsureStartupBrowserProfilesAsync(installed));
        Assert.Equal(2, service.Inner.State.Profiles.Length);
        Assert.Equal(2, vm.Applications.Count);
        var chrome = Assert.Single(service.Inner.State.Profiles, BrowserCatalog.IsChrome);
        var edge = Assert.Single(service.Inner.State.Profiles, BrowserCatalog.IsEdge);
        Assert.Equal("AUTO", chrome.Mode); Assert.True(DesktopViewModel.NativeBrowser(chrome));
        Assert.Equal("AUTO", edge.Mode); Assert.Equal("edge-sites", edge.PolicyData!["app_preset"].GetString());
        foreach (var profile in service.Inner.State.Profiles) Assert.Contains(Assert.Single(profile.Executables), installed.Select(b => Path.GetFullPath(b.ExePath)));
        Assert.Equal(2, service.Inner.Calls.Count(c => c.Method == "profile.set"));
        Assert.All(vm.BrowserStartup!.Browsers, r => Assert.Equal("AUTO_CONFIGURED", r.State));
        Assert.True(vm.BrowserStartup.Completed >= vm.BrowserStartup.Started); Assert.True(vm.BrowserStartup.ElapsedMs >= 0);
        Assert.False(vm.Optimizing);
        Assert.DoesNotContain(service.Inner.Calls, c => c.Method.Contains("prepare") || c.Method.Contains("confirm") || c.Method.Contains("policy") || c.Method == "optimize" || c.Method.Contains("kill") || c.Method.Contains("launch"));
    });

    [Theory]
    [InlineData("DIRECT")]
    [InlineData("AUTO")]
    [InlineData("DIRECT_PLUS")]
    [InlineData("MANUAL")]
    public Task StartupPreservesExistingBrowserIdentityModeRulesAndStrategy(string mode) => WithInstalled(async installed =>
    {
        var service = new Service();
        service.Inner.State.Profiles = installed.Select(b => new Profile { Id = b.Id, Executables = [b.ExePath], Mode = mode, RelayId = "VPS-01", LocalStrategyId = "baseline", PolicyData = new() { ["app_preset"] = System.Text.Json.JsonSerializer.SerializeToElement("custom") } }).ToArray();
        var vm = new DesktopViewModel(service);
        await vm.RefreshAsync(); await vm.EnsureStartupBrowserProfilesAsync(installed);
        Assert.Equal(mode=="AUTO"?2:0,service.Inner.Calls.Count(c=>c.Method=="profile.set"));
        Assert.All(vm.BrowserStartup!.Browsers, r => Assert.Equal(mode=="AUTO"?"AUTO_CONFIGURED":"EXISTING", r.State));
        Assert.All(service.Inner.State.Profiles, p => { Assert.Equal(mode, p.Mode); Assert.Equal("baseline", p.LocalStrategyId); Assert.Equal("custom", p.PolicyData!["app_preset"].GetString()); Assert.False(vm.StartupChromeNeedsActivation(p)); });
    });

    [Fact]
    public Task EdgeFailureKeepsApplicationsAndRetriesWithoutDuplicateChromeOrSecretText() => WithInstalled(async installed =>
    {
        var service = new Service { RejectEdge = true }; var vm = new DesktopViewModel(service);
        await vm.RefreshAsync(); await vm.EnsureStartupBrowserProfilesAsync(installed);
        Assert.True(vm.Available); Assert.Single(vm.Applications);
        var failed = vm.BrowserStartup!.Browsers.Single(b => b.Browser == "edge");
        Assert.Equal("FAILED", failed.State); Assert.Equal("IPC_REJECTED", failed.Code);
        Assert.Contains("выключена",vm.Notice);Assert.DoesNotContain("secret",vm.Notice);
        Assert.DoesNotContain("do-not-persist", System.Text.Json.JsonSerializer.Serialize(vm.BrowserStartup));
        service.RejectEdge = false; await vm.EnsureStartupBrowserProfilesAsync(installed);
        Assert.Equal(2, vm.Applications.Count); Assert.Equal(2, service.Inner.Calls.Count(c => c.Method == "profile.set"));
    });

    [Fact]
    public Task StartupConfiguresMissingEdgeAutoDuringCaptureWithoutPolicyOrRestart() => WithInstalled(async installed =>
    {
        var service = new Service(); service.Inner.State.Optimizing = true;
        var vm = new DesktopViewModel(service); await vm.RefreshAsync(); await vm.EnsureStartupBrowserProfilesAsync(installed);
        var edge=Assert.Single(service.Inner.State.Profiles,BrowserCatalog.IsEdge);
        Assert.Equal("AUTO",edge.Mode);
        Assert.Equal("edge-sites",edge.PolicyData!["app_preset"].GetString());
        Assert.Equal("AUTO_CONFIGURED", vm.BrowserStartup!.Browsers.Single(b=>b.Browser=="edge").State);
    });

    [Fact]
    public Task OptionalStartupIPCFailureDoesNotEraseAuthenticatedApplications() => WithInstalled(async installed =>
    {
        var service = new Service(); service.Inner.State.Profiles = [new() { Id = "game", Executables = ["game.exe"] }];
        var vm = new DesktopViewModel(service); await vm.RefreshAsync(); service.RejectProfiles = true;
        await vm.EnsureStartupBrowserProfilesAsync(installed);
        Assert.True(vm.Available); Assert.Equal("game", Assert.Single(vm.Applications).Profile.Id);
        Assert.All(vm.BrowserStartup!.Browsers, r => Assert.Equal("FAILED", r.State));
        Assert.False(vm.Busy);
    });

    [Fact]
    public Task FreezeAndLegacyDefaultDirectBecomeNativeAutoButExplicitOptOutStaysDirect() => WithInstalled(async installed => {
        var service=new Service();
        service.Inner.State.Profiles=installed.Select(b=>new Profile{Id=b.Id,Name=b.Name,Executables=[b.ExePath],Mode="DIRECT",Custom=true,PolicyData=b.Id=="edge"?new(){["browser_auto_disabled"]=System.Text.Json.JsonSerializer.SerializeToElement(true)}:null}).ToArray();
        var vm=new DesktopViewModel(service);await vm.RefreshAsync();await vm.EnsureStartupBrowserProfilesAsync(installed);
        Assert.Equal("AUTO",service.Inner.State.Profiles.Single(BrowserCatalog.IsChrome).Mode);
        Assert.Equal("DIRECT",service.Inner.State.Profiles.Single(BrowserCatalog.IsEdge).Mode);
        Assert.Single(service.Inner.Calls,c=>c.Method=="profile.set");
        Assert.DoesNotContain(service.Inner.Calls,c=>c.Method.Contains("policy")||c.Method.Contains("prepare")||c.Method.Contains("launch")||c.Method.Contains("kill"));
    });

    [Fact]
    public async Task MissingBrowsersDoNotSendIPCOrCreatePhantomProfiles()
    {
        var service = new Service(); var vm = new DesktopViewModel(service);
        await vm.EnsureStartupBrowserProfilesAsync([]);
        Assert.Empty(service.Inner.Calls);
        Assert.All(vm.BrowserStartup!.Browsers, r => Assert.Equal("NOT_INSTALLED", r.State));
    }

    [Fact]
    public async Task WindowsAlreadyRunningChromeAndEdgeKeepPidAndCreationTimeDuringRegistration()
    {
        if (!OperatingSystem.IsWindows()) return; // Native part runs in Windows CI.
        var installed = BrowserCatalog.Discover(File.Exists, Environment.GetEnvironmentVariable)
            .Where(b => b.Id is "chrome" or "edge").ToArray();
        Assert.Equal(2, installed.Length);
        var directory = Path.Combine(Path.GetTempPath(), "veliq-existing-browsers-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var processes = new List<(System.Diagnostics.Process Process, int Pid, DateTime Created)>();
        try
        {
            foreach (var browser in installed)
            {
                var start = new System.Diagnostics.ProcessStartInfo(browser.ExePath) { UseShellExecute = false };
                foreach (var argument in new[] { "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--remote-debugging-port=0", "--user-data-dir=" + Path.Combine(directory, browser.Id), "about:blank" }) start.ArgumentList.Add(argument);
                var process = System.Diagnostics.Process.Start(start)!;
                processes.Add((process, process.Id, process.StartTime));
            }
            await Task.Delay(1500);
            Assert.All(processes, p => Assert.False(p.Process.HasExited));
            var service = new Service(); var vm = new DesktopViewModel(service);
            await vm.RefreshAsync(); await vm.EnsureStartupBrowserProfilesAsync(installed);
            Assert.All(processes, p => { p.Process.Refresh(); Assert.False(p.Process.HasExited); Assert.Equal(p.Pid, p.Process.Id); Assert.Equal(p.Created, p.Process.StartTime); });
            Assert.Equal(2, service.Inner.State.Profiles.Length);
        }
        finally
        {
            foreach (var p in processes) { if (!p.Process.HasExited) p.Process.Kill(true); await p.Process.WaitForExitAsync(); p.Process.Dispose(); }
            // Chromium descendants/antivirus can hold this owned temporary profile
            // after parent exit. Bounded cleanup does not weaken PID/birth assertions.
            for (var attempt = 0; attempt < 50; attempt++)
            {
                try { Directory.Delete(directory, true); break; }
                catch (IOException) when (attempt < 49) { await Task.Delay(100); }
                catch (UnauthorizedAccessException) when (attempt < 49) { await Task.Delay(100); }
            }
        }
    }
}
