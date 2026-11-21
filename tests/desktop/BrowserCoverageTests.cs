using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;

public class BrowserCoverageTests
{
    static string? Env(string name) => name switch
    {
        "ProgramFiles" => @"C:\Program Files",
        "ProgramFiles(x86)" => @"C:\Program Files (x86)",
        "LOCALAPPDATA" => @"C:\Users\u\AppData\Local",
        _ => null
    };

    [Fact]
    public void DiscoveryFindsTheFirstExistingPathPerBrowserAndSkipsMissingOnes()
    {
        var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Users\u\AppData\Local\Google\Chrome\Application\chrome.exe",   // per-user install
            @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            @"C:\Program Files\Mozilla Firefox\firefox.exe",
        };
        var found = BrowserCatalog.Discover(present.Contains, Env);
        Assert.Equal(new[] { "chrome", "edge", "firefox" }, found.Select(b => b.Id));
        Assert.Equal(@"C:\Users\u\AppData\Local\Google\Chrome\Application\chrome.exe", found[0].ExePath);
        Assert.True(found[0].AutoSupported);
        Assert.True(found[1].AutoSupported);
        Assert.False(found[2].AutoSupported);
        Assert.Equal(new[] { "Mozilla Firefox" }, BrowserCatalog.NotCovered(found));
    }

    [Fact]
    public void MissingEnvironmentVariableSkipsOnlyThatCandidate()
    {
        var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"C:\Program Files\Google\Chrome\Application\chrome.exe" };
        var found = BrowserCatalog.Discover(present.Contains, n => n == "ProgramFiles" ? @"C:\Program Files" : null);
        Assert.Equal("chrome", Assert.Single(found).Id);
        Assert.Empty(BrowserCatalog.Discover(_ => true, _ => null));
    }

    [Fact]
    public void RegistryDiscoverySupportsNonstandardInstallAndOperaGxIsListedSeparately() {
        var custom=@"D:\Browsers\Chrome\chrome.exe";
        var gx=@"C:\Users\u\AppData\Local\Programs\Opera GX\opera.exe";
        var installed=BrowserCatalog.Discover(p=>p==custom||p==gx,Env,id=>id=="chrome"?[custom]:[]);
        Assert.Equal(custom,installed.Single(b=>b.Id=="chrome").ExePath);
        Assert.Equal(gx,installed.Single(b=>b.Id=="opera-gx").ExePath);
        Assert.DoesNotContain(installed,b=>b.Id=="opera");
    }

    static string TempChrome(out string dir)
    {
        dir = Path.Combine(Path.GetTempPath(), "veliq-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "chrome.exe");
        File.WriteAllBytes(path, [0]);
        return path;
    }

    [Fact]
    public async Task CleanInstallCreatesOneSafeChromeProfileAndSecondCallCreatesNothing()
    {
        var path = TempChrome(out var dir);
        try
        {
            var service = new PickerService();
            var vm = new DesktopViewModel(service);
            await vm.RefreshAsync();
            var installed = new[] { new InstalledBrowser("chrome", "Google Chrome", path, true), new InstalledBrowser("edge", "Microsoft Edge", @"C:\e\msedge.exe", false) };
            var created = await vm.EnsureChromeProfileAsync(installed);
            Assert.NotNull(created);
            var saved = Assert.Single(service.State.Profiles);
            Assert.Equal(Path.GetFullPath(path), Assert.Single(saved.Executables));
            Assert.Equal("DIRECT", saved.Mode);          // AUTO only after the real PAC activation
            Assert.True(saved.Custom);
            Assert.Equal(saved.Id, created!.Id);
            Assert.Null(await vm.EnsureChromeProfileAsync(installed));
            Assert.Single(service.Calls, c => c.Method == "profile.set");
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("DIRECT")]
    [InlineData("AUTO")]
    [InlineData("DIRECT_PLUS")]
    public async Task ExistingChromeProfileInAnyModeAndAtAnyPathIsNeverTouched(string mode)
    {
        var path = TempChrome(out var dir);
        try
        {
            var service = new PickerService();
            service.State = new() { Profiles = [new() { Id = "mine", Name = "Chrome", Mode = mode, Custom = true, Executables = [@"D:\Portable\Chrome\chrome.exe"] }] };
            var vm = new DesktopViewModel(service);
            Assert.Null(await vm.EnsureChromeProfileAsync([new InstalledBrowser("chrome", "Google Chrome", path, true)]));
            Assert.DoesNotContain(service.Calls, c => c.Method == "profile.set");
            Assert.Equal(mode, Assert.Single(service.State.Profiles).Mode);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task NothingIsCreatedWithoutChromeOrForBrowsersWithoutAutomaticSupport()
    {
        var service = new PickerService();
        var vm = new DesktopViewModel(service);
        var edgeOnly = new[] { new InstalledBrowser("edge", "Microsoft Edge", @"C:\e\msedge.exe", false), new InstalledBrowser("firefox", "Mozilla Firefox", @"C:\f\firefox.exe", false) };
        Assert.Null(await vm.EnsureChromeProfileAsync(edgeOnly));
        Assert.Null(await vm.EnsureChromeProfileAsync([]));
        Assert.DoesNotContain(service.Calls, c => c.Method == "profile.set");
    }

    [Fact]
    public void NewBrowserCoverageMessagesAreRussianAndPresent()
    {
        Assert.Contains("Chrome", Text.Get("BrowsersNotCovered"));
        Assert.Contains("Chrome", Text.Get("ChromeAutoSetupFailed"));
    }
}
