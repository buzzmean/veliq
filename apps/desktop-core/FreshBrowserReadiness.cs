namespace Neexitlag.Desktop;

// Explicit fresh/repair transaction. Ordinary GUI startup still preserves user modes.
public sealed partial class DesktopViewModel
{
    public async Task<Profile[]> PrepareFreshBrowserProfilesAsync(IReadOnlyList<InstalledBrowser> installed, CancellationToken ct = default)
    {
        var result = new List<Profile>(2);
        foreach (var browser in installed.Where(b => b.Id is "chrome" or "edge"))
        {
            if (!Path.IsPathFullyQualified(browser.ExePath) || !File.Exists(browser.ExePath))
                throw new ChromeActivationException("Installed browser path is unavailable", "profiles", "BROWSER_EXECUTABLE_UNAVAILABLE");
            var path = Path.GetFullPath(browser.ExePath);
            var profiles = await client.Call<Profile[]>("profiles", cancellationToken: ct);
            var matching = profiles.Where(p => p.Executables.Any(e => SameExecutable(e, path))).ToArray();
            if (matching.Length > 1) throw new ChromeActivationException("Ambiguous browser profiles", "profiles", "BROWSER_PROFILE_AMBIGUOUS");
            if (matching.Length == 0)
            {
                // DIRECT staging is safe even when the freshly installed service
                // already optimizes other apps. No pending AUTO/capture or PAC yet.
                if (!await AddApplicationAsync(path, ct))
                    throw new ChromeActivationException("Cannot register browser", "profiles", "BROWSER_PROFILE_REGISTRATION_FAILED");
                profiles = await client.Call<Profile[]>("profiles", cancellationToken: ct);
                matching = profiles.Where(p => p.Executables.Any(e => SameExecutable(e, path))).ToArray();
            }
            if (matching.Length != 1 || matching[0].Mode is not ("DIRECT" or "AUTO"))
                throw new ChromeActivationException("Explicit custom browser mode preserved", "profiles", "BROWSER_PROFILE_MODE_CONFLICT");
            result.Add(matching[0].Copy());
        }
        if (result.Count == 0) throw new ChromeActivationException("No supported installed browser", "profiles", "BROWSER_NOT_INSTALLED");
        await RefreshAsync(ct);
        return result.ToArray();
    }

    public async Task<Profile[]> PrepareAutomaticBrowserProfilesAsync(IReadOnlyList<InstalledBrowser> installed,CancellationToken ct=default) {
        await EnsureStartupBrowserProfilesAsync(installed,ct);
        var profiles=await client.Call<Profile[]>("profiles",cancellationToken:ct);
        var result=profiles.Where(p=>NativeBrowser(p)&&p.Mode=="AUTO").ToArray();
        if(installed.Any(b=>b.AutoSupported)&&result.Length==0)throw new ChromeActivationException("Browser profiles not prepared","profiles","BROWSER_AUTO_NOT_COMMITTED");
        return result;
    }
    public async Task VerifyNativeBrowserAsync(string id,CancellationToken ct=default) {
        var profiles=await client.Call<Profile[]>("profiles",cancellationToken:ct);
        var status=await client.Call<NativeBrowserStatus>("browser.native.status",cancellationToken:ct);
        if(!profiles.Any(p=>p.Id==id&&p.Mode=="AUTO"&&NativeBrowser(p))||!status.CaptureReady||!status.Optimizing)
            throw new ChromeActivationException("Native path not armed","verify_native","NATIVE_CAPTURE_NOT_READY");
        if(!status.AuthorityTransport.SystemProxyApplied)
            throw new ChromeActivationException("Owner authority transport not applied","verify_native","AUTHORITY_TRANSPORT_NOT_APPLIED");
    }

    public async Task VerifyFreshBrowserAsync(string id, bool edge, CancellationToken ct = default)
    {
        var profiles = await client.Call<Profile[]>("profiles", cancellationToken: ct);
        if (!profiles.Any(p => p.Id == id && p.Mode == "AUTO"))
            throw new ChromeActivationException("Browser remained outside AUTO", "verify_pac", "BROWSER_AUTO_NOT_COMMITTED");
        if (edge)
        {
            var s = await EdgeStatusAsync(ct);
            if (s.Listening && s.PolicyReady && (s.ReadyProfiles.Contains(id)||s.SilentActivation.ConfiguredProfiles.Contains(id))) return;
        }
        else
        {
            var s = await ChromeStatusAsync(ct);
            if (s.Listening && s.PolicyReady && (s.ReadyProfiles.Contains(id)||s.SilentActivation.ConfiguredProfiles.Contains(id))) return;
        }
        throw new ChromeActivationException("Actual PAC/owner proof missing", "verify_pac", "BROWSER_PAC_NOT_READY");
    }
}
