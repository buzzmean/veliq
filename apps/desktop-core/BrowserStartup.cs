using System.Diagnostics;

namespace Neexitlag.Desktop;

// Native AUTO configuration is separate from armed capture and Optimize.
// This report describes profiles, not browser/network readiness.
public sealed record BrowserStartupEntry(string Browser, string State, string ProfileId, string Mode, string ExePath, string Code);
public sealed record BrowserStartupReport(DateTimeOffset Started, DateTimeOffset Completed, long ElapsedMs, BrowserStartupEntry[] Browsers);

public sealed partial class DesktopViewModel
{
    readonly HashSet<string> startupChromeProfiles = [];
    bool browserStartupComplete;
    public BrowserStartupReport? BrowserStartup { get; private set; }
    public string BrowserStartupSummary => BrowserStartup is null
        ? "Профили браузеров: ожидается подключение к службе"
        : "Профили браузеров: " + string.Join("; ", BrowserStartup.Browsers.Select(b => $"{b.Browser}: {b.State} {b.Mode} {b.Code}"))
          + ". Регистрация не подтверждает PAC или доступность сайтов.";

    public static bool CanAdoptDefaultBrowser(Profile p) =>
        !NativeBrowser(p) && !(p.PolicyData is {} offData && offData.TryGetValue("browser_auto_disabled",out var off) && off.ValueKind==System.Text.Json.JsonValueKind.True) &&
        (p.Mode=="AUTO" || p.Mode=="DIRECT" && string.IsNullOrEmpty(p.LocalStrategyId) &&
          !(p.PolicyData is {} d && (d.TryGetValue("rules",out var rules) && rules.ValueKind==System.Text.Json.JsonValueKind.Array && rules.GetArrayLength()>0
            || d.TryGetValue("app_preset",out var preset) && preset.ValueKind==System.Text.Json.JsonValueKind.String && preset.GetString() is not (null or "" or "edge-sites" or "edge-sites-pending"))));
    public static Profile NativeAutoProfile(Profile original) {
        var p=original.Copy();p.Mode="AUTO";p.PolicyData??=new();
        p.PolicyData["browser_transport"]=System.Text.Json.JsonSerializer.SerializeToElement("native");
        p.PolicyData["browser_auto_disabled"]=System.Text.Json.JsonSerializer.SerializeToElement(false);
        if(BrowserCatalog.IsEdge(p) && (!p.PolicyData.TryGetValue("app_preset",out var preset)||preset.ValueKind!=System.Text.Json.JsonValueKind.String||preset.GetString() is "" or "edge-sites-pending"))p.PolicyData["app_preset"]=System.Text.Json.JsonSerializer.SerializeToElement("edge-sites");
        return p;
    }
    // Track Chrome created on startup for quiet PAC preparation on Optimize.
    // Existing DIRECT/custom profiles never enter this set.
    public bool StartupChromeNeedsActivation(Profile profile) => profile.Mode == "DIRECT" && startupChromeProfiles.Contains(profile.Id);

    public async Task EnsureStartupBrowserProfilesAsync(IReadOnlyList<InstalledBrowser> installed, CancellationToken ct = default)
    {
        await gate.WaitAsync(ct);
        try
        {
            if (browserStartupComplete) return;
            Busy = true;
            var started = DateTimeOffset.UtcNow;
            var watch = Stopwatch.StartNew();
            var rows = new List<BrowserStartupEntry>(2);
            foreach (var browser in new[] { "chrome", "edge" })
            {
                var found = installed.FirstOrDefault(b => b.Id == browser && b.AutoSupported);
                if (found is null)
                {
                    rows.Add(new(browser, "NOT_INSTALLED", "", "", "", ""));
                    continue;
                }
                try
                {
                    var profiles = await client.Call<Profile[]>("profiles", cancellationToken: ct);
                    var existing = profiles.FirstOrDefault(p => browser == "chrome" ? BrowserCatalog.IsChrome(p) : BrowserCatalog.IsEdge(p));
                    if (existing is not null)
                    {
                        if (CanAdoptDefaultBrowser(existing)) {
                            var adopted=NativeAutoProfile(existing);
                            var adoptedProfiles=await client.Call<Profile[]>("profile.set",adopted,ct);
                            if(Snapshot is {} adoptedSnapshot)adoptedSnapshot.Profiles=adoptedProfiles;
                            foreach(var row in Applications.Where(a=>a.Profile.Id==adopted.Id))row.Update(adopted,null,null);
                            rows.Add(new(browser,"AUTO_CONFIGURED",adopted.Id,adopted.Mode,adopted.Executables.FirstOrDefault()??"",""));
                        } else rows.Add(new(browser, "EXISTING", existing.Id, existing.Mode, existing.Executables.FirstOrDefault() ?? "", ""));
                        continue;
                    }
                    if (!Path.IsPathFullyQualified(found.ExePath) || !found.ExePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(found.ExePath))
                        throw new InvalidOperationException("Invalid installed browser path");
                    var path = Path.GetFullPath(found.ExePath);
                    var profile = new Profile
                    {
                        Id = "custom-" + Guid.NewGuid().ToString("N"), Name = found.Name,
                        Executables = [path], Mode = "DIRECT", Custom = true
                    };
                    profile = NativeAutoProfile(profile);
                    var saved = await client.Call<Profile[]>("profile.set", profile, ct);
                    if (Snapshot is { } snapshot) snapshot.Profiles = saved;
                    foreach (var p in saved)
                    {
                        if (Applications.Any(a => a.Profile.Id == p.Id)) continue;
                        var row = new ApplicationRow(); row.Update(p, null, null); Applications.Add(row);
                    }

                    rows.Add(new(browser, "AUTO_CONFIGURED", profile.Id, profile.Mode, path, ""));
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception error)
                {
                    // Optional startup work must not clear an authenticated table or
                    // persist raw IPC exception text (which can contain secrets).
                    var code = error is EdgeActivationException edge ? edge.Code
                        : error is ServiceException ipc ? "IPC_" + ipc.Failure.ToString().ToUpperInvariant()
                        : "BROWSER_PROFILE_REGISTRATION_FAILED";
                    rows.Add(new(browser, "FAILED", "", "", found.ExePath, code));
                    ReportBrowserPreparationFailure(error, "browser.startup." + browser);
                }
            }
            BrowserStartup = new(started, DateTimeOffset.UtcNow, watch.ElapsedMilliseconds, rows.ToArray());
            browserStartupComplete = rows.All(r => r.State is not ("FAILED" or "DEFERRED"));
            Changed(nameof(BrowserStartup)); Changed(nameof(BrowserStartupSummary));
        }
        finally { Busy = false; gate.Release(); }
    }
}
