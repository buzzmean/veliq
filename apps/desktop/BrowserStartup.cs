using System.Text.Json;

namespace Veliq.Desktop;

public partial class MainWindow
{
    DateTimeOffset nextBrowserStartup;
    BrowserStartupReport? savedBrowserStartup;
    async Task RegisterStartupBrowsersAsync()
    {
        if (model.Activation?.Status.CapturePermitted==false || !model.Available || model.Busy || DateTimeOffset.UtcNow < nextBrowserStartup) return;
        nextBrowserStartup = DateTimeOffset.UtcNow.AddSeconds(model.Snapshot?.BrowserPolicy is {ChromeReady:true,EdgeReady:true}?10:2);
        await model.EnsureStartupBrowserProfilesAsync(BrowserDiscovery.Installed(), lifetime.Token);
        await model.EnsureBrowserOptimizationOnStartupAsync(lifetime.Token);
        if(model.Optimizing && model.Snapshot?.Settings.Automatic==true && model.Snapshot?.Connected==true)await PrepareNativeBrowsersAsync();
        if (ReferenceEquals(savedBrowserStartup, model.BrowserStartup) || model.BrowserStartup is null) return;
        // Bounded, owner-user report; no policy, tokens, certificates or payloads.
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VELIQ");
        Directory.CreateDirectory(folder);
        var report = Path.Combine(folder, "browser-startup.json");
        var pending = report + ".pending";
        try
        {
            await File.WriteAllTextAsync(pending, JsonSerializer.Serialize(model.BrowserStartup, WireJson.Options), lifetime.Token);
            File.Move(pending, report, true);
            savedBrowserStartup = model.BrowserStartup;
        }
        finally { if (File.Exists(pending)) File.Delete(pending); }
    }
}
