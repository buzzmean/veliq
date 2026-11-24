namespace Veliq.Desktop;

public partial class MainWindow
{
    bool nativeBrowsersActivating;
    readonly Dictionary<string, DateTimeOffset> nativeBrowserRetry = [];
    async Task PrepareNativeBrowsersAsync(bool forOptimize = false)
    {
        if (chromeActivating || edgeActivating || nativeBrowsersActivating || !model.Available || model.Busy || model.Snapshot?.Settings.Automatic!=true || (!forOptimize && !model.Optimizing)) return;
        nativeBrowsersActivating = true;
        try
        {
            foreach (var p in model.Applications.Select(a => a.Profile.Copy()).Where(model.NativeBrowserCandidate).ToArray())
            {
                // Idempotent enable repairs an owned Edge guard/listener after service restart.
                if (!forOptimize && nativeBrowserRetry.TryGetValue(p.Id, out var at) && at > DateTimeOffset.UtcNow) continue;
                // Native ingress never waits for browser policy or PAC uptake.
                nativeBrowserRetry[p.Id] = DateTimeOffset.UtcNow.AddSeconds(2);
                var browser=BrowserCatalog.IsEdge(p)?"edge":"chrome";
                var phase=browser+".native.enable";
                try {
                    await model.EnableNativeBrowserAsync(p, lifetime.Token);
                    model.ClearBrowserPreparationFailure(phase);
                    nativeBrowserRetry[p.Id]=DateTimeOffset.UtcNow.AddSeconds(30);
                    phase=browser+".native.recovery";
                    // Restore existing owner-scoped recovery only; never create PAC
                    // or a new browser profile, and never launch/quit a browser.
                    if (BrowserCatalog.IsEdge(p)) {
                        if (!edgeLifetimeHook) { Closed += (_,_) => edgeRecovery.Dispose(); edgeLifetimeHook=true; }
                        if (File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VELIQ", "edge-recovery.json")))
                            await edgeRecovery.StartAsync(lifetime.Token);
                    } else if (ChromePolicy.Monitored || File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VELIQ", "chrome-recovery.json"))) await chromeRecovery.StartAsync(lifetime.Token);
                    model.ClearBrowserPreparationFailure(phase);

                }
                catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { throw; }
                catch (Exception error)
                {
                    model.ReportBrowserPreparationFailure(error,phase);
                }
            }
            await model.ObserveAuxiliaryAsync(() => model.ObserveNativeBrowsersAsync(lifetime.Token), "browser.native.status", lifetime.Token);
        }
        finally { nativeBrowsersActivating = false; }
    }
}
