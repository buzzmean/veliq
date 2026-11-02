using System.Text.Json;

namespace Neexitlag.Desktop;

public partial class App
{
    // Explicit quiet bootstrap; policy uptake is reported separately.
    internal static string? FreshPCSetupArguments(string[] args)
    {
        if (!args.Contains("--fresh-pc-setup")) return null;
        if (args.Length != 2 || args[0] != "--fresh-pc-setup" || !Path.IsPathFullyQualified(args[1]))
            throw new ArgumentException("Invalid fresh-PC setup arguments");
        var path = Path.GetFullPath(args[1]);
        var parent = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(parent) || File.Exists(path) || (File.GetAttributes(parent) & FileAttributes.ReparsePoint) != 0)
            throw new ArgumentException("Fresh-PC report must be a new file in a real owner directory");
        return path;
    }
}

public partial class MainWindow
{
    internal async Task RunFreshPCSetupAsync(string report)
    {
        timer.Stop();
        var phase = "service";
        bool pass = false;
        string errorClass = "";
        string code = "BROWSER_SETUP_FAILED";
        string browser = "both";
        try
        {
            await model.RefreshAsync(lifetime.Token);
            if (!model.Available) throw new IOException("Служба недоступна");
            phase = "profiles";
            var profiles = await model.PrepareAutomaticBrowserProfilesAsync(BrowserDiscovery.Installed(), lifetime.Token);
            phase="optimize";
            await model.OptimizeAsync(true,lifetime.Token);
            if(!model.Optimizing)throw new ChromeActivationException("Capture not enabled","optimize","BROWSER_OPTIMIZE_FAILED");
            phase="native_prepare";
            foreach(var profile in profiles)await model.EnableNativeBrowserAsync(profile,lifetime.Token);
            phase="verify_native";
            foreach(var profile in profiles)await model.VerifyNativeBrowserAsync(profile.Id,lifetime.Token);
            pass = true;
            phase = "ready"; code = "OK"; browser = "both";
        }
        catch (Exception error)
        {
            // Fixed safe report, never serialize IPC payloads/certs/tokens or an
            // arbitrary exception. Existing activation already installs guard.
            errorClass = error.GetType().Name;
            code = FreshBrowserDiagnostics.ErrorCode(error);
            if (error is ChromeActivationException chrome) phase = chrome.Phase;
            if (error is EdgeActivationException edge) phase = edge.Phase;
            model.ReportActionFailure(error);
        }
        finally
        {
            var states = await model.FreshBrowserDiagnosticsAsync(CancellationToken.None);
            var pending = report + "." + Guid.NewGuid().ToString("N") + ".pending";
            try {
                await using (var file = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    await JsonSerializer.SerializeAsync(file, new { pass, stage = phase, code, browser, states, error_class = errorClass, scope = "native capture armed; owner CONNECT configured; browser uptake and Internet pages require acceptance" });
                File.Move(pending, report);
            }
            finally { if (File.Exists(pending)) File.Delete(pending); timer.Start(); }
        }
    }
}
