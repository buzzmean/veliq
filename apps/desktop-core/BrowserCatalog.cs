namespace Veliq.Desktop;

public sealed record InstalledBrowser(string Id, string Name, string ExePath, bool AutoSupported);

// Which browsers exist on this PC and which of them VELIQ can route on its own.
// Chrome and Edge have independent automatic lanes (owned policy, PAC, recovery listener,
// readiness proof). Registration at GUI startup does not activate these lanes:
// Chrome and Edge stage DIRECT; quiet activation commits AUTO after listeners/policy.
public static class BrowserCatalog
{
    sealed record Entry(string Id, string Name, bool AutoSupported, string[] Candidates);
    // %Variables% are expanded from the environment; candidates with an unset variable are skipped.
    static readonly Entry[] Entries =
    [
        new("chrome", "Google Chrome", true,
            [@"%ProgramFiles%\Google\Chrome\Application\chrome.exe", @"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe", @"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"]),
        new("edge", "Microsoft Edge", true,
            [@"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe", @"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"]),
        new("firefox", "Mozilla Firefox", false,
            [@"%ProgramFiles%\Mozilla Firefox\firefox.exe", @"%ProgramFiles(x86)%\Mozilla Firefox\firefox.exe"]),
        new("brave", "Brave", false,
            [@"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe", @"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\brave.exe"]),
        new("yandex", "Яндекс Браузер", false,
            [@"%LOCALAPPDATA%\Yandex\YandexBrowser\Application\browser.exe"]),
        new("opera-gx", "Opera GX", false,
            [@"%LOCALAPPDATA%\Programs\Opera GX\opera.exe", @"%ProgramFiles%\Opera GX\opera.exe"]),
        new("opera", "Opera", false,
            [@"%LOCALAPPDATA%\Programs\Opera\opera.exe", @"%ProgramFiles%\Opera\opera.exe"]),
        new("vivaldi", "Vivaldi", false,
            [@"%LOCALAPPDATA%\Vivaldi\Application\vivaldi.exe", @"%ProgramFiles%\Vivaldi\Application\vivaldi.exe"]),
    ];

    public static IReadOnlyList<InstalledBrowser> Discover(Func<string, bool> exists, Func<string, string?> environment, Func<string,IEnumerable<string>>? registered = null)
    {
        var found = new List<InstalledBrowser>();
        foreach (var entry in Entries)
        {
            var registryPaths=(registered?.Invoke(entry.Id)??[]).Take(32).Where(p=>p.Length>3&&char.IsLetter(p[0])&&p[1]==':'&&p[2]=='\\'&&p.EndsWith(".exe",StringComparison.OrdinalIgnoreCase));
            foreach (var template in registryPaths.Concat(entry.Candidates))
            {
                var path = Expand(template, environment);
                if (path is null || !exists(path)) continue;
                found.Add(new InstalledBrowser(entry.Id, entry.Name, path, entry.AutoSupported));
                break;
            }
        }
        return found;
    }

    static string? Expand(string template, Func<string, string?> environment, Func<string,IEnumerable<string>>? registered = null)
    {
        var result = template;
        foreach (var name in new[] { "ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA" })
        {
            var token = "%" + name + "%";
            if (!result.Contains(token, StringComparison.Ordinal)) continue;
            var value = environment(name);
            // Environment values must be absolute Windows paths (X:\...). Checked by shape, not
            // Path.IsPathFullyQualified, so the logic is identical on every OS the tests run on.
            if (string.IsNullOrWhiteSpace(value) || value.Length < 3 || !char.IsLetter(value[0]) || value[1] != ':' || value[2] != '\\') return null;
            result = result.Replace(token, value.TrimEnd('\\'), StringComparison.Ordinal);
        }
        return result;
    }

    public static bool IsChrome(Profile profile) =>
        profile.Executables.Any(p => p.Replace('\\', '/').Split('/').Last().Equals("chrome.exe", StringComparison.OrdinalIgnoreCase));

    public static bool IsEdge(Profile profile) =>
        profile.Executables.Any(p => p.Replace('\\', '/').Split('/').Last().Equals("msedge.exe", StringComparison.OrdinalIgnoreCase));

    // Installed browsers that VELIQ does not route automatically, by display name.
    public static string[] NotCovered(IEnumerable<InstalledBrowser> installed) =>
        installed.Where(b => !b.AutoSupported).Select(b => b.Name).ToArray();
}
