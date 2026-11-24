namespace Veliq.Desktop;

public sealed partial class DesktopViewModel
{
    readonly Dictionary<string, (string Phase, string Reason)> browserLaneIssues = new(StringComparer.Ordinal);
    NativeBrowserStatus? browserNativeReadiness;
    DateTimeOffset browserNativeReadAt;
    public string BrowserReadinessText { get; private set; } = "";
    HealthRow[] browserHealth = [];

    void RefreshBrowserReadiness(NativeBrowserStatus? native = null)
    {
        var now = DateTimeOffset.UtcNow;
        if (native is not null)
        {
            browserNativeReadiness = native;
            browserNativeReadAt = now;
        }
        else if (now - browserNativeReadAt <= TimeSpan.FromSeconds(10))
            native = browserNativeReadiness;

        var rows = new List<HealthRow>(2);
        var policy = Snapshot?.BrowserPolicy;
        if (Optimizing && policy is not null)
        {
            AddBrowser("Chrome", BrowserCatalog.IsChrome, policy.ChromeConfigured, policy.ChromeReady, policy.ChromeReason);
            AddBrowser("Edge", BrowserCatalog.IsEdge, policy.EdgeConfigured, policy.EdgeReady, policy.EdgeReason);
        }

        void AddBrowser(string name, Func<Profile, bool> matches, bool configured, bool ready, string reason)
        {
            var installed = Applications.Where(a => matches(a.Profile)).ToArray();
            var apps = installed.Where(a => a.Profile.Mode == "AUTO").ToArray();
            if (!configured && apps.Length == 0 && !browserLaneIssues.ContainsKey(name)) return;

            // An unknown process-list result is different from a known closed browser.
            var closed = installed.Length > 0 && installed.All(a => a.ProcessStatus == Text.Get("NotRunning"));
            var authority = native?.AuthorityTransport;
            var observed = native is { CaptureReady: true, Optimizing: true, State: "AUTHORITY_REQUEST_OBSERVED" }
                && authority?.SystemProxyApplied == true && (authority.Profiles ?? []).Any(proof => proof.Requests > 0 && proof.Exchanges > 0
                    && apps.Any(app => app.Profile.Id == proof.ProfileId && NativeBrowser(app.Profile)));

            if (closed)
                rows.Add(new(name, "не запущен", HealthLevel.Neutral));
            else if (browserLaneIssues.TryGetValue(name, out var issue))
                rows.Add(new(name, issue.Reason, HealthLevel.Warning));
            else if (observed || ready)
                rows.Add(new(name, "обмен подтверждён", HealthLevel.Ok));
            else if (reason is "" or "READY" or "AUTHORITY_EXCHANGE_OBSERVED" or "AUTHORITY_TRANSPORT_PENDING")
                rows.Add(new(name, "ожидается обмен", HealthLevel.Neutral));
            else
                rows.Add(new(name, BrowserReason(reason, "маршруты пока недоступны"), HealthLevel.Warning));
        }

        browserHealth = rows.ToArray();
        var summary = !Optimizing ? "Браузеры используют обычную сеть."
            : rows.Count == 0 ? "Для браузеров не настроена автоматическая маршрутизация."
            : string.Join("\n", rows.Select(row => $"{row.Name} — {row.State}"));
        if (BrowserReadinessText != summary)
        {
            BrowserReadinessText = summary;
            Changed(nameof(BrowserReadinessText));
        }
        HealthChanged();
    }

    void ClearBrowserLaneIssue(string browser, string phase)
    {
        if (browserLaneIssues.TryGetValue(browser, out var issue) && issue.Phase == phase)
        {
            browserLaneIssues.Remove(browser);
            RefreshBrowserReadiness();
        }
    }

    static string? BrowserName(Exception? error, string phase)
    {
        if (error is ChromeActivationException || phase.StartsWith("chrome.", StringComparison.Ordinal) || phase.EndsWith(".chrome", StringComparison.Ordinal))
            return "Chrome";
        if (error is EdgeActivationException || phase.StartsWith("edge.", StringComparison.Ordinal) || phase.EndsWith(".edge", StringComparison.Ordinal))
            return "Edge";
        return null;
    }

    static string BrowserReason(string? code, string fallback) => code switch
    {
        "ACTIVATION_REQUIRED" or "ACTIVATION_NOT_READY" => "требуется активация VELIQ",
        "AUTOMATIC_DISABLED" or "OPTIMIZATION_DISABLED" or "NATIVE_AUTOMATIC_DISABLED" => "автоматическая маршрутизация выключена",
        "CAPTURE_NOT_READY" or "NATIVE_CAPTURE_NOT_READY" or "NATIVE_CAPTURE_NOT_CONFIGURED" => "захват трафика ещё не готов",
        "CAPTURE_START_FAILED" or "NATIVE_CAPTURE_START_FAILED" => "не удалось запустить захват трафика",
        "RELAY_NOT_CONNECTED" => "соединение с релеем недоступно",
        "BROWSER_PROFILE_NOT_AUTO" or "NATIVE_BROWSER_PROFILE_REQUIRED" => "профиль AUTO не настроен",
        "CHROME_LISTENER_BIND_FAILED" or "EDGE_LISTENER_BIND_FAILED" or "CONNECT_LISTENER_UNAVAILABLE" => "не удалось запустить локальное подключение",
        "EDGE_POLICY_ACCESS_DENIED" or "EDGE_POLICY_OWNERSHIP_CHANGED" or "CHROME_POLICY_FAILED" => "не удалось применить настройки подключения",
        "CHROME_READINESS_NOT_OBSERVED" or "EDGE_READINESS_NOT_OBSERVED" or "EDGE_BROWSER_POLICY_NOT_OBSERVED" => "браузер ещё не применил настройки подключения",
        "CHROME_RECOVERY_START_FAILED" or "EDGE_RECOVERY_FAILED" => "не удалось запустить восстановление подключения",
        "IPC_UNAVAILABLE" or "EDGE_SERVICE_UNAVAILABLE" => "не удалось получить состояние подключения",
        _ => fallback
    };
}
