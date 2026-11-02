namespace Neexitlag.Desktop;

// Never serialize an exception message, IPC payload, PAC, URL, nonce or records.
public sealed record FreshBrowserDiagnostic(string Browser, bool Listening, bool PolicyReady,
    string ReadinessState, string LastError, int ReadyProfiles, string QueryCode);
public static class FreshBrowserDiagnostics
{
    static readonly HashSet<string> Codes = new(StringComparer.Ordinal) {
        "BROWSER_PROFILE_AMBIGUOUS", "BROWSER_PROFILE_REGISTRATION_FAILED", "BROWSER_PROFILE_MODE_CONFLICT",
        "BROWSER_NOT_INSTALLED", "BROWSER_EXECUTABLE_UNAVAILABLE", "BROWSER_AUTO_NOT_COMMITTED", "BROWSER_PAC_NOT_READY",
        "BROWSER_ACTIVATION_CANCELLED", "CHROME_ACTIVATION_BUSY", "CHROME_ACTIVATION_FAILED",
        "CHROME_LISTENER_BIND_FAILED", "CHROME_PREPARE_FAILED", "CHROME_READINESS_NOT_OBSERVED", "CHROME_POLICY_NOT_OWNED",
        "CHROME_RECOVERY_START_FAILED", "CHROME_RECOVERY_FAILED", "CHROME_ROLLBACK_FAILED", "CHROME_POLICY_FAILED",
        "EDGE_READINESS_NOT_OBSERVED", "EDGE_READINESS_EXPIRED", "EDGE_PREPARE_REQUIRED", "EDGE_PROFILE_NOT_FOUND",
        "EDGE_RECOVERY_FAILED", "EDGE_BROWSER_POLICY_NOT_OBSERVED", "EDGE_POLICY_MANAGED", "EDGE_POLICY_ACCESS_DENIED",
        "EDGE_OWNER_SID_REQUIRED", "EDGE_LISTENER_BIND_FAILED", "EDGE_OPERATION_FAILED", "EDGE_IPC_ACCESS_DENIED",
        "EDGE_IPC_UNSUPPORTED", "EDGE_SERVICE_UNAVAILABLE", "EDGE_LAUNCH_FAILED", "EDGE_GUARD_STATE_WRITE_FAILED",
        "NATIVE_OWNED_PAC_GUARD_REQUIRED", "BROWSER_SERVICE_UNAVAILABLE", "BROWSER_SETUP_FAILED", "BROWSER_OPTIMIZE_FAILED"
    };
    public static string SafeCode(string? value) => Codes.FirstOrDefault(c =>
        value == c || value?.EndsWith(": " + c, StringComparison.Ordinal) == true) ?? "BROWSER_SETUP_FAILED";
    public static string ErrorCode(Exception error) => error switch {
        EdgeActivationException e => SafeCode(e.Code), ChromeActivationException c => SafeCode(c.Code),
        ServiceException s => s.Failure == ServiceFailure.AccessDenied ? "EDGE_IPC_ACCESS_DENIED" : "BROWSER_SERVICE_UNAVAILABLE",
        _ => "BROWSER_SETUP_FAILED"
    };
    public static string State(string? value) => value is "NOT_PREPARED" or "PREPARED" or "PAC_READY" or "READY"
        or "NATIVE_NEW_TCP" or "NATIVE_READY_NEW_CONNECTIONS" or "NATIVE_ONLY_OBSERVED" or "NATIVE_OPENED_NO_EXCHANGE" or "NATIVE_DISABLED" or "NATIVE_RELAY_PENDING" or "NOT_REQUIRED_FOR_NATIVE"
        or "AUTHORITY_TRANSPORT_PENDING" or "AUTHORITY_PENDING" or "AUTHORITY_REQUEST_OBSERVED" or "AUTHORITY_PROXY_APPLIED_UPTAKE_PENDING"
        or "PAC_NONCE_CONFIRMED" or "NATIVE_ARMED_PAC_GUARD" or "GUARDED"
        or "LISTENER_UNAVAILABLE" or "OWNER_NONCE_VERIFIED" or "NONCE_INVALIDATED" or "NONCE_EXPIRED"
        or "WAITING_FOR_BROWSER_REQUEST" or "NATIVE_CAPTURE_NOT_READY" or "NATIVE_ARMED_NO_NEW_FLOW"
        or "NATIVE_UPSTREAM_OPENED_NO_EXCHANGE" or "NATIVE_TUNNEL_OBSERVED" or "PAC_TUNNEL_OBSERVED_NATIVE_IDLE" or "POLICY_PENDING_BROWSER_REFRESH" or "PAC_REQUEST_OBSERVED" or "POLICY_OR_LISTENER_UNAVAILABLE" ? value : "UNKNOWN";
}
public sealed partial class DesktopViewModel
{
    public async Task<FreshBrowserDiagnostic[]> FreshBrowserDiagnosticsAsync(CancellationToken ct = default)
    {
        var rows = new List<FreshBrowserDiagnostic>(2);
        foreach (var edge in new[] { false, true })
        {
            try
            {
                if (edge) {
                    var s = await EdgeStatusAsync(ct);
                    rows.Add(new("edge",s.Listening,s.PolicyReady,FreshBrowserDiagnostics.State(s.ReadinessState),s.LastError == "" ? "" : FreshBrowserDiagnostics.SafeCode(s.LastError),s.ReadyProfiles.Length,"OK"));
                } else {
                    var s = await ChromeStatusAsync(ct);
                    rows.Add(new("chrome",s.Listening,s.PolicyReady,FreshBrowserDiagnostics.State(s.ReadinessState),s.LastError == "" ? "" : FreshBrowserDiagnostics.SafeCode(s.LastError),s.ReadyProfiles.Length,"OK"));
                }
            }
            catch (Exception e) when (!ct.IsCancellationRequested) { rows.Add(new(edge?"edge":"chrome",false,false,"UNKNOWN","",0,FreshBrowserDiagnostics.ErrorCode(e))); }
        }
        return rows.ToArray();
    }
}
