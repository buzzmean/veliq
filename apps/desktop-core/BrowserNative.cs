using System.Text.Json;

namespace Neexitlag.Desktop;

public sealed class NativeBrowserStatus
{
    public string State {get;set;}="";
    public string Reason {get;set;}="";
    public string NativeOnlyState {get;set;}="";
    public BrowserAuthorityStatus AuthorityTransport { get; set; } = new();
    public int Version { get; set; }
    public bool CaptureReady { get; set; }
    public bool Optimizing { get; set; }
    public string ExistingTcp { get; set; } = "";
    public NativeBrowserTiming[] Profiles { get; set; } = [];
    public NativeBrowserRecord[] Records { get; set; } = [];
    public bool Truncated { get; set; }
    public ulong Lost { get; set; }
}
public sealed class BrowserAuthorityStatus
{
    public string State { get; set; } = "";
    public bool SystemProxyApplied { get; set; }
    public int SafeFallbackRequests { get; set; }
    public BrowserAuthorityProof[] Profiles { get; set; } = [];
}
public sealed class BrowserAuthorityProof
{
    public string ProfileId { get; set; } = "";
    public int Requests { get; set; }
    public int Exchanges { get; set; }
}
public sealed class NativeBrowserTiming
{
    public string ProfileId { get; set; } = "";
    public ulong Opened { get; set; }
    public ulong Accepted { get; set; }
    public ulong Failed { get; set; }
    public NativeIngressProof NativeOnly { get; set; } = new();
    public long EnableToFirstOpenMs { get; set; } = -1;
    public long EnableToFirstExchangeMs { get; set; } = -1;
}
public sealed class NativeIngressProof
{
    public ulong BidirectionalExchanges { get; set; }
    public ulong SentBytes { get; set; }
    public ulong ReceivedBytes { get; set; }
}
public sealed class NativeBrowserRecord
{
    public string Ingress { get; set; } = "";
    public ulong Id { get; set; }
    public BrowserOwner Owner { get; set; } = new();
    public DateTimeOffset Started { get; set; }
    public string Domain { get; set; } = "";
    public FlowPolicyEvidence Policy { get; set; } = new();
    public string OriginProbe { get; set; } = "";
    public string Result { get; set; } = "";
    public string FailureReason { get; set; } = "";
    public ulong SentBytes { get; set; }
    public ulong ReceivedBytes { get; set; }
    public bool Active { get; set; }
    public BrowserConnection Connection() => new() { Id = Id, Owner = Owner, Started = Started, Domain = Domain,
        Plan = new() { Policy = Policy, Probe = OriginProbe }, Result = Result, OpenFailure = FailureReason,
        SentBytes = SentBytes, ReceivedBytes = ReceivedBytes, Active = Active, EvidenceSource = Ingress == "" ? "NATIVE_TCP" : Ingress };
}
public sealed partial class DesktopViewModel
{
    public string BrowserReadinessText {get;private set;}="Подготавливаем браузер…";
    public void ApplyNativeBrowserReadiness(NativeBrowserStatus status){
        var configured = Applications.Where(a => NativeBrowser(a.Profile) && a.Profile.Mode == "AUTO").Select(a => a.Profile.Id).ToArray();
        var authority=status.AuthorityTransport;
        var observed = authority.SystemProxyApplied && configured.Any(id => authority.Profiles.Any(p => p.ProfileId == id && p.Requests > 0 && p.Exchanges > 0));
        var next=!Optimizing?"Браузеры используют обычную сеть.":status.CaptureReady&&status.Optimizing&&status.State=="AUTHORITY_REQUEST_OBSERVED"&&observed
          ?"Браузер: обмен по адресатам подтверждён."
          :status.CaptureReady&&status.Optimizing&&status.State=="AUTHORITY_PENDING"
          ?"Подготавливаем браузер: временно используется защищённый маршрут."
          :"Подготавливаем браузер…";
        if(BrowserReadinessText!=next){BrowserReadinessText=next;Changed(nameof(BrowserReadinessText));HealthChanged();}
    }
    public static bool NativeBrowser(Profile p) => p.PolicyData is { } data && data.TryGetValue("browser_transport", out var v)
        && v.ValueKind == JsonValueKind.String && v.GetString() == "native";
    public bool NativeBrowserCandidate(Profile p) => (BrowserCatalog.IsChrome(p) || BrowserCatalog.IsEdge(p))
        && (p.Mode == "AUTO" || NativeBrowser(p) || StartupChromeNeedsActivation(p)
            || p.Mode == "DIRECT" && p.PolicyData is { } data && data.TryGetValue("app_preset", out var v) && v.ValueKind == JsonValueKind.String && v.GetString() == "edge-sites-pending");
    public static string NativeBrowserErrorCode(Exception error)
    {
        string[] codes = ["NATIVE_OPTIMIZATION_DISABLED", "CAPTURE_START_FAILED", "NATIVE_OWNED_PAC_GUARD_REQUIRED", "NATIVE_CAPTURE_NOT_READY", "NATIVE_CAPTURE_NOT_CONFIGURED", "NATIVE_CAPTURE_START_FAILED", "NATIVE_AUTOMATIC_DISABLED", "NATIVE_OWNER_SID_REQUIRED", "NATIVE_BROWSER_PROFILE_REQUIRED", "NATIVE_PROFILE_PERSIST_FAILED", "EDGE_LISTENER_BIND_FAILED", "EDGE_POLICY_OWNERSHIP_CHANGED", "CHROME_LISTENER_BIND_FAILED", "NATIVE_GUARD_ADDRESS_CHANGED"];
        return codes.OrderByDescending(c=>c.Length).FirstOrDefault(c => error.Message.Contains(c, StringComparison.Ordinal))
            ?? (error.Message.Contains("unsupported IPC", StringComparison.OrdinalIgnoreCase) ? "NATIVE_IPC_UNSUPPORTED" : "NATIVE_ACTIVATION_FAILED");
    }
    public async Task EnableNativeBrowserAsync(Profile p, CancellationToken ct = default)
    {
        // Endpoint validates owner/capture; authority PAC uptake is observed separately.
        // A refusal never starts or closes browser processes.
        await client.Call<JsonElement>("browser.native.enable", new { profile_id = p.Id }, ct);
        startupChromeProfiles.Remove(p.Id);
        await RefreshAsync(ct);
    }
    // Explicit user's Disable PAC action, unlike automatic failure rollback.
    // Caller keeps the owned guard; there is never an unguarded interval.
    public async Task<JsonElement> DisableNativeBrowserAsync(Profile original, CancellationToken ct = default)
    {
        var copy=original.Copy();copy.Mode="DIRECT";copy.PolicyData ??= new();
        copy.PolicyData["browser_transport"]=JsonSerializer.SerializeToElement("");
        copy.PolicyData["browser_auto_disabled"]=JsonSerializer.SerializeToElement(true);
        if(BrowserCatalog.IsEdge(copy)) copy.PolicyData["app_preset"]=JsonSerializer.SerializeToElement("edge-sites");
        await client.Call<Profile[]>("profile.set",copy,ct);
        startupChromeProfiles.Remove(copy.Id);
        var applied=BrowserCatalog.IsEdge(copy)?await EdgePolicyAsync(copy,"guard",ct):JsonSerializer.SerializeToElement(new{applied=true,guard=true});
        await RefreshAsync(ct);return applied;
    }
    public static BrowserTransportSnapshot CombineBrowserPaths(BrowserTransportSnapshot pac, BrowserConnection[] native, NativeBrowserStatus status, IReadOnlySet<string>? profiles = null) => new()
    {
        Listening = pac.Listening || status.CaptureReady,
        Records = pac.Records.Concat(native.Where(r => profiles is null || profiles.Contains(r.Owner.ProfileId))).ToArray(),
        Truncated = pac.Truncated || status.Truncated, Lost = pac.Lost + status.Lost,
        ReadyProfiles = pac.ReadyProfiles, RecoveryAddress = pac.RecoveryAddress, SilentActivation=pac.SilentActivation, PolicyReady=pac.PolicyReady, ReadinessState=pac.ReadinessState
    };
    public async Task ObserveNativeBrowsersAsync(CancellationToken ct = default)
    {
        if (!Applications.Any(a => NativeBrowser(a.Profile))) return;
        var status = await client.Call<NativeBrowserStatus>("browser.native.status", cancellationToken: ct);
        ApplyNativeBrowserReadiness(status);
        // An empty native ledger must never replace a working PAC snapshot.
        // A PAC ingress may delegate an upstream into native: label both pieces,
        // never count them as two independent requests or a native-only PASS.
        var records = status.Records.Select(r => r.Connection()).ToArray();
        if (Applications.Any(a => BrowserCatalog.IsChrome(a.Profile) && NativeBrowser(a.Profile)))
        {
            var pac = await ChromeStatusAsync(ct);
            ApplyBrowser(CombineBrowserPaths(pac, records, status, Applications.Where(a => BrowserCatalog.IsChrome(a.Profile)).Select(a => a.Profile.Id).ToHashSet(StringComparer.Ordinal)));
        }
        if (Applications.Any(a => BrowserCatalog.IsEdge(a.Profile) && NativeBrowser(a.Profile)))
        {
            var pac = await EdgeStatusAsync(ct);
            ApplyEdge(CombineBrowserPaths(pac.Snapshot(), records, status, Applications.Where(a => BrowserCatalog.IsEdge(a.Profile)).Select(a => a.Profile.Id).ToHashSet(StringComparer.Ordinal)));
            ApplyEdgePolicyState(pac);
        }
    }
}
