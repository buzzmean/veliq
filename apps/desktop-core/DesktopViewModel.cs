using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json;
namespace Neexitlag.Desktop;
public abstract class Observable : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    protected void Changed([CallerMemberName] string? property = null) => PropertyChanged?.Invoke(this, new(property));
    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? property = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;
        field = value;
        Changed(property);
        return true;
    }
}
public sealed record Choice(string Value, string Label);
public sealed record RouteRow(string Id, string Name, string Status, string Rtt, string Jitter, string Loss, string Score, string Role, QualityMetrics? Quality = null)
{
    public string Burst => Quality is null ? Text.Get("NoData") : Quality.MaxLossBurst.ToString(Text.Russian);
    public string Stability => Quality is null ? Text.Get("NoData") : Text.Percent(Quality.Stability);
    public string SampleCount => Quality is null ? Text.Get("NoData") : Quality.SampleCount.ToString(Text.Russian);
    public string Median => Quality?.PercentilesAvailable == true ? Text.Milliseconds(Quality.MedianRtt / 1e6) : Text.Get("NoData");
    public string P95 => Quality?.PercentilesAvailable == true ? Text.Milliseconds(Quality.P95Rtt / 1e6) : Text.Get("NoData");
}
public sealed record DiagnosticRow(string Name, string Status, string Detail);
public sealed record MeasurementRow(string Time, string Route, string Rtt, string Jitter, string Loss);
public sealed partial class ApplicationRow : Observable
{
    public Profile Profile { get; private set; } = new(); public string Name => Profile.Name; public string Path => executablePath; public string Mode => Text.Mode(Profile.Mode);
    string processStatus = Text.Get("NoData"), route = Text.Get("NoData"), executablePath = Text.Get("NoData"); public string ProcessStatus => processStatus; public string Route => route;
    public string UserStatus {get;private set;}=Text.Get("NoData");
    public string LocalDetails {get;private set;}=Text.Get("NoData");
 public string Udp { get; private set; } = Text.Get("NoData");
 public string Tcp { get; private set; } = Text.Get("NoData");
 public string Ipv4 { get; private set; } = Text.Get("NoData");
 public string Ipv6 { get; private set; } = Text.Get("IPv6Unsupported");
 public void Update(Profile profile, ProcessIdentity[]? processes, CaptureEvidence? capture)
    {
        var previous = DisplayValues();
        Profile = profile;
        var matched = processes?.Where(p => profile.Executables.Any(exe => Matches(exe, p.Path))).ToArray();
        executablePath = string.Join(", ", profile.Executables.Select(exe => exe.Contains('\\') || exe.Contains('/') ? exe : matched?.FirstOrDefault(p => Matches(exe, p.Path))?.Path ?? $"{exe} ({Text.Get("NoData")})"));
        processStatus = matched is null ? Text.Get("NoData") : Text.Get(matched.Length > 0 ? "Active" : "NotRunning");
        bool Attributed(CaptureFlow f) => f.ProcessGroup==profile.Id && f.IdentityCurrent || profile.Executables.Any(exe=>Matches(exe,f.Exe)) && (matched?.Any(p=>p.PID==f.Pid&&p.CreationTime==f.CreationTime)==true || processes is null&&f.IdentityCurrent);
        bool FreshFlow(CaptureFlow f) => f.Active || (f.LastSeen<=DateTimeOffset.UtcNow.AddSeconds(1)&&DateTimeOffset.UtcNow-f.LastSeen<TimeSpan.FromSeconds(30));
        var active=capture?.Flows.Where(f=>Attributed(f)&&FreshFlow(f)).ToArray();
        string Summary(Func<CaptureFlow,bool> predicate){var values=active?.Where(predicate).Select(f=>f.SelectedRoute=="BLOCK_UNSUPPORTED_IPV6"?Text.Get("IPv6Blocked"):f.SelectedRoute is "DIRECT" or "DIRECT_PLUS"?Text.Route(f.SelectedRoute):f.SelectedRoute=="RELAY"?Text.Route(f.RelayId):Text.Get("NoData")).Distinct().ToArray();return values is {Length:>0}?string.Join(", ",values):Text.Get("NoData");}
        route=Summary(_=>true);
        var livePaths=active?.Where(f=>f.ProcessGroup==profile.Id&&f.IdentityCurrent&&profile.Executables.Any(exe=>string.Equals(exe.Replace('\\','/').Split('/').Last(),f.Exe.Replace('\\','/').Split('/').Last(),StringComparison.OrdinalIgnoreCase))).Select(f=>f.Exe).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if(livePaths is {Length:>0})executablePath=string.Join(", ",livePaths);
        bool relay=active?.Any(f=>f.SelectedRoute=="RELAY"&&f.Counters.RelayedBytes>0)==true;
        bool direct=active?.Any(f=>f.SelectedRoute=="DIRECT"&&f.Counters.DirectPackets>0&&(f.Policy?.Fallback!="FLOW_RELAY_FALLBACK"||f.UdpHealth?.State=="DIRECT_CONFIRMED"))==true;
        UserStatus=active is null||active.Length==0?Text.Get("NoData"):active.Any(f=>f.SelectedRoute.StartsWith("BLOCK",StringComparison.Ordinal)||f.RelayRequiredBlocked)?Text.Get("ProtectedFlowBlocked"):relay&&direct?Text.Get("HybridRoute"):relay?Text.Get("ProtectedRoute"):active.Any(f=>f.Counters.DirectPlusPackets>0)?Text.Get("AppliedDirectOptimization"):direct?Text.Get("DirectConnection"):Text.Get("AutoChecking");
        if(capture?.Truncated==true)UserStatus=Text.Get("PartialRouteEvidence")+" "+UserStatus;
        if(active?.Length>0)processStatus=Text.Get("Active");
        LocalDetails=active is null?Text.Get("NoData"):string.Join("; ",active.Select(f=>$"{f.Protocol} · {f.Source} → {f.Destination} · upstream={f.UpstreamSource} · flow={f.FlowId} · {f.ProcessGroup} · {f.Exe} · PID={f.Pid}/{f.CreationTime} · {f.Policy?.Action} · {f.Policy?.Reason} · {f.Policy?.Source} · {f.FallbackReason} · {f.NetworkFingerprint} · blocked={f.RelayRequiredBlocked} · captured={f.Counters.CapturedPackets}/{f.Counters.CapturedBytes} · direct={f.Counters.DirectPackets}/{f.Counters.DirectBytes} · replies={f.Counters.DirectReplyPackets} · udp-health={f.UdpHealth?.State}/{f.UdpHealth?.Reason} · probation={f.UdpHealth?.ProbationReplies}/{f.UdpHealth?.ProbationReplyBytes}/{f.UdpHealth?.ProbationDurationMs}ms · cadence={f.UdpHealth?.ReplyBins}/{f.UdpHealth?.OutboundBins} · degraded={f.UdpHealth?.DegradedDurationMs}ms · direct+={f.Counters.DirectPlusBytes} · {f.Strategy}: {f.Domain} {f.Destination} {Text.Route(f.SelectedRoute=="RELAY"?f.RelayId:f.SelectedRoute)} · {f.Preset} {f.Chain} · {(f.FakeTtl>0?$"TTL={f.FakeTtl}":"")} · {Text.Get("LocalModified")}: {f.Counters.DirectPlusPackets} · {Text.Get("RelayTraffic")}: {Text.Bytes(f.Counters.RelayedBytes)} · QUIC→TCP={f.Counters.QuicFallbackPackets}").Distinct());
        Udp=Summary(f=>f.Protocol=="udp");Tcp=Summary(f=>f.Protocol=="tcp");Ipv4=Summary(f=>f.IpVersion=="IPv4");
        Ipv6=active?.Any(f=>f.IpVersion=="IPv6")==true?Summary(f=>f.IpVersion=="IPv6"):Text.Get("IPv6Unsupported");
        NotifyDisplayChanges(previous);
    }
    public static bool Matches(string executable, string path)
    {
        var e = executable.Replace('\\', '/');
        var p = path.Replace('\\', '/');
        return string.Equals(e, p.Contains('/') && !e.Contains('/') ? p[(p.LastIndexOf('/') + 1)..] : p, StringComparison.OrdinalIgnoreCase);
    }
}
public sealed partial class DesktopViewModel : Observable
{
    readonly IServiceClient client; readonly SemaphoreSlim gate = new(1, 1); public Snapshot? Snapshot
    {
        get => snapshot; private set { snapshot = value; HealthChanged(); }
    }
    Snapshot? snapshot;
    bool available, busy; string connection = Text.Get("Connecting"), error = "", notice = "";
    public bool Available
    {
        get => available; private set
        {
            if (Set(ref available, value))
            { Changed(nameof(CanControl)); HealthChanged(); }
        }
    }
    public bool Busy
    {
        get => busy; private set
        {
            if (Set(ref busy, value))
            { Changed(nameof(CanControl)); NotifyBusyHome(); }
        }
    }
    public bool CanControl => Available && !Busy;
    public string Connection
    {
        get => connection; private set => Set(ref connection, value);
    }
    public string Error
    {
        get => error; private set => Set(ref error, value);
    }
    public void SetNotice(string value) => Notice=value;
    public string Notice
    {
        get => notice; private set => Set(ref notice, value);
    }
    public ObservableCollection<ApplicationRow> Applications { get; } = []; public ObservableCollection<RouteRow> Routes { get; } = []; public ObservableCollection<Choice> Relays { get; } = [];
    public ObservableCollection<DiagnosticRow> Diagnostics { get; } = []; public ObservableCollection<MeasurementRow> Measurements { get; } = []; public ObservableCollection<string> Changes { get; } = [];
    public ObservableCollection<Choice> ProfileFallbacks {get;}=[new("",Text.Get("InheritFallback")),new("FAIL_OPEN_DIRECT",Text.Get("DirectConnection")),new("RELAY_REQUIRED",Text.Get("RequiredRelayFallback")),new("BLOCK",Text.Get("Block"))];
    public ObservableCollection<Choice> Modes { get; } = [new("AUTO", Text.Mode("AUTO")), new("DIRECT", Text.Mode("DIRECT")), new("DIRECT_PLUS",Text.Mode("DIRECT_PLUS")), new("MANUAL", Text.Mode("MANUAL"))];
    public bool Optimizing => Available && Snapshot?.Optimizing == true; public string OptimizeLabel => Text.Get(Optimizing ? "DisableOptimization" : "EnableOptimization");
    public string OptimizationStatus => !Available ? Text.Get("NoData") : !Optimizing ? Text.Get("OptimizationOff")
        : Snapshot?.HotAttach?.State switch {
            "HOT_ATTACH_RECONNECTING" or "HOT_ATTACH_PREPARING" => Text.Get("HotAttachReconnecting"),
            "HOT_ATTACH_INCOMPLETE" => Text.Get("HotAttachIncomplete"),
            _ => Connection == Text.Get("Connected") ? Text.Get("OptimizationOn") : Connection
        };
    public string Primary => Available ? Text.Route(Snapshot?.Primary) : Text.Get("NoData");
    public string ActiveApps => !Available ? Text.Get("NoData") : Snapshot?.ActiveApps.Length > 0 ? string.Join(", ", Snapshot.ActiveApps.Select(id => Snapshot.Profiles.FirstOrDefault(p => p.Id == id)?.Name ?? id)) : Text.Get("NoActiveApps");
    public string Rx => Available && Snapshot is { } s ? Text.Bytes(s.RxBytes) : Text.Get("NoData"); public string Tx => Available && Snapshot is { } s ? Text.Bytes(s.TxBytes) : Text.Get("NoData");
    Route? Current => Snapshot?.Routes.FirstOrDefault(r => r.Id == Snapshot.Primary); public string CurrentLatency => Metric(Current, r => Text.Milliseconds(r.RttMs));
    public string DirectLatency => Metric(Snapshot?.Routes.FirstOrDefault(r => r.Id == "DIRECT"), r => Text.Milliseconds(r.RttMs));
    public string RelayLatency => Metric(Snapshot?.Routes.Where(r => r.Id != "DIRECT" && Fresh(r)).OrderBy(r => r.Id == Snapshot.Primary ? 0 : 1).ThenBy(r => r.Score ?? double.MaxValue).FirstOrDefault(), r => Text.Milliseconds(r.RttMs)); public string Jitter => Metric(Current, r => Text.Milliseconds(r.JitterMs)); public string Loss => Available && Current?.Quality?.NetworkSampleCount > 0 ? Text.Percent(Current.Quality.ProbeLoss) : Metric(Current, r => Text.Percent(r.Loss));
    public string CurrentBurst => Available && Current?.Quality is { } q ? q.MaxLossBurst.ToString(Text.Russian) : Text.Get("NoData");
    public string CurrentStability => Available && Current?.Quality is { } q ? Text.Percent(q.Stability) : Text.Get("NoData");
    public string CurrentSamples => Available && Current?.Quality is { } q ? q.SampleCount.ToString(Text.Russian) : Text.Get("NoData");
    public DesktopViewModel(IServiceClient client)
    {
        this.client = client;
    }
    public static bool Fresh(Route route) => route.Status == "healthy" && route.ObservedAt != default && DateTimeOffset.UtcNow - route.ObservedAt < TimeSpan.FromSeconds(90) && route.ObservedAt <= DateTimeOffset.UtcNow.AddSeconds(5);
    string Metric(Route? route, Func<Route, string> format) => Available && route is not null && Fresh(route) ? format(route) : Text.Get("NoData");
    static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> source)
    {
        var next = source.ToArray();
        if (target.SequenceEqual(next) || JsonSerializer.Serialize(target) == JsonSerializer.Serialize(next))
            return;
        target.Clear();
        foreach (var item in next)
            target.Add(item);
    }
    public async Task RefreshAsync(CancellationToken ct = default)
    {
        if (!await gate.WaitAsync(0, ct))
            return;
        var phase="ipc.status";
        try
        {
            var status = await client.Call<Snapshot>("status", cancellationToken: ct);
            if (status.Demo)
                throw new ServiceException(ServiceFailure.Incompatible);
            ProcessIdentity[]? processes = null;
            CaptureEvidence? capture = null;
            // Auxiliary diagnostics must not prevent a valid service connection.
            try
            {
                processes = await client.Call<ProcessIdentity[]>("processes", new
                {
                    executables = status.Profiles.SelectMany(p => p.Executables).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
                }, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { ReportAuxiliaryFailure(error,"ipc.processes"); }
            try
            {
                capture = await client.Call<CaptureEvidence>("capture.diagnostics", cancellationToken: ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { ReportAuxiliaryFailure(error,"ipc.capture"); }
            phase="status.apply";
            try { Apply(status, processes, capture); }
            catch (Exception error) when (processes is not null || capture is not null) {
                Apply(status); // Validate/display core status independently of malformed auxiliary data.
                ReportAuxiliaryFailure(error,"diagnostics.apply");
            }
            try { ApplyBrowser(await client.Call<BrowserTransportSnapshot>("browser.status", cancellationToken: ct)); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { ApplyBrowser(new()); ReportAuxiliaryFailure(error,"ipc.browser"); }
            try { await RefreshGamesAsync(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception error) { ReportAuxiliaryFailure(error,"ipc.gameudp"); }
            Error = "";
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception e) { RecordGuiFailure(e,phase); SetUnavailable(e); }
        finally { gate.Release(); }
    }
    public void Apply(Snapshot status, ProcessIdentity[]? processes = null, CaptureEvidence? capture = null)
    {
        var previous = HomeValues();
        ObserveBrowserControlState(status);
        Snapshot = status;
        Available = true;
        Connection = ServiceConnectionText.Describe(status);
        if (status.Backend.Capabilities.Tcp && !Modes.Any(m => m.Value == "BLOCK"))
            Modes.Add(new("BLOCK", Text.Mode("BLOCK")));
        if (!status.Backend.Capabilities.Tcp)
        {
            var block = Modes.FirstOrDefault(m => m.Value == "BLOCK");
            if (block is not null)
                Modes.Remove(block);
        }
        // Truncation prevents proving ABSENCE, not displaying positive evidence
        // that the authenticated backend actually supplied for a live identity.
        foreach (var old in Applications.Where(a => !status.Profiles.Any(p => p.Id == a.Profile.Id)).ToArray())
            Applications.Remove(old);
        foreach (var profile in status.Profiles)
        {
            var row = Applications.FirstOrDefault(a => a.Profile.Id == profile.Id);
            if (row is null)
            {
                row = new();
                Applications.Add(row);
            }
            row.Update(profile, processes, capture);
        }
        Replace(Routes, status.Routes.Select(r => new RouteRow(r.Id, Text.Route(r.Id), Text.Get(Fresh(r) ? "Available" : "Unavailable"), Metric(r, x => Text.Milliseconds(x.RttMs)), Metric(r, x => Text.Milliseconds(x.JitterMs)), r.Quality?.NetworkSampleCount > 0 ? Text.Percent(r.Quality.ProbeLoss) : Metric(r, x => Text.Percent(x.Loss)), Fresh(r) && r.Score.HasValue ? r.Score.Value.ToString("F1", Text.Russian) : Text.Get("NoData"), r.Id == status.Primary ? Text.Get("Primary") : r.Id == status.Secondary || r.Id == status.Tertiary ? Text.Get("Backup") : "", r.Quality)));
        var availableRelays = status.Routes.Where(r => r.Id != "DIRECT" && Fresh(r)).Select(r => new Choice(r.Id, Text.Route(r.Id))).ToArray();
        if (!Relays.SequenceEqual(availableRelays))
            Replace(Relays, availableRelays);
        RenderHistory(status.History);
        ClearBrowserPreparationIssue();
        ApplyDisabledBrowserDisplay();
        NotifyHomeChanges(previous);
    }
    void RenderHistory(JsonElement history)
    {
        var rows = new List<MeasurementRow>();
        var events = new List<string>();
        if (history.ValueKind != JsonValueKind.Object)
        {
            Replace(Measurements, rows);
            Replace(Changes, events);
            return;
        }
        if (history.TryGetProperty("measurements", out var list) && list.ValueKind == JsonValueKind.Array)
            foreach (var m in list.EnumerateArray().TakeLast(80).Reverse())
            {
                bool measured = m.GetProperty("available").GetBoolean();
                rows.Add(new(m.GetProperty("observed_at").GetDateTimeOffset().ToLocalTime().ToString("HH:mm:ss"), Text.Route(m.GetProperty("route_id").GetString()), measured ? Text.Milliseconds(m.GetProperty("rtt").GetDouble() / 1e6) : Text.Get("NoData"), measured ? Text.Milliseconds(m.GetProperty("jitter").GetDouble() / 1e6) : Text.Get("NoData"), measured ? Text.Percent(m.GetProperty("loss").GetDouble()) : Text.Get("NoData")));
            }
        if (history.TryGetProperty("changes", out var changes) && changes.ValueKind == JsonValueKind.Array)
            foreach (var c in changes.EnumerateArray().TakeLast(80).Reverse())
                events.Add($"{c.GetProperty("At").GetDateTimeOffset().ToLocalTime():HH:mm:ss}  {Text.Route(c.GetProperty("From").GetString())} → {Text.Route(c.GetProperty("To").GetString())}");
        Replace(Measurements, rows);
        Replace(Changes, events);
    }
    public void SetUnavailable(Exception e)
    {
        InvalidateBrowserPreparation();
        Notice = "";
        Available = false;
        Snapshot = null;
        Connection = Text.Failure(e);
        Error = Connection;
        Applications.Clear();
        Routes.Clear();
        Relays.Clear();
        Measurements.Clear();
        Changes.Clear();
        Diagnostics.Clear();
        Changed("");
    }
    async Task<bool> Act(Func<Task> action, CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        Busy = true;
        try
        {
            await action();
            Error = "";
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { return false; }
        catch (Exception e)
        {
            if (e is ServiceException failure && failure.Failure != ServiceFailure.Rejected)
                SetUnavailable(e);
            else if(e is EdgeActivationException)ReportActionFailure(e);
            else
                Error = Text.Failure(e);
            return false;
        }
        finally { Busy = false; gate.Release(); }
    }
    public async Task OptimizeAsync(bool enabled, CancellationToken ct = default)
    {
        if(!enabled){SuppressAutomaticBrowserStartup();InvalidateBrowserPreparation();}
        if (await Act(async () => { if(!enabled)InvalidateBrowserPreparation();await client.Call<Snapshot>("optimize", new { enabled }, ct); }, ct))
            await RefreshAsync(ct);
    }
    public RunningApplicationsViewModel CreateApplicationPicker() => new(client);
    public async Task<bool?> AddApplicationFromFileAsync(Func<string?> chooseFile, CancellationToken ct = default)
    {
        string? path = chooseFile();
        return path is null ? null : await AddApplicationAsync(path, ct);
    }
    public async Task<bool> AddApplicationAsync(string path, CancellationToken ct = default)
    {
        if (!System.IO.Path.IsPathFullyQualified(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
        {
            Error = Text.Get("InvalidExecutable");
            return false;
        }
        path = System.IO.Path.GetFullPath(path);
        var profile = new Profile { Id = "custom-" + Guid.NewGuid().ToString("N"), Name = System.IO.Path.GetFileNameWithoutExtension(path), Executables = [path], Mode = "DIRECT", Custom = true };
        if(BrowserCatalog.IsEdge(profile))profile.PolicyData=new(){["app_preset"]=System.Text.Json.JsonSerializer.SerializeToElement("edge-sites-pending")};
        bool duplicate = false;
        bool ok = await Act(async () =>
        {
            // Recheck current service state inside the mutation gate. An old GUI
            // snapshot or two rapid clicks must not create duplicate profiles.
            var existing = await client.Call<Profile[]>("profiles", cancellationToken: ct);
            duplicate = existing.Any(p => p.Executables.Any(e => SameExecutable(e, path)));
            if (duplicate) return;
            if(BrowserCatalog.IsEdge(profile))await RequireEdgeServiceAsync(ct);
            var saved = await client.Call<Profile[]>("profile.set", profile, ct);
            if (Snapshot is { } snapshot) snapshot.Profiles = saved;
            foreach (var p in saved)
            {
                var row = Applications.FirstOrDefault(a => a.Profile.Id == p.Id);
                if (row is null)
                {
                    row = new(); row.Update(p, null, null); Applications.Add(row);
                }
            }
        }, ct);
        if (duplicate) { Error = Text.Get("AlreadyAdded"); return false; }
        // Profile mutation already returned the authoritative list. Close the
        // picker immediately; ordinary polling will fill live process evidence.
        return ok;
    }
    // Clean install: make sure Chrome has a profile without any manual step. A profile the
    // user (or an earlier run) already created for chrome.exe, at any path and in any mode,
    // is left exactly as it is. Returns the profile that was just created (DIRECT, the same
    // safe shape as adding Chrome by hand) so the caller can run the normal activation, or
    // null when nothing was created.
    public async Task<Profile?> EnsureChromeProfileAsync(IReadOnlyList<InstalledBrowser> installed, CancellationToken ct = default)
    {
        var chrome = installed.FirstOrDefault(b => b.Id == "chrome" && b.AutoSupported);
        if (chrome is null) return null;
        // Authoritative list from the service, not the GUI snapshot (two rapid clicks, stale poll).
        var existing = await client.Call<Profile[]>("profiles", cancellationToken: ct);
        if (existing.Any(BrowserCatalog.IsChrome)) return null;
        if (!await AddApplicationAsync(chrome.ExePath, ct)) return null;
        return Applications.Select(a => a.Profile).FirstOrDefault(BrowserCatalog.IsChrome);
    }
    static bool SameExecutable(string a, string b)
    {
        try { return System.IO.Path.IsPathFullyQualified(a) && string.Equals(System.IO.Path.GetFullPath(a), b, StringComparison.OrdinalIgnoreCase); }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or System.IO.PathTooLongException) { return false; }
    }
    public async Task<bool> SetProfileAsync(Profile original, string mode, string? relay, CancellationToken ct = default)
    {
        if (mode == "BLOCK" && Snapshot?.Backend.Capabilities.Tcp != true)
        {
            Error = Text.Get("BlockUnsupported");
            return false;
        }
        if (!new[] { "AUTO", "DIRECT", "DIRECT_PLUS", "MANUAL", "BLOCK" }.Contains(mode))
        {
            Error = Text.Get("CommandRejected");
            return false;
        }
        if (mode == "MANUAL" && !(Snapshot?.Routes.Any(r => r.Id == relay && r.Id != "DIRECT" && Fresh(r)) == true))
        {
            Error = Text.Get("NoRelay");
            return false;
        }
        var copy = original.Copy();
        copy.Mode = mode;
        if(BrowserCatalog.IsChrome(copy)||BrowserCatalog.IsEdge(copy)){
            copy.PolicyData??=new();copy.PolicyData["browser_auto_disabled"]=System.Text.Json.JsonSerializer.SerializeToElement(mode!="AUTO");
            if(mode=="AUTO")copy=NativeAutoProfile(copy);
        }
        if(mode!="AUTO" && (BrowserCatalog.IsChrome(copy)||BrowserCatalog.IsEdge(copy))){
            copy.PolicyData??=new();copy.PolicyData["browser_transport"]=System.Text.Json.JsonSerializer.SerializeToElement("");
            if(BrowserCatalog.IsEdge(copy))copy.PolicyData["app_preset"]=System.Text.Json.JsonSerializer.SerializeToElement("edge-sites");
            startupChromeProfiles.Remove(copy.Id);
        }
        copy.RelayId = mode == "MANUAL" ? relay : null;
        bool ok = await Act(async () => { await client.Call<Profile[]>("profile.set", copy, ct); }, ct);
        if (ok)
        {
            Notice = Text.Get("ProfileSaved");
            await RefreshAsync(ct);
        }
        return ok;
    }
    public async Task DeleteApplicationAsync(Profile profile, CancellationToken ct = default)
    {
        if (!profile.Custom)
        {
            Error = Text.Get("DefaultProfile");
            return;
        }
        if (await Act(async () => { await client.Call<Profile[]>("profile.delete", new { id = profile.Id }, ct); }, ct))
            await RefreshAsync(ct);
    }
    public Task<LocalStrategyPreset[]> GetPresetsAsync(CancellationToken ct=default)=>client.Call<LocalStrategyPreset[]>("local.presets",cancellationToken:ct);
    public async Task<bool> ApplyPresetAsync(Profile original,string preset,bool quic,CancellationToken ct=default)
    {
        string path=original.Executables.FirstOrDefault()??"";
        if(!System.IO.Path.IsPathFullyQualified(path)){Error=Text.Get("PresetNeedsPath");return false;}
        bool ok=await Act(async()=>{
            var install=await client.Call<PresetInstall>("local.preset.apply",new{application=path,preset,quic_fallback=quic},ct);
            var copy=original.Copy();copy.Mode="DIRECT_PLUS";copy.LocalStrategyId=install.StrategyId;copy.RelayId=null;
            await client.Call<Profile[]>("profile.set",copy,ct);
        },ct);
        if(ok)await RefreshAsync(ct);return ok;
    }
    public Task<LocalStrategyConfig> GetLocalStrategiesAsync(CancellationToken ct=default)=>client.Call<LocalStrategyConfig>("local.get",cancellationToken:ct);
 public Task<LocalStrategyConfig> SaveLocalStrategiesAsync(LocalStrategyConfig config,CancellationToken ct=default)=>client.Call<LocalStrategyConfig>("local.set",config,ct);
 public Task<LocalStrategyMetrics> GetLocalMetricsAsync(CancellationToken ct=default)=>client.Call<LocalStrategyMetrics>("local.metrics",cancellationToken:ct);
 public async Task<bool> SaveServiceSettingsAsync(ServiceSettings settings, CancellationToken ct = default)
    {
        if (settings.Failover == "BLOCK" && Snapshot?.Backend.Capabilities.Tcp != true)
        {
            Error = Text.Get("BlockUnsupported");
            return false;
        }
        if(!settings.Automatic)InvalidateBrowserPreparation();
        return await Act(async () => { await client.Call<ServiceSettings>("settings.set", settings, ct); }, ct);
    }
    public async Task DiagnoseAsync(CancellationToken ct = default)
    {
        await Act(async () =>
        {
            var checks = await client.Call<Check[]>("diagnostics", cancellationToken: ct);
            var s = await client.Call<Snapshot>("status", cancellationToken: ct);
            var rows = new List<DiagnosticRow> { new(Text.Get("ServiceName"), Text.Get("Working"), Text.Get("ServiceWorking")), new(Text.Get("DriverName"), Text.Get(s.Backend.Ready ? "Working" : string.IsNullOrEmpty(s.Backend.Error) ? "NotAvailable" : "Error"), Text.Get(s.Backend.Ready ? "DriverReady" : string.IsNullOrEmpty(s.Backend.Error) ? "DriverIdle" : "DriverFailure")) };
            if(s.HotAttach is { } hot) rows.Add(new("HOT ATTACH",Text.Get(hot.State=="HOT_ATTACH_INCOMPLETE"?"Error":hot.State is "HOT_ATTACH_RECONNECTING" or "HOT_ATTACH_PREPARING"?"HotAttachReconnecting":"Working"),$"{Text.Get("HotAttachNetworkHint")} {hot.TcpReset}; {hot.Pending}. {hot.Error}"));
            foreach (var c in checks)
            {
                string key = c.Name switch
                {
                    "Control Plane" => "ControlPlane",
                    "Relay" => "RelayCheck",
                    "Latency / Loss" => "LatencyCheck",
                    "TCP interception" => "TcpInterception",
                    "UDP interception" => "UdpInterception",
                    "IPv4" => "IPv4Label",
                    "IPv6" => "IPv6Label",
                    "HTTPS through relay" => "HttpsRelay",
                    "QUIC through relay" => "QuicRelay",
                    "Browser DNS" => "BrowserDns",
                    _ => ""
                };
                var name = key != "" ? Text.Get(key) : new[] { "UDP", "TCP", "MTU", "DNS" }.Contains(c.Name) ? c.Name : Text.Get("Check");
                var detail = c.Status == "not configured" ? Text.Get("DiagnosticUnconfigured") : c.Status is "healthy" or "measured" ? Text.Get(c.Name == "MTU" ? "DiagnosticMtu" : c.Name == "DNS" ? "DiagnosticDns" : "DiagnosticHealthy") : Text.Get("DiagnosticUnavailable");
                if (c.Name is "HTTPS through relay" or "QUIC through relay" or "Browser DNS") detail=Text.Get(c.Name=="Browser DNS" ? "BrowserDnsHint" : "WebNotMeasured");
                if (c.Name=="IPv6") detail=Text.Get("IPv6GuardHint");
                if (c.Name is "TCP interception" or "UDP interception" or "IPv4") detail=Text.Get("InterceptionHint");
                rows.Add(new(name, c.Status=="unsupported" ? Text.Get("IPv6Unsupported") : Text.Status(c.Status), detail));
            }
            try {var n=await client.Call<NetworkObservation>("local.network",cancellationToken:ct);
 rows.Add(new(Text.Get("LocalNetwork"),Text.Get(string.IsNullOrEmpty(n.Error) && DateTimeOffset.UtcNow-n.ObservedAt<TimeSpan.FromSeconds(45)?"Working":"NoData"),string.Join("; ",n.Adapters)));
 rows.Add(new(Text.Get("LocalVPN"),Text.Get(n.Vpn.Length>0?"Active":"NoData"),n.Vpn.Length>0?string.Join(", ",n.Vpn):Text.Get("LocalVPNUnknown")));
 rows.Add(new(Text.Get("LocalConflict"),Text.Get(n.Conflicts.Length>0?"Error":"NoData"),n.Conflicts.Length>0?string.Join(", ",n.Conflicts):Text.Get("LocalConflictUnknown")));
 rows.Add(new(Text.Get("LocalRoutes"),Text.Get("NoData"),string.Join("; ",n.Routes)));
 rows.Add(new(Text.Get("LocalDNS"),Text.Get("NoData"),string.Join("; ",n.Dns)+"; "+Text.Get("LocalDNSUnknown")));
 rows.Add(new(Text.Get("LocalProxy"),Text.Get("NoData"),n.Proxy));
 }catch(ServiceException){rows.Add(new(Text.Get("LocalNetwork"),Text.Get("NoData"),Text.Get("LocalVPNUnknown")));}
 var direct = checks.FirstOrDefault(c => c.Name == "UDP");
            rows.Add(new(Text.Get("DirectCheck"), Text.Status(direct?.Status ?? "not configured"), Text.Get(direct?.Status == "healthy" ? "DiagnosticHealthy" : direct?.Status == "not configured" || direct is null ? "DiagnosticUnconfigured" : "DiagnosticUnavailable")));
            try
            {
                var drops = await client.Call<DropDiagnostics>("quality.diagnostics", cancellationToken: ct);
                foreach (var metric in drops.Capture ?? [])
                {
                    rows.Add(RenderDrop("WinDivert", metric.Key, metric.Value));
                }
                foreach (var route in drops.Transport)
                    foreach (var metric in route.Value)
                    {
                        rows.Add(RenderDrop(route.Key, metric.Key, metric.Value));
                    }
                if (!drops.RemoteRelayAvailable)
                    rows.Add(new(Text.Get("RemoteDrops"), Text.Get("NoData"), Text.Get("RemoteDropsHint")));
            }
            catch (ServiceException) {/* Older IPC v1 service has no optional endpoint. */}
            Replace(Diagnostics, rows);
        }, ct);
    }
    static DiagnosticRow RenderDrop(string scope, string key, DropMetric metric)
    {
        string resource = key switch
        {
            "capture_queue_drops" => "CaptureQueueDrops",
            "worker_saturation_drops" => "WorkerDrops",
            "transport_queue_drops" => "TransportDrops",
            "quic_decode_drops" => "DecodeDrops",
            "unknown_flow_drops" => "UnknownFlowDrops",
            "relay_socket_send_drops" => "SocketDrops",
            "reply_reinjection_failures" => "ReinjectDrops",
            "capture_kernel_queue_drops" => "KernelDrops",
            "capture_receive_errors" => "CaptureErrors",
            "policy_drops" => "PolicyDrops",
            _ => "CaptureDrops"
        };
        string detail = !metric.Available ? Text.Get("NoData") : metric.Count.ToString(Text.Russian) + " " + Text.Get(metric.Unit == "events" ? "Events" : "Packets") + (metric.Fraction.HasValue ? " (" + Text.Percent(metric.Fraction.Value) + ")" : "; " + Text.Get("FractionUnknown"));
        return new(scope + " · " + Text.Get(resource), Text.Get(!metric.Available ? "NotAvailable" : metric.Count > 0 ? "Error" : "Working"), detail);
    }

}
