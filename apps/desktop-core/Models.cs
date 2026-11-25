using System.Text.Json;
using System.Text.Json.Serialization;
namespace Veliq.Desktop;
public static class WireJson
{
    public static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
}
public sealed class Profile
{
 [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)] public string? Fallback {get;set;}
 [JsonExtensionData] public Dictionary<string,JsonElement>? PolicyData {get;set;}
 public string LocalStrategyId {get;set;}="";
    public string Id { get; set; } = ""; public string Name { get; set; } = ""; public string[] Executables { get; set; } = [];
    public string Mode { get; set; } = "DIRECT"; public string? RelayId
    {
        get; set;
    }
    public bool Custom
    {
        get; set;
    }
    public string? Publisher
    {
        get; set;
    }
    public string? SignatureSha256
    {
        get; set;
    }
    public string[]? ProtocolHints
    {
        get; set;
    }
    public ushort[]? PortHints
    {
        get; set;
    }
    public Profile Copy() => new() { Fallback=Fallback, PolicyData=PolicyData is null?null:new(PolicyData), Id = Id, Name = Name, Executables = [.. Executables], Mode = Mode, RelayId = RelayId, Custom = Custom, LocalStrategyId = LocalStrategyId, Publisher = Publisher, SignatureSha256 = SignatureSha256, ProtocolHints = ProtocolHints, PortHints = PortHints };
}
public sealed class Route
{
    public QualityMetrics? Quality
    {
        get; set;
    }
    public string Id { get; set; } = ""; public double RttMs
    {
        get; set;
    }
    public double JitterMs
    {
        get; set;
    }
    public double Loss
    {
        get; set;
    }
    public double? Score
    {
        get; set;
    }
    public string Status { get; set; } = "unavailable"; public DateTimeOffset ObservedAt
    {
        get; set;
    }
}
public sealed class Capabilities
{
    public bool Udp
    {
        get; set;
    }
    public bool Tcp
    {
        get; set;
    }
    public bool Ipv4
    {
        get; set;
    }
    public bool Ipv6
    {
        get; set;
    }
}
public sealed class BackendStatus
{
    public string Backend { get; set; } = "none"; public bool Ready
    {
        get; set;
    }
    public string? Error
    {
        get; set;
    }
    public Capabilities Capabilities { get; set; } = new();
}
public sealed class ServiceSettings
{
    public bool Automatic
    {
        get; set;
    }
    public string Failover { get; set; } = "DIRECT"; public string UpdateChannel { get; set; } = "stable";
    [System.Text.Json.Serialization.JsonPropertyName("youtube_via_relay")]
    public bool YouTubeViaRelay { get; set; }
}
public sealed class HotAttachStatus
{
 public ulong Epoch {get;set;}
 public string State {get;set;}="";
 public string? Error {get;set;}
 public int Pending {get;set;}
 public int TcpReset {get;set;}
}
public sealed class Snapshot
{
 public BrowserPolicyView BrowserPolicy {get;set;}=new();
 public uint ServicePid {get;set;}
 public string ConnectionReason {get;set;}=""; public bool RelayConnected {get;set;}
 public HotAttachStatus? HotAttach {get;set;}
    public string Version { get; set; } = ""; public bool Connected
    {
        get; set;
    }
    public bool Optimizing
    {
        get; set;
    }
    public bool Demo
    {
        get; set;
    }
    public string Primary { get; set; } = ""; public string Secondary { get; set; } = ""; public string Tertiary { get; set; } = "";
    public Route[] Routes { get; set; } = []; public Profile[] Profiles { get; set; } = []; public ulong RxBytes
    {
        get; set;
    }
    public ulong TxBytes
    {
        get; set;
    }
    public string[] ActiveApps { get; set; } = [];
    public Dictionary<string, string> ActiveAppExecutables { get; set; } = new(StringComparer.Ordinal);
    public BackendStatus Backend { get; set; } = new(); public JsonElement History
    {
        get; set;
    }
    public ServiceSettings Settings { get; set; } = new(); public string ControlPlane { get; set; } = "";
}
// Existing processes IPC serializes Go Identity fields using their original names.
public sealed class ProcessIdentity
{
    public uint PID
    {
        get; set;
    }
    public string Path { get; set; } = ""; public string Name { get; set; } = ""; [JsonPropertyName("CreationTime")]
    public ulong CreationTime
    {
        get; set;
    }
}
public sealed class Check
{
    public string Name { get; set; } = ""; public string Status { get; set; } = ""; public string Detail { get; set; } = "";
}
public sealed class CaptureEvidence
{
    public bool Truncated
    {
        get; set;
    }
    public CaptureFlow[] Flows { get; set; } = [];
}
public sealed class FlowPolicyEvidence {public string RelayId {get;set;}="";public string Action {get;set;}="";public string Reason {get;set;}="";public string Source {get;set;}="";public string Fallback {get;set;}="";}
public sealed class UdpHealthEvidence
{
 public string State {get;set;}=""; public string Reason {get;set;}="";
 public ulong ProbationReplies {get;set;} public ulong ProbationReplyBytes {get;set;}
 public long ProbationDurationMs {get;set;} public int OutboundBins {get;set;} public int ReplyBins {get;set;}
 public long DegradedDurationMs {get;set;}
}
public sealed class CaptureFlow
{
 public UdpHealthEvidence? UdpHealth {get;set;}
 public ulong FlowId {get;set;} public string Source {get;set;}="";public string UpstreamSource {get;set;}="";public DateTimeOffset StartedAt {get;set;}
 public FlowPolicyEvidence Policy {get;set;}=new();public string ProcessGroup {get;set;}="";public string NetworkFingerprint {get;set;}="";public string FallbackReason {get;set;}="";public bool RelayRequiredBlocked {get;set;}
 public string Preset {get;set;}=""; public string Chain {get;set;}=""; public byte FakeTtl {get;set;}
 public bool Active {get;set;} public bool IdentityCurrent {get;set;}
 public string Strategy {get;set;}=""; public string Domain {get;set;}=""; public string Destination {get;set;}="";
 public LocalCaptureCounters Counters {get;set;}=new();
 public string Protocol { get; set; } = "";
 public string IpVersion { get; set; } = "";
    public uint Pid
    {
        get; set;
    }
    public string Exe { get; set; } = ""; public ulong CreationTime
    {
        get; set;
    }
    public string SelectedRoute { get; set; } = ""; public string? RelayId
    {
        get; set;
    }
    public DateTimeOffset LastSeen
    {
        get; set;
    }
}

public sealed class QualityMetrics
{
    public long LatestRtt
    {
        get; set;
    }
    public long MedianRtt
    {
        get; set;
    }
    public long P95Rtt
    {
        get; set;
    }
    public long Jitter
    {
        get; set;
    }
    public long EwmaRtt
    {
        get; set;
    }
    public long EwmaJitter
    {
        get; set;
    }
    public double ProbeLoss
    {
        get; set;
    }
    public double EwmaLoss
    {
        get; set;
    }
    public double Stability
    {
        get; set;
    }
    public int ConsecutiveLoss
    {
        get; set;
    }
    public int MaxLossBurst
    {
        get; set;
    }
    public int SampleCount
    {
        get; set;
    }
    public int NetworkSampleCount
    {
        get; set;
    }
    public bool PercentilesAvailable
    {
        get; set;
    }
    public string Health { get; set; } = "";
}
public sealed class DropMetric
{
    public ulong Count
    {
        get; set;
    }
    public ulong Attempts
    {
        get; set;
    }
    public double? Fraction
    {
        get; set;
    }
    public bool Available
    {
        get; set;
    }
    public string Unit { get; set; } = "";
}
public sealed class DropDiagnostics
{
    public Dictionary<string, DropMetric>? Capture
    {
        get; set;
    }
    public Dictionary<string, Dictionary<string, DropMetric>> Transport { get; set; } = [];
    public bool RemoteRelayAvailable
    {
        get; set;
    }
}

public sealed class LocalCaptureCounters {
 public ulong CapturedPackets {get;set;}public ulong CapturedBytes {get;set;}public ulong DirectPackets {get;set;}public ulong DirectBytes {get;set;}public ulong DirectReplyPackets {get;set;}public ulong DirectReplyBytes {get;set;}
 public ulong DirectPlusBytes {get;set;} public ulong DirectPlusPackets {get;set;} public ulong RelayedBytes {get;set;} public ulong RelayedPackets {get;set;} public ulong FakeTlsPackets {get;set;} public ulong QuicFallbackPackets {get;set;}
}
public sealed class LocalStrategyAction {public string Kind {get;set;}="";private ushort[] _Positions=[]; public ushort[] Positions {get=>_Positions;set=>_Positions=value??[];}public string Anchor {get;set;}="";public byte Ttl {get;set;} }
public sealed class LocalStrategyPreset {public string Id {get;set;}="";public string Name {get;set;}="";public int Version {get;set;} private string[] _Domains=[]; public string[] Domains {get=>_Domains;set=>_Domains=value??[];}[JsonIgnore] public string Label=>$"{Name} v{Version}";}
public sealed class PresetInstall {public LocalStrategyConfig Config {get;set;}=new();public string StrategyId {get;set;}="";}
public sealed class LocalStrategyProfile {
 private LocalStrategyAction[] _Actions=[]; public LocalStrategyAction[] Actions {get=>_Actions;set=>_Actions=value??[];} public string Preset {get;set;}="";public int PresetVersion {get;set;}public bool QuicFallback {get;set;}
 [JsonIgnore] public string Advanced => Actions.Length==0?Strategy:string.Join(" + ",Actions.Select(a=>a.Kind+(a.Ttl>0?$" (TTL={a.Ttl})":"")+(a.Positions.Length>0?$" ({a.Anchor}: {string.Join(',',a.Positions)})":"")));
 public ushort SplitPosition {get;set;}
 public string Id {get;set;}=""; public string Name {get;set;}=""; public int Version {get;set;}=1;
 public string Protocol {get;set;}="tcp"; private ushort[] _Ports=[443]; public ushort[] Ports {get=>_Ports;set=>_Ports=value??[];} public string Application {get;set;}="";
 private string[] _Domains=[]; public string[] Domains {get=>_Domains;set=>_Domains=value??[];} private string[] _Ips=[]; public string[] Ips {get=>_Ips;set=>_Ips=value??[];} private string[] _ExcludeDomains=[]; public string[] ExcludeDomains {get=>_ExcludeDomains;set=>_ExcludeDomains=value??[];} private string[] _ExcludeIps=[]; public string[] ExcludeIps {get=>_ExcludeIps;set=>_ExcludeIps=value??[];}
 public string Strategy {get;set;}="tcp-split-1"; public uint Cutoff {get;set;}=2; public int Priority {get;set;} public bool Enabled {get;set;}=true;
}
public sealed class LocalStrategyConfig { public int Version {get;set;}=1; public bool Enabled {get;set;} private LocalStrategyProfile[] _Builtin=[]; public LocalStrategyProfile[] Builtin {get=>_Builtin;set=>_Builtin=value??[];} private LocalStrategyProfile[] _User=[]; public LocalStrategyProfile[] User {get=>_User;set=>_User=value??[];} }
public sealed class LocalStrategyMetrics { public ulong PacketsInspected {get;set;} public ulong PacketsModified {get;set;} public ulong ExtraPacketsGenerated {get;set;} public ulong FlowsDirectPlus {get;set;} public ulong BytesDirectPlus {get;set;} public ulong BytesRelayAvoided {get;set;} }

public sealed class NetworkObservation { public DateTimeOffset ObservedAt {get;set;} public string Fingerprint {get;set;}=""; private string[] _Adapters=[]; public string[] Adapters {get=>_Adapters;set=>_Adapters=value??[];} private string[] _Routes=[]; public string[] Routes {get=>_Routes;set=>_Routes=value??[];} private string[] _Dns=[]; public string[] Dns {get=>_Dns;set=>_Dns=value??[];} private string[] _Conflicts=[]; public string[] Conflicts {get=>_Conflicts;set=>_Conflicts=value??[];} private string[] _Vpn=[]; public string[] Vpn {get=>_Vpn;set=>_Vpn=value??[];} public string Proxy {get;set;}=""; public string SecureDns {get;set;}=""; public string? Error {get;set;} }

public sealed class BrowserPolicyView {public bool ChromeConfigured {get;set;} public bool EdgeConfigured {get;set;} public bool ChromeReady {get;set;} public bool EdgeReady {get;set;} public string ChromeReason {get;set;}=""; public string EdgeReason {get;set;}=""; public string Reason {get;set;}="";}
