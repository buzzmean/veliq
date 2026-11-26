using System.Text.Json;
using Veliq.Desktop;
using Xunit;
namespace Veliq.Tests;

public sealed class PickerService : IServiceClient
{
    public Snapshot State = new() { Profiles = [] };
    public RunningApplicationList Running = new();
    public readonly List<(string Method, object? Payload)> Calls = [];
    public bool RejectStatus;
    public bool RejectApplicationQuery;
    public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
    {
        Calls.Add((method, payload));
        if (method == "status" && RejectStatus) return Task.FromException<T>(new ServiceException(ServiceFailure.Unavailable));
        if (method == "processes" && RejectApplicationQuery && payload is not null && JsonSerializer.SerializeToElement(payload).TryGetProperty("applications", out _))
            return Task.FromException<T>(new ServiceException(ServiceFailure.Rejected));
        if (method == "profile.set") State.Profiles = [.. State.Profiles, ((Profile)payload!).Copy()];
        object result = method switch
        {
            "profiles" or "profile.set" => State.Profiles,
            "status" => State,
            "processes" when payload is not null && JsonSerializer.SerializeToElement(payload).TryGetProperty("applications", out _) => Running,
            "processes" => Array.Empty<ProcessIdentity>(),
            "capture.diagnostics" => new CaptureEvidence(),
            "browser.status" => new BrowserTransportSnapshot(),
            _ => throw new InvalidOperationException(method)
        };
        return Task.FromResult((T)result);
    }
}
public sealed class ApplicationPickerTests
{
    [Fact]
    public async Task PickerUsesBoundedServiceViewAndSearchesApplicationExePathAndPid()
    {
        var service = new PickerService { Running = new() { Applications = [
            new() { Name = "Discord.exe", Path = @"C:\Apps\Discord.exe", Pids = [55], Pid = 55, ProcessCount = 1, DisplayName = "Discord" },
            new() { Name = "chrome.exe", Path = @"C:\Browser\chrome.exe", Pids = [20,21,22,23,24,25,26,27,28,29], Pid = 20, ProcessCount = 10, DisplayName = "Google Chrome" }
        ] } };
        var picker = new DesktopViewModel(service).CreateApplicationPicker();
        await picker.RefreshAsync();
        var query = JsonSerializer.SerializeToElement(service.Calls.Single().Payload);
        Assert.True(query.GetProperty("applications").GetBoolean());
        Assert.Equal(128, query.GetProperty("limit").GetInt32());
        Assert.Equal(new[] { "Discord", "Google Chrome" }, picker.Applications.Select(a => a.Title));
        Assert.Equal(10, picker.Applications[1].ProcessCount);
        foreach (string term in new[] { "GOOGLE", "chrome.exe", @"C:\Browser", "29" })
        {
            picker.Search = term;
            Assert.Equal("chrome.exe", Assert.Single(picker.Applications).Name);
        }
        picker.Search = "not running";
        Assert.Empty(picker.Applications);
        Assert.Equal(Text.Get("RunningEmpty"), picker.Status);
        picker.Search = "";
        service.Running = new() { Applications = [new() { Name = "new.exe", Path = @"C:\new.exe", Pid = 99, Pids = [99], ProcessCount = 1 }], Truncated = true };
        await picker.RefreshAsync();
        Assert.Equal("new.exe", Assert.Single(picker.Applications).Name);
        Assert.True(picker.Truncated);
        Assert.Equal(Text.Get("RunningTruncated"), picker.Status);
    }
    [Fact]
    public async Task FullExecutablePathIsSavedAndAppearsImmediately()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid()+".exe");
        try
        {
            await File.WriteAllBytesAsync(path, [0]);
            var service = new PickerService();
            var desktop = new DesktopViewModel(service);
            await desktop.RefreshAsync();
            // A stalled/unavailable next status poll cannot delay or erase the
            // authoritative profile.set result and the newly inserted row.
            service.RejectStatus = true;
            Assert.True(await desktop.AddApplicationAsync(path));
            var saved = Assert.Single(service.State.Profiles);
            Assert.Equal(Path.GetFullPath(path), Assert.Single(saved.Executables));
            Assert.True(saved.Custom);
            Assert.Equal("DIRECT", saved.Mode);
            Assert.Equal(saved.Id, Assert.Single(desktop.Applications).Profile.Id);
            Assert.Equal(path, Assert.Single(desktop.Applications).Path);
            Assert.Single(service.Calls, c => c.Method == "status");
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public async Task DuplicateRechecksServiceAndRestoresEditorRow()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid()+".exe");
        try
        {
            await File.WriteAllBytesAsync(path, [0]);
            var service = new PickerService();
            var desktop = new DesktopViewModel(service) { ShowTechnical = true };
            await desktop.RefreshAsync();
            service.State = new() { Profiles = [new() { Id = "existing", Executables = [path], Custom = true }] };
            Assert.False(await desktop.AddApplicationAsync(path));
            Assert.Equal(Text.Get("AlreadyAdded"), desktop.Error);
            Assert.Contains(desktop.ServiceApplications, a => a.Profile.Id == "existing");
            Assert.DoesNotContain(service.Calls, c => c.Method == "profile.set");
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public async Task ManualFilePickerCancellationAndSelectionKeepWorking()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid()+".exe");
        try
        {
            await File.WriteAllBytesAsync(path, [0]);
            var service = new PickerService();
            var desktop = new DesktopViewModel(service);
            Assert.Null(await desktop.AddApplicationFromFileAsync(() => null));
            Assert.Empty(service.Calls);
            int opened = 0;
            Assert.True(await desktop.AddApplicationFromFileAsync(() => { opened++; return path; }));
            Assert.Equal(1, opened);
            Assert.Equal(path, Assert.Single(service.State.Profiles).Executables.Single());
            Assert.Single(desktop.Applications);
            Assert.False(await desktop.AddApplicationFromFileAsync(() => path));
            Assert.Single(service.Calls, c => c.Method == "profile.set");
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public async Task UnsupportedApplicationQueryKeepsManualFileFallbackAvailable()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid()+".exe");
        try
        {
            await File.WriteAllBytesAsync(path, [0]);
            var service = new PickerService { RejectApplicationQuery = true };
            var desktop = new DesktopViewModel(service);
            var picker = desktop.CreateApplicationPicker();
            await picker.RefreshAsync();
            Assert.Empty(picker.Applications);
            Assert.NotEmpty(picker.Error);
            Assert.False(picker.Busy);
            Assert.True(await desktop.AddApplicationFromFileAsync(() => path));
            Assert.Equal(path, Assert.Single(service.State.Profiles).Executables.Single());
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public async Task DirectPlusCanStillBeSavedWithoutLosingItsStrategy()
    {
        var service = new FakeService();
        service.State.Profiles[0].LocalStrategyId = "tcp-split-1";
        var desktop = new DesktopViewModel(service);
        await desktop.RefreshAsync();
        Assert.Contains(desktop.Modes, m => m.Value == "DIRECT_PLUS");
        Assert.True(await desktop.SetProfileAsync(service.State.Profiles[0], "DIRECT_PLUS", null));
        var saved = (Profile)service.Calls.Single(c => c.method == "profile.set").payload!;
        Assert.Equal("DIRECT_PLUS", saved.Mode);
        Assert.Equal("tcp-split-1", saved.LocalStrategyId);
        Assert.Equal(Text.Get("DirectPlus"), Text.Mode(saved.Mode));
    }
}

public sealed class DirectPlusV2PresentationTests
{
 [Fact] public void TruncatedSnapshotRetainsPositiveRelayEvidenceAndLiveIdleConnections()
 {
  var service=new FakeService();var vm=new DesktopViewModel(service);
  var process=new ProcessIdentity{PID=42,CreationTime=100,Path=@"C:\game.exe"};
  var f=new CaptureFlow{Pid=42,CreationTime=100,Exe=process.Path,SelectedRoute="RELAY",RelayId="VPS-01",Protocol="tcp",IpVersion="IPv4",Active=true,IdentityCurrent=true,LastSeen=DateTimeOffset.UtcNow.AddMinutes(-2)};
  vm.Apply(service.State,[process],new(){Truncated=true,Flows=[f]});Assert.Equal("VPS-01",vm.Applications[0].Route);
  // Service-confirmed identity is usable when optional processes IPC failed.
  vm.Apply(service.State,null,new(){Truncated=true,Flows=[f]});Assert.Equal("VPS-01",vm.Applications[0].Route);
  f.IdentityCurrent=false;vm.Apply(service.State,null,new(){Flows=[f]});Assert.Equal(Text.Get("NoData"),vm.Applications[0].Route);
 }
 [Fact] public void AdvancedChainsRoundTripWithoutUnrecognizedPresentationFields()
 {
  var p=new LocalStrategyProfile{Id="v2",Strategy="chain",Preset="youtube",PresetVersion=2,QuicFallback=true,Actions=[new(){Kind="fake-tls",Ttl=5},new(){Kind="tcp-multisplit",Anchor="sni",Positions=[1,5]},new(){Kind="tcp-disorder"}]};
  var json=JsonSerializer.SerializeToElement(p,WireJson.Options);Assert.False(json.TryGetProperty("advanced",out _));Assert.Equal(5,json.GetProperty("actions")[0].GetProperty("ttl").GetInt32());
  var restored=json.Deserialize<LocalStrategyProfile>(WireJson.Options)!;Assert.Equal(3,restored.Actions.Length);Assert.Contains("TTL=5",restored.Advanced);Assert.True(restored.QuicFallback);
 }
 [Fact] public void ActualFlowDetailsExposeOnlyCommittedTTLAndCounters()
 {
  var row=new ApplicationRow();var p=new Profile{Executables=[@"C:\chrome.exe"]};var id=new ProcessIdentity{PID=42,CreationTime=10,Path=p.Executables[0]};
  var f=new CaptureFlow{Pid=42,CreationTime=10,Exe=id.Path,Protocol="tcp",SelectedRoute="DIRECT_PLUS",Strategy="p2-fake5",Preset="youtube",Chain="fake-tls + tcp-multisplit",Domain="www.youtube.com",FakeTtl=5,LastSeen=DateTimeOffset.UtcNow,Counters=new(){DirectPlusPackets=1,DirectPlusBytes=500,FakeTlsPackets=1,RelayedBytes=0}};
  row.Update(p,[id],new(){Flows=[f]});Assert.Contains("youtube",row.LocalDetails);Assert.Contains("TTL=5",row.LocalDetails);Assert.Contains("fake-tls",row.LocalDetails);Assert.Equal(Text.Get("DirectPlus"),row.Route);
 }
}

public sealed class PresetCommandTests
{
 sealed class Service : IServiceClient
 {
  public FakeService Inner=new();public List<(string Method,object? Payload)> Calls=[];
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default)
  {
   Calls.Add((method,payload));
   if(method=="local.preset.apply")return Task.FromResult((T)(object)new PresetInstall{StrategyId="p2-youtube-fake5"});
   if(method=="local.presets")return Task.FromResult((T)(object)new[]{new LocalStrategyPreset{Id="youtube",Name="YouTube",Version=2}});
   return Inner.Call<T>(method,payload,cancellationToken);
  }
 }
 [Fact] public async Task OnePresetActionInstallsVersionedRulesThenSavesExactProfileIdentity()
 {
  var service=new Service();var vm=new DesktopViewModel(service);await vm.RefreshAsync();var original=service.Inner.State.Profiles[0];original.Executables=[Path.Combine(Path.GetTempPath(),"chrome.exe")];
  Assert.Equal("YouTube v2",(await vm.GetPresetsAsync()).Single().Label);
  Assert.True(await vm.ApplyPresetAsync(original,"youtube",true));
  var request=JsonSerializer.SerializeToElement(service.Calls.Single(c=>c.Method=="local.preset.apply").Payload);Assert.Equal(original.Executables[0],request.GetProperty("application").GetString());Assert.True(request.GetProperty("quic_fallback").GetBoolean());
  var saved=(Profile)service.Calls.Single(c=>c.Method=="profile.set").Payload!;Assert.Equal(original.Id,saved.Id);Assert.Equal("DIRECT_PLUS",saved.Mode);Assert.Equal("p2-youtube-fake5",saved.LocalStrategyId);Assert.Equal("AUTO",original.Mode);
 }
}
