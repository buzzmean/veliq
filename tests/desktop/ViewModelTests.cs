using System.Text.Json;
using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class FakeService : IServiceClient
{
    public Snapshot State = new() { Version = "0.3.0-dev", Primary = "DIRECT", Backend = new() { Ready = true }, Routes = [new() { Id = "DIRECT", Status = "healthy", ObservedAt = DateTimeOffset.UtcNow, RttMs = 10 }, new() { Id = "VPS-01", Status = "healthy", ObservedAt = DateTimeOffset.UtcNow, RttMs = 8, Score = 3 }], Profiles = [new() { Id = "game", Name = "Игра", Executables = ["C:\\game.exe"], Mode = "AUTO" }] };
    public Exception? Failure; public List<(string method, object? payload)> Calls = [];
    public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
    {
        Calls.Add((method, payload));
        if (Failure is not null)
            return Task.FromException<T>(Failure);
        object result = method switch
        {
            "status" or "optimize" => State,
            "profiles" => State.Profiles,
            "processes" => Array.Empty<ProcessIdentity>(),
            "capture.diagnostics" => new CaptureEvidence(),
            "browser.status" => new BrowserTransportSnapshot(),
            "gameudp.status" => new GameUdpStatus(),
            "update.status" => new UpdateSnapshot(),
            "profile.set" or "profile.delete" => State.Profiles,
            "settings.set" => payload!,
            "quality.diagnostics" => new DropDiagnostics(),
 "local.network" => new NetworkObservation{Error="not measured"},
 "local.get"=>new LocalStrategyConfig(),
 "local.set"=>payload!,
 "local.metrics"=>new LocalStrategyMetrics(),
            "diagnostics" => new[] { new Check { Name = "UDP", Status = "healthy" }, new Check { Name = "TCP", Status = "not configured" }, new Check { Name = "Relay", Status = "unavailable" } },
            _ => throw new Exception(method)
        };
        return Task.FromResult((T)result);
    }
}
public sealed class ViewModelTests
{
    [Fact]
    public async Task ActiveAppsUseDisplayNameExecutableOrOtherWithoutExposingInternalIDs()
    {
        var service = new FakeService();
        service.State.ActiveApps = ["game", "auto-abcd", "auto-other", "auto-duplicate"];
        service.State.ActiveAppExecutables["auto-abcd"] = "example.exe";
        service.State.ActiveAppExecutables["auto-duplicate"] = "EXAMPLE.exe";
        var vm = new DesktopViewModel(service);
        await vm.RefreshAsync();
        Assert.Equal("Игра, example.exe, Другое приложение", vm.ActiveApps);
        Assert.Contains("auto-abcd", vm.Snapshot!.ActiveApps);
    }
    [Fact]
    public void ApplicationProtocolsUseOnlyFreshAttributedCapture()
    {
        var row=new ApplicationRow();
        var p=new Profile{Id="browser",Executables=["C:\\chrome.exe"]};
        var processes=new[]{new ProcessIdentity{PID=42,CreationTime=7,Path="C:\\chrome.exe"}};
        var evidence=new CaptureEvidence{Flows=[new CaptureFlow{Pid=42,CreationTime=7,Exe="C:\\chrome.exe",Protocol="tcp",IpVersion="IPv4",SelectedRoute="RELAY",RelayId="VPS-01",LastSeen=DateTimeOffset.UtcNow}]};
        row.Update(p,processes,evidence);
        Assert.Contains("VPS-01",row.Tcp);Assert.Equal(Text.Get("NoData"),row.Udp);
        Assert.Equal(Text.Get("IPv6Unsupported"),row.Ipv6);
        evidence.Flows[0].CreationTime=8;row.Update(p,processes,evidence);
        Assert.Equal(Text.Get("NoData"),row.Tcp);
    }
    [Fact]
    public async Task HomeUsesOnlyRealFreshMeasurements()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        Assert.Equal("Нет данных", vm.Primary);
        await vm.RefreshAsync();
        Assert.True(vm.Available);
        Assert.Equal("Напрямую", vm.Primary);
        Assert.Equal("10,0 мс", vm.DirectLatency);
        Assert.Equal("8,0 мс", vm.RelayLatency);
        Assert.Equal("Не запущен", vm.Applications.Single().ProcessStatus);
        service.State.Routes[0].ObservedAt = DateTimeOffset.UtcNow.AddMinutes(-2);
        vm.Apply(service.State);
        Assert.Equal("Нет данных", vm.DirectLatency);
        Assert.Equal("Недоступен", vm.Routes[0].Status);
    }
    [Fact]
    public async Task ServiceUnavailableClearsStaleTelemetryAndCanReconnect()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        await vm.RefreshAsync();
        service.Failure = new ServiceException(ServiceFailure.Stopped);
        await vm.RefreshAsync();
        Assert.False(vm.Available);
        Assert.Equal("Служба VELIQ остановлена", vm.Connection);
        Assert.Equal("Нет данных", vm.Rx);
        Assert.Empty(vm.Routes);
        service.Failure = null;
        await vm.RefreshAsync();
        Assert.True(vm.Available);
    }
    [Fact]
    public async Task ManualRequiresActualAvailableRelayAndBlockCapability()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        await vm.RefreshAsync();
        Assert.False(await vm.SetProfileAsync(service.State.Profiles[0], "MANUAL", "nonexistent"));
        Assert.False(await vm.SetProfileAsync(service.State.Profiles[0], "BLOCK", null));
        Assert.DoesNotContain(service.Calls, c => c.method == "profile.set");
        Assert.True(await vm.SetProfileAsync(service.State.Profiles[0], "MANUAL", "VPS-01"));
        var sent = (Profile)service.Calls.Single(c => c.method == "profile.set").payload!;
        Assert.Equal("MANUAL", sent.Mode);
        Assert.Equal("VPS-01", sent.RelayId);
        Assert.Equal("AUTO", service.State.Profiles[0].Mode);
    }
    [Fact]
    public async Task ProfileCommandsPreserveIdentityAndMetadata()
    {
        var service = new FakeService();
        var profile = service.State.Profiles[0];
        profile.SignatureSha256 = "pinned";
        var vm = new DesktopViewModel(service);
        await vm.RefreshAsync();
        await vm.SetProfileAsync(profile, "DIRECT", null);
        var p = (Profile)service.Calls.Single(c => c.method == "profile.set").payload!;
        Assert.Equal(profile.Id, p.Id);
        Assert.Equal(profile.Executables, p.Executables);
        Assert.Equal("pinned", p.SignatureSha256);
        await vm.DeleteApplicationAsync(profile);
        Assert.DoesNotContain(service.Calls, c => c.method == "profile.delete");
        profile.Custom = true;
        await vm.DeleteApplicationAsync(profile);
        Assert.Contains(service.Calls, c => c.method == "profile.delete");
    }
    [Fact]
    public async Task AddExecutableUsesRealFileAndProfileIpc()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe");
        try
        {
            await File.WriteAllBytesAsync(path, [0]);
            Assert.True(await vm.AddApplicationAsync(path));
            var profile = (Profile)service.Calls.Single(c => c.method == "profile.set").payload!;
            Assert.Equal(path, profile.Executables.Single());
            Assert.True(profile.Custom);
            Assert.Equal("DIRECT", profile.Mode);
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public void ProcessReuseCannotDisplayOldCaptureRoute()
    {
        var row = new ApplicationRow();
        var profile = new Profile { Name = "Игра", Executables = ["C:\\game.exe"] };
        var process = new ProcessIdentity { PID = 7, Path = "C:\\game.exe", CreationTime = 100 };
        var capture = new CaptureEvidence { Flows = [new() { Pid = 7, Exe = process.Path, CreationTime = 99, SelectedRoute = "RELAY", RelayId = "VPS-01", LastSeen = DateTimeOffset.UtcNow }] };
        row.Update(profile, [process], capture);
        Assert.Equal("Активен", row.ProcessStatus);
        Assert.Equal("Нет данных", row.Route);
        capture.Flows[0].CreationTime = 100;
        row.Update(profile, [process], capture);
        Assert.Equal("VPS-01", row.Route);
    }
    [Fact]
    public async Task DiagnosticsAreRussianAndNotFabricated()
    {
        var vm = new DesktopViewModel(new FakeService());
        await vm.DiagnoseAsync();
        Assert.Contains(vm.Diagnostics, c => c.Name == "Служба Windows" && c.Status == "Работает");
        Assert.Contains(vm.Diagnostics, c => c.Name == "TCP" && c.Status == "Не настроено");
        Assert.Contains(vm.Diagnostics, c => c.Name == "Соединение через сервер" && c.Status == "Недоступно");
        Assert.Contains(vm.Diagnostics, c => c.Name == "Прямое соединение" && c.Status == "Работает");
    }
    [Theory][InlineData(ServiceFailure.NotInstalled, "Служба VELIQ не установлена")][InlineData(ServiceFailure.Stopped, "Служба VELIQ остановлена")][InlineData(ServiceFailure.Incompatible, "Несовместимая версия службы")][InlineData(ServiceFailure.Unavailable, "Не удалось подключиться к службе")] public void StatusMappingIsRussian(ServiceFailure failure, string expected) => Assert.Equal(expected, Text.Failure(new ServiceException(failure, "English internals")));
    [Fact]
    public void RouteRenderingMarksPrimaryBackupAndNoData()
    {
        var s = new FakeService().State;
        s.Primary = "VPS-01";
        s.Secondary = "DIRECT";
        s.Routes[1].Status = "unavailable";
        var vm = new DesktopViewModel(new FakeService());
        vm.Apply(s);
        Assert.Equal("Основной", vm.Routes[1].Role);
        Assert.Equal("Резервный", vm.Routes[0].Role);
        Assert.Equal("Нет данных", vm.Routes[1].Rtt);
        Assert.Empty(vm.Relays);
    }
}
public sealed class HistoryAndSettingsTests
{
    [Fact]
    public void HistoryRendersActualNanosecondMeasurementsAndRouteChanges()
    {
        var service = new FakeService();
        service.State.History = JsonDocument.Parse("""
 {"measurements":[{"route_id":"DIRECT","rtt":12500000,"jitter":2000000,"loss":0.1,"available":true,"observed_at":"2026-10-13T01:00:00Z"},{"route_id":"VPS-01","rtt":0,"jitter":0,"loss":1,"available":false,"observed_at":"2026-10-13T01:00:01Z"}],"changes":[{"From":"DIRECT","To":"VPS-01","At":"2026-10-13T01:00:01Z"}]}
 """).RootElement.Clone();
        var vm = new DesktopViewModel(service);
        vm.Apply(service.State);
        Assert.Equal("Нет данных", vm.Measurements[0].Rtt);
        Assert.Equal("12,5 мс", vm.Measurements[1].Rtt);
        Assert.Contains("Напрямую → VPS-01", vm.Changes.Single());
    }
    [Fact]
    public async Task PollingPreservesModeAndRelayCollectionIdentity()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        await vm.RefreshAsync();
        var mode = vm.Modes[2];
        var relay = vm.Relays[0];
        await vm.RefreshAsync();
        Assert.Same(mode, vm.Modes[2]);
        Assert.Same(relay, vm.Relays[0]);
    }
    [Fact]
    public async Task SettingsUseServiceIpcAndDoNotOfferUnsupportedBlocking()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        await vm.RefreshAsync();
        Assert.DoesNotContain(vm.Modes, m => m.Value == "BLOCK");
        Assert.False(await vm.SaveServiceSettingsAsync(new()
        {
            Failover = "BLOCK"
        }));
        Assert.True(await vm.SaveServiceSettingsAsync(new()
        {
            Automatic = true,
            Failover = "DIRECT",
            UpdateChannel = "preview"
        }));
        Assert.Contains(service.Calls, c => c.method == "settings.set");
        service.State.Backend.Capabilities.Tcp = true;
        vm.Apply(service.State);
        Assert.Contains(vm.Modes, m => m.Value == "BLOCK");
    }
    [Fact]
    public async Task FailedProfileSaveKeepsOriginalModeAndShowsRussianError()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        await vm.RefreshAsync();
        service.Failure = new ServiceException(ServiceFailure.Rejected, "English internals");
        Assert.False(await vm.SetProfileAsync(service.State.Profiles[0], "DIRECT", null));
        Assert.Equal("AUTO", service.State.Profiles[0].Mode);
        Assert.DoesNotContain("English", vm.Error);
    }
}
public sealed class ApplicationStateTests
{
    [Fact]
    public async Task ProcessQueryRequestsOnlyConfiguredExecutables()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        await vm.RefreshAsync();
        var query = JsonSerializer.SerializeToElement(service.Calls.Single(c => c.method == "processes").payload);
        Assert.Equal("C:\\game.exe", query.GetProperty("executables")[0].GetString());
    }
    [Fact]
    public void ActiveBasenameProfileDisplaysRealExecutablePath()
    {
        var row = new ApplicationRow();
        row.Update(new()
        {
            Executables = ["game.exe"]
        }, [new() { PID = 7, Path = "C:\\games\\game.exe", CreationTime = 1 }], null);
        Assert.Equal("C:\\games\\game.exe", row.Path);
        Assert.Equal("Активен", row.ProcessStatus);
    }
    [Fact]
    public async Task DuplicateExecutableDoesNotCreateConflictingProfile()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe");
        try
        {
            await File.WriteAllBytesAsync(path, [0]);
            var service = new FakeService();
            service.State.Profiles[0].Executables = [path];
            var vm = new DesktopViewModel(service);
            await vm.RefreshAsync();
            Assert.False(await vm.AddApplicationAsync(path));
            Assert.DoesNotContain(service.Calls, c => c.method == "profile.set");
        }
        finally { File.Delete(path); }
    }
    [Fact]
    public async Task StaleRelayCannotBeSavedEvenIfPreviouslyListed()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        await vm.RefreshAsync();
        service.State.Routes[1].ObservedAt = DateTimeOffset.UtcNow.AddMinutes(-2);
        Assert.False(await vm.SetProfileAsync(service.State.Profiles[0], "MANUAL", "VPS-01"));
        Assert.DoesNotContain(service.Calls, c => c.method == "profile.set");
    }
}
public sealed class PollingPresentationTests
{
    [Fact]
    public void UnchangedSnapshotsKeepRouteRowsStableForSelection()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        vm.Apply(service.State);
        var row = vm.Routes[0];
        vm.Apply(service.State);
        Assert.Same(row, vm.Routes[0]);
    }
}
public sealed class CommandDisconnectionTests
{
    [Fact]
    public async Task LostServiceDuringCommandImmediatelyClearsTelemetry()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        await vm.RefreshAsync();
        service.Failure = new ServiceException(ServiceFailure.Unavailable);
        await vm.OptimizeAsync(true);
        Assert.False(vm.Available);
        Assert.Equal("Нет данных", vm.CurrentLatency);
        Assert.Empty(vm.Applications);
        Assert.Equal("Не удалось подключиться к службе", vm.Connection);
    }
}
public sealed class QualityPresentationTests
{
    [Fact]
    public void OptionalQualityFieldsPreserveOldServiceCompatibility()
    {
        var service = new FakeService();
        var vm = new DesktopViewModel(service);
        vm.Apply(service.State);
        Assert.Equal("Нет данных", vm.Routes[0].Burst);
        Assert.Equal("Нет данных", vm.CurrentSamples);
        service.State.Routes[0].Quality = new()
        {
            MaxLossBurst = 5,
            SampleCount = 50,
            NetworkSampleCount = 50,
            Stability = .8,
            ProbeLoss = .1,
            PercentilesAvailable = true,
            MedianRtt = 20000000,
            P95Rtt = 80000000
        };
        service.State.Routes[0].Status = "unhealthy";
        vm.Apply(service.State);
        Assert.Equal("5", vm.Routes[0].Burst);
        Assert.Equal("50", vm.CurrentSamples);
        Assert.Equal("20,0 мс", vm.Routes[0].Median);
        Assert.Equal("80,0 мс", vm.Routes[0].P95);
        Assert.Equal(Text.Percent(.1), vm.Routes[0].Loss);
        Assert.Equal(Text.Percent(.1), vm.Loss);
    }
    [Fact]
    public void QualityJsonUsesRealNanosecondDurations()
    {
        var route = JsonSerializer.Deserialize<Route>(
            """{"id":"DIRECT","quality":{"sample_count":50,"network_sample_count":50,"max_loss_burst":3,"ewma_rtt":12000000,"p95_rtt":25000000,"percentiles_available":true}}""",
            WireJson.Options)!;
        Assert.Equal(12000000, route.Quality!.EwmaRtt);
        Assert.Equal(3, route.Quality.MaxLossBurst);
    }
}

public sealed class LocalStrategyUiTests {
 [Fact] public void DirectPlusShowsOnlyRealAttributedEvidence(){
 var row=new ApplicationRow();var p=new Profile{Id="chosen",Name="Выбрано",Executables=["C:\\chosen.exe"],Mode="DIRECT_PLUS",LocalStrategyId="s"};
 var process=new ProcessIdentity{PID=9,CreationTime=11,Path="C:\\chosen.exe"};var flow=new CaptureFlow{Pid=9,CreationTime=11,Exe=process.Path,Protocol="tcp",IpVersion="IPv4",SelectedRoute="DIRECT_PLUS",Strategy="s",Destination="203.0.113.9:443",Counters=new(){DirectPlusBytes=100},LastSeen=DateTimeOffset.UtcNow};
 row.Update(p,[process],new(){Flows=[flow]});Assert.Equal("Напрямую+",row.Route);Assert.Contains("203.0.113.9:443",row.LocalDetails);Assert.Contains("s:",row.LocalDetails);
 flow.CreationTime=12;row.Update(p,[process],new(){Flows=[flow]});Assert.Equal(Text.Get("NoData"),row.Route);Assert.DoesNotContain("203.0.113.9",row.LocalDetails);
 Assert.Equal("s",p.Copy().LocalStrategyId);Assert.Equal("Напрямую+",Text.Mode("DIRECT_PLUS"));
 }
 [Fact]public async Task ConfigurationUsesAuthenticatedServiceNotGuiPacketEngine(){var s=new FakeService();var vm=new DesktopViewModel(s);var config=new LocalStrategyConfig{Enabled=true,User=[new(){Id="s",Application="chosen.exe",Ips=["203.0.113.9"]}]};await vm.SaveLocalStrategiesAsync(config);Assert.Contains(s.Calls,c=>c.method=="local.set");Assert.Equal("s",System.Text.Json.JsonSerializer.Deserialize<LocalStrategyConfig>(System.Text.Json.JsonSerializer.Serialize(config,WireJson.Options),WireJson.Options)!.User[0].Id);}
}
