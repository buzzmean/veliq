using System.Text.Json;
using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class GameUdpTests {
 [Fact]public void ActualDecoysAndRepliesRequiredForActiveMessage(){
 var p=new GameUdpProfile{Name="PUBG",Engine=new(){Enabled=true}};
 Assert.Contains("Готов",p.Summary);
 p.Engine.Flows=[new(){Stage="LOCAL_UDP",Destination="18.157.46.1:7766",FakePackets=24,InboundPackets=0}];Assert.Contains("приманок: 24",p.Summary);Assert.Contains("ответов: 0",p.Summary);Assert.DoesNotContain("пинг",p.Summary);
 p.Reason="DRIVER_ANTICHEAT_COMPATIBILITY_UNVERIFIED";Assert.Contains("не проверена",p.Summary);
 p.Engine.Enabled=false;Assert.Contains("выключен",p.Summary);
 }
 [Fact]public void ReadsSnakeCaseAndDoesNotReportMatchSuccess(){
 var s=JsonSerializer.Deserialize<GameUdpStatus>("""{"profiles":[{"profile_id":"pubg","name":"PUBG","state":"ACTIVE","engine":{"enabled":true,"flows":[{"flow_id":1,"stage":"RELAY","destination":"18.157.46.1:7766","inbound_packets":7,"fake_packets":0}]}}]}""",WireJson.Options)!;
 var p=Assert.Single(s.Profiles);Assert.Equal("pubg",p.ProfileId);Assert.Contains("релей",p.Summary);Assert.Contains("ответов: 7",p.Summary);Assert.DoesNotContain("успеш",p.Summary);
 var vm=new DesktopViewModel(new FakeService());vm.ApplyGameUdp(s);var count=0;vm.GameUdpProfiles.CollectionChanged+=(_,_)=>count++;vm.ApplyGameUdp(s);Assert.Equal(0,count);
 }
 [Fact]public void UnexpectedServiceTextIsNotShownAsRawError(){Assert.DoesNotContain("secret",GameUdpMessages.Reason("secret=password"));}
}
public sealed class GameUdpRejectedTests {
 sealed class Rejected : IServiceClient {
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){Assert.Equal("gameudp.set",method);return Task.FromException<T>(new ServiceException(ServiceFailure.Rejected,"GAME_UDP_ANTICHEAT_COMPATIBILITY_UNVERIFIED"));}
 }
 [Fact]public async Task AnticheatRejectionHasReadableReasonAndKeepsApplications(){
 var vm=new DesktopViewModel(new Rejected());vm.Apply(new FakeService().State);var row=Assert.Single(vm.Applications);
 await vm.SetGameUdpAsync("game",true);Assert.Contains("Vanguard/FACEIT",vm.Notice);Assert.Same(row,Assert.Single(vm.Applications));Assert.Empty(vm.Error);
 }
}
public class PubgReadinessTests {
 [Fact]public void ActiveArmedDoesNotClaimInjectedPacketsOrMatchPass(){
 var s=JsonSerializer.Deserialize<GameUdpStatus>("""{"guard":{"driver_anti_cheat":"VANGUARD_OR_FACEIT"},"profiles":[{"profile_id":"pubg","state":"ACTIVE","ready":true,"activity":"WAITING_NEW_FLOW","engine":{"enabled":true,"initial_policy":"LOCAL_FIRST_UNCONFIRMED_ENDPOINT","flows":[]}}]}""",WireJson.Options)!;
 var p=Assert.Single(s.Profiles);Assert.True(p.Ready);Assert.Contains("Ожидаем",p.Summary);Assert.Contains("K12/N2",p.Summary);Assert.DoesNotContain("Обход активен",p.Summary);Assert.DoesNotContain("успеш",p.Summary);Assert.Contains("PUBG:",ClubPresentation.GameLine(s));Assert.DoesNotContain("Vanguard",ClubPresentation.GameLine(s));
 p.Reason="FOREIGN_UDP_INTERCEPTOR";Assert.Contains("двойная обработка",ClubPresentation.GameLine(s));
 }
 [Fact]public void IncompletePrimingHasHonestReadableFailure(){var p=new GameUdpProfile{Engine=new(){Enabled=true,Flows=[new(){Stage="LOCAL_UDP",State="LOCAL_PRIMING_INCOMPLETE",Reason="GLOBAL_DECOY_RATE_LIMITED",FakePackets=12}]}};Assert.Contains("не полностью",p.Summary);Assert.Contains("лимит",p.Summary);Assert.DoesNotContain("Обход активен",p.Summary);}
}

public sealed class LocalOnlyGameTests {
 sealed class LocalService : IServiceClient {
  public object? Payload;
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){Assert.Equal("gameudp.set",method);Payload=payload;return Task.FromResult((T)(object)new GameUdpStatus());}
 }
 [Fact]public async Task ToggleExplicitlyRequestsNoRelay(){var s=new LocalService();var vm=new DesktopViewModel(s);await vm.SetGameUdpAsync("cs2",true);var p=JsonSerializer.SerializeToElement(s.Payload);Assert.True(p.GetProperty("local_only").GetBoolean());Assert.Contains("без VPS",vm.Notice);}
 [Fact]public void PolicyAndStalledFlowDoNotClaimHealthyPlay(){
  var p=new GameUdpProfile{Engine=new(){Enabled=true,LocalOnly=true}};
  Assert.Contains("VPS запрещён",p.Summary);
  p.Engine.Flows=[new(){Stage="DIRECT",State="INSUFFICIENT_REPLIES",InboundPackets=6}];
  Assert.Contains("устойчивых ответов нет",p.Summary);
  p.Reason="GAME_UDP_LOCAL_ONLY_EXHAUSTED";Assert.Contains("исчерпаны",p.Summary);Assert.Contains("VPS запрещён",p.Summary);
 }
 [Fact]public void PinnedRelayIsVisibleAfterPolicySwitch(){
  var p=new GameUdpProfile{Engine=new(){Enabled=true,LocalOnly=true,Flows=[new(){Stage="RELAY",LastOutgoing=DateTimeOffset.UtcNow}]}};
  Assert.Contains("ещё идёт через VPS",p.Summary);
 }
 [Fact]public void StaleTrafficDoesNotClaimActiveLocal(){
  var p=new GameUdpProfile{Engine=new(){Enabled=true,LocalOnly=true,Flows=[new(){Stage="LOCAL_UDP",FakePackets=24,LastOutgoing=DateTimeOffset.UtcNow.AddMinutes(-1)}]}};
  Assert.Contains("Свежий игровой трафик не наблюдается",p.Summary);
 }
}

public sealed class LocalOnlyCatalogTests {
 sealed class Service : IServiceClient {
  public List<(string Method,object? Payload)> Calls=[];
  public bool Reject;
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){
   Calls.Add((method,payload));
   if(method=="gameudp.set" && Reject)return Task.FromException<T>(new ServiceException(ServiceFailure.Rejected,"UNKNOWN_FIELD"));
   object result=method switch {
    "profiles"=>new Profile[]{new(){Id="cs2",Name="CS2",Mode="DIRECT",Executables=[@"C:\Games\cs2.exe"]}},
    "gameudp.status"=>new GameUdpStatus(),"gameudp.set"=>new GameUdpStatus(),"status"=>new Snapshot(),_=>throw new InvalidOperationException(method)
   };return Task.FromResult((T)result);
  }
 }
 [Theory][InlineData(false)][InlineData(true)]public async Task LocalSelectionNeverRetriesWithoutNoRelayPolicy(bool reject){
  var s=new Service{Reject=reject};var vm=new GameCatalogViewModel(s);await vm.RefreshAsync();var card=vm.Games.Single(g=>g.Id=="cs2");card.Mode="DIRECT_PLUS";await vm.ApplyAsync(card);
  var call=Assert.Single(s.Calls,c=>c.Method=="gameudp.set");Assert.True(JsonSerializer.SerializeToElement(call.Payload).GetProperty("local_only").GetBoolean());
  Assert.DoesNotContain(s.Calls,c=>c.Method=="profile.set");
  Assert.Contains(reject?"не сохранён":"без VPS",vm.Notice);
 }
}
