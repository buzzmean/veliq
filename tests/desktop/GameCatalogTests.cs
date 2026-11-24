using Veliq.Desktop;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;
namespace Veliq.Tests;
public sealed class GameCatalogTests {
 [Fact]public void BundledCatalogHasSelectedGamesAndSafeDefaults(){
  var c=GameCatalog.Bundled();Assert.Equal(1,c.Version);Assert.Equal(13,c.Games.Length);Assert.All(c.Games,g=>Assert.Equal("DIRECT",g.DefaultMode));
  Assert.Contains(c.Games,g=>g.Id=="valorant"&&g.Executables.Contains("VALORANT-Win64-Shipping.exe")&&g.UdpPreset==""&&g.LauncherNeedsBypass);
  Assert.DoesNotContain(c.Games.SelectMany(g=>g.Executables),e=>e is "vgc.exe" or "vgk.exe" or "RiotClientServices.exe");
 }
 [Fact]public void TamperingAndUntrustedSignatureAreRejected(){
  var raw=JsonSerializer.SerializeToUtf8Bytes(GameCatalog.Bundled());Assert.Throws<InvalidDataException>(()=>GameCatalog.Parse(raw,GameCatalog.BundledSha256));
  using var key=RSA.Create(2048);var sig=key.SignData(raw,HashAlgorithmName.SHA256,RSASignaturePadding.Pss);Assert.Equal(13,GameCatalog.VerifySigned(raw,sig,key).Games.Length);
  raw[10]^=1;Assert.Throws<InvalidDataException>(()=>GameCatalog.VerifySigned(raw,sig,key));
 }
 sealed class Service:IServiceClient {
  public Profile[] Profiles=[new(){Id="riot-client",Name="Riot Client",Mode="DIRECT",Executables=["RiotClientServices.exe"],PolicyData=new(){["app_preset"]=JsonSerializer.SerializeToElement("riot-client")}}];
  public bool RelayHealthy=true;public string? Reject;
  public List<(string method,object? payload)> Calls=[];
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){Calls.Add((method,payload));if(method=="profile.set"&&Reject is not null)return Task.FromException<T>(new ServiceException(ServiceFailure.Rejected,Reject));object result=method switch{"profiles"=>Profiles,"profile.set"=>Profiles,"gameudp.status"=>new GameUdpStatus(),"status"=>new Snapshot{Routes=[new(){Id="VPS-PRIMARY",Status=RelayHealthy?"healthy":"unavailable"}]},_=>throw new ServiceException(ServiceFailure.Rejected)};return Task.FromResult((T)result);}
 }
 [Fact]public async Task RepairOnlyMutatesLauncherAndKeepsPolicyMetadata(){
  var s=new Service();var vm=new GameCatalogViewModel(s);await vm.RefreshAsync();var g=vm.Games.Single(g=>g.Id=="valorant");await vm.RepairLauncherAsync(g);
  var p=Assert.IsType<Profile>(Assert.Single(s.Calls,c=>c.method=="profile.set").payload);Assert.Equal("riot-client",p.Id);Assert.Equal("AUTO",p.Mode);Assert.True(p.PolicyData!.ContainsKey("app_preset"));Assert.Single(p.Executables);Assert.DoesNotContain("VALORANT",p.Executables[0]);
 }
 [Fact]public async Task AutoGameIsExplicitProfileAndNeverRequestsUdpOrRelay(){
  var s=new Service();var vm=new GameCatalogViewModel(s);await vm.RefreshAsync();var g=vm.Games.Single(g=>g.Id=="valorant");g.Mode="AUTO";await vm.ApplyAsync(g);
  var p=Assert.IsType<Profile>(Assert.Single(s.Calls,c=>c.method=="profile.set").payload);Assert.Equal("AUTO",p.Mode);Assert.Null(p.RelayId);Assert.Equal("game-valorant",p.Id);Assert.Contains("античит",g.Compatibility);Assert.DoesNotContain(s.Calls,c=>c.method=="gameudp.set");
 }
 [Fact]public async Task UnsupportedDirectPlusDoesNotMutateGame(){
  var s=new Service();var vm=new GameCatalogViewModel(s);await vm.RefreshAsync();var g=vm.Games.Single(g=>g.Id=="valorant");g.Mode="DIRECT_PLUS";await vm.ApplyAsync(g);Assert.DoesNotContain(s.Calls,c=>c.method=="profile.set"||c.method=="gameudp.set");Assert.Contains("не проверен",vm.Notice);
 }
 [Fact]public async Task RelayNeedsHealthyRouteAndExplicitApply(){
  var s=new Service{RelayHealthy=false};var vm=new GameCatalogViewModel(s);await vm.RefreshAsync();var g=vm.Games.Single(g=>g.Id=="valorant");g.Mode="MANUAL";await vm.ApplyAsync(g);Assert.DoesNotContain(s.Calls,c=>c.method=="profile.set");Assert.Contains("маршрут не изменён",vm.Notice);
  s.RelayHealthy=true;await vm.ApplyAsync(g);var p=Assert.IsType<Profile>(Assert.Single(s.Calls,c=>c.method=="profile.set").payload);Assert.Equal("MANUAL",p.Mode);Assert.Equal("VPS-PRIMARY",p.RelayId);Assert.Contains("пинг может вырасти",vm.Notice);
 }
 [Fact]public async Task ExistingGameIdentityAndExtensionDataSurviveModeChange(){
  var s=new Service{Profiles=[new(){Id="custom-game",Name="Existing",Executables=[@"D:\Games\VALORANT-Win64-Shipping.exe"],Publisher="Fixture",Mode="AUTO",Custom=true,PolicyData=new(){["identity"]=JsonSerializer.SerializeToElement(new{fixture=true})}}]};var vm=new GameCatalogViewModel(s);await vm.RefreshAsync();var g=vm.Games.Single(g=>g.Id=="valorant");g.Mode="DIRECT";await vm.ApplyAsync(g);var p=Assert.IsType<Profile>(Assert.Single(s.Calls,c=>c.method=="profile.set").payload);Assert.Equal("custom-game",p.Id);Assert.True(p.Custom);Assert.Equal("Fixture",p.Publisher);Assert.True(p.PolicyData!["identity"].GetProperty("fixture").GetBoolean());
 }
 [Fact]public async Task ClubRejectionDoesNotClearCatalogOrClaimSavedMode(){
  var s=new Service{Reject="CLUB_ADMIN_MANAGED"};var vm=new GameCatalogViewModel(s);await vm.RefreshAsync();var count=vm.Games.Count;var g=vm.Games.Single(g=>g.Id=="valorant");g.Mode="AUTO";await vm.ApplyAsync(g);Assert.Equal(count,vm.Games.Count);Assert.Null(g.Profile);Assert.Contains("администратор",vm.Notice);Assert.DoesNotContain("Активация",vm.Notice);
 }
 [Fact]public void RiotStatusDoesNotPromiseLauncherSuccessFromBytes(){
  using var d=JsonDocument.Parse("""{"records":[{"received_bytes":1000,"policy":{"action":"RELAY_REQUIRED"}}]}""");var s=GameCatalog.RiotActivity(d.RootElement);Assert.Contains("обмен",s);Assert.Contains("не подтверждён",s);
 }
 [Fact]public async Task SearchDoesNotCreateOrReplaceProfiles(){
  var s=new Service();var vm=new GameCatalogViewModel(s);await vm.RefreshAsync();vm.Search="Riot";Assert.Equal(2,vm.Games.Count);Assert.DoesNotContain(s.Calls,c=>c.method=="profile.set");
 }
 [Fact]public async Task QBadgesUseCommunityNamesAndRealRelayRoutes(){
  var s=new Service();var vm=new GameCatalogViewModel(s);await vm.RefreshAsync();
  Assert.Equal("LoL",vm.Games.Single(g=>g.Id=="lol").Badge);Assert.Equal("Dota 2",vm.Games.Single(g=>g.Id=="dota2").Badge);
  Assert.All(vm.Games,g=>Assert.False(g.Badge.Length==3&&g.Badge==g.Definition.Icon&&g.Id is not "cs2"));
  var relay=Assert.Single(vm.Routes,o=>o.Mode=="MANUAL");Assert.Equal("VPS-PRIMARY",relay.RelayId);
  var g=vm.Games.Single(g=>g.Id=="cs2");vm.Select(g);Assert.True(g.IsSelected);Assert.True(vm.Routes.Single(o=>o.Key=="DIRECT").IsSelected);
  vm.ChooseRoute(relay);Assert.True(relay.IsSelected);Assert.True(g.IsCustom);await vm.ApplyAsync(g);
  var p=Assert.IsType<Profile>(Assert.Single(s.Calls,c=>c.method=="profile.set").payload);Assert.Equal("MANUAL",p.Mode);Assert.Equal("VPS-PRIMARY",p.RelayId);
 }
 [Fact]public async Task RouteStripClosesOnApplySecondClickAndDropsUnsavedChoice(){
  var s=new Service();var vm=new GameCatalogViewModel(s);await vm.RefreshAsync();var g=vm.Games.Single(g=>g.Id=="cs2");
  vm.Select(g);vm.ChooseRoute(vm.Routes.Single(o=>o.Key=="AUTO"));vm.Select(g);Assert.False(vm.HasSelection);Assert.False(g.IsSelected);Assert.Equal("DIRECT",g.Mode);
  vm.Select(g);vm.ChooseRoute(vm.Routes.Single(o=>o.Key=="AUTO"));vm.Close();Assert.False(vm.HasSelection);Assert.Equal("DIRECT",g.Mode);
  vm.Select(g);vm.ChooseRoute(vm.Routes.Single(o=>o.Key=="AUTO"));await vm.ApplyAsync(g);Assert.False(vm.HasSelection);Assert.Equal("AUTO",g.Mode);Assert.DoesNotContain("DIRECT",vm.Notice);
 }
}
