using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class SubscriptionTests {
 sealed class Service(string json,bool fail=false):IServiceClient {public string? Method;public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){Method=method;if(fail)throw new ServiceException(ServiceFailure.Rejected,"unknown method");return Task.FromResult(System.Text.Json.JsonSerializer.Deserialize<T>(json,WireJson.Options)!);}}
 [Fact]public async Task ActiveShowsOnlyDate(){var s=new Service("""{"state":"ACTIVE","paid_until":"2030-11-26T10:00:00Z"}""");var m=new SubscriptionModel(s);await m.RefreshAsync();Assert.Equal("subscription.status",s.Method);Assert.StartsWith("Подписка до ",m.Status.Summary);Assert.Contains("2030",m.Status.Summary);Assert.False(m.Status.Expired);Assert.Equal("",m.Status.Hint);}
 [Fact]public async Task ExpiredIsPlainAndRecheckAsksService(){var s=new Service("""{"state":"EXPIRED","paid_until":"2020-01-01T00:00:00Z"}""");var m=new SubscriptionModel(s);await m.RefreshAsync(true);Assert.Equal("subscription.refresh",s.Method);Assert.True(m.Status.Expired);Assert.Equal("Подписка закончилась",m.Status.Summary);Assert.Contains("Интернет работает",m.Status.Hint);}
 [Fact]public async Task OldServiceOrUnmanagedShowsNothingAndBlocksNothing(){var m=new SubscriptionModel(new Service("{}",fail:true));await m.RefreshAsync();Assert.False(m.Status.Known);Assert.False(m.Status.Expired);Assert.Equal("",m.Status.Summary);
  m=new SubscriptionModel(new Service("""{"state":"UNMANAGED"}"""));await m.RefreshAsync();Assert.False(m.Status.Known);Assert.Equal("",m.Status.Summary);}
 [Fact]public void SoonEndingHintsRenewal(){var v=new SubscriptionView{State="ACTIVE",PaidUntil=DateTimeOffset.UtcNow.AddDays(1)};Assert.Contains("скоро закончится",v.Hint);}
 [Fact]
 public async Task ActiveWithoutPeriodShowsAccessWithoutRenewal()
 {
  var model = new SubscriptionModel(new Service("""{"state":"ACTIVE"}"""));
  await model.RefreshAsync();
  Assert.True(model.Status.Known);
  Assert.Equal("Доступ активен", model.Status.Summary);
  Assert.False(model.Status.CanRenew);
 }
 [Fact]
 public void DatedAndEndedSubscriptionsCanBeRenewed()
 {
  Assert.True(new SubscriptionView { State = "ACTIVE", PaidUntil = DateTimeOffset.UtcNow.AddDays(7) }.CanRenew);
  Assert.True(new SubscriptionView { State = "EXPIRED" }.CanRenew);
  Assert.False(new SubscriptionView { State = "UNMANAGED" }.CanRenew);
  Assert.False(new SubscriptionView { State = "UNKNOWN" }.CanRenew);
 }
 [Fact]public void TextsExist(){foreach(var k in new[]{"RenewSubscription","SubscriptionEnded","SubscriptionEndedLead","SubscriptionRecheck"})Assert.False(string.IsNullOrEmpty(Text.Get(k)));}
}
