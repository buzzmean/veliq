using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class AccountConnectionTests {
 sealed class Service:IServiceClient {
  public List<string> Methods=new();
  public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){Methods.Add(method);return Task.FromResult(System.Text.Json.JsonSerializer.Deserialize<T>(method=="account.link.start"?"""{"state":"STARTING"}""":"""{"state":"LINKED","kind":"club","name":"Test Club"}""",WireJson.Options)!);}
 }
 [Fact]public async Task RegistrationUsesAccountIPCAndNeverActivationCode(){var service=new Service();var model=new AccountConnectionModel(service);await model.StartAsync();Assert.Equal("STARTING",model.Status.State);await model.RefreshAsync();Assert.True(model.Status.Linked);Assert.Equal("Клуб · Test Club",model.Status.Summary);Assert.Equal(new[]{"account.link.start","account.status"},service.Methods);}
 [Theory][InlineData("http://example.test/account.html#device=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")][InlineData("https://user:pass@example.test/account.html#device=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")][InlineData("https://example.test/other#device=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")][InlineData("javascript:alert(1)")][InlineData("https://example.test/account.html?redirect=evil#device=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
 public void BrowserLaunchRejectsUntrustedURLShapes(string url){Assert.Null(new AccountConnectionView{VerificationUrl=url}.VerificationUri);}
 [Fact]public void LaunchesOnlyHTTPSAccountPageWithPublicRequestID(){var s=new AccountConnectionView{VerificationUrl="https://example.test/account.html#device=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",CabinetUrl="https://example.test/account.html"};Assert.NotNull(s.VerificationUri);Assert.NotNull(s.CabinetUri);}
 [Fact]public void ReadyImageDoesNotTellOwnerToEnrollTheTemplate(){var s=new AccountConnectionView{State="IMAGE_READY",Kind="club",ImagePreparation=true};Assert.True(s.ImageReady);Assert.Contains("Выключите",s.Message);Assert.Contains("автоматически",s.Message);}
 [Fact]public void PlayerAndClubLabelsAreDistinct(){Assert.Equal("Пользователь",new AccountConnectionView{Kind="player"}.KindLabel);Assert.Equal("Клуб",new AccountConnectionView{Kind="club"}.KindLabel);}
}
