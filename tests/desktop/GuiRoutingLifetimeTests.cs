using Veliq.Desktop;
using Xunit;
public class GuiRoutingLifetimeTests {
 [Fact] public async Task ClosingStopsRoutingBeforeCompleting() {
  var stopped=false; await GuiRoutingLifetime.StopAsync(()=>{stopped=true;return Task.CompletedTask;}); Assert.True(stopped);
 }
 [Fact] public async Task FailureIsNotReportedAsClosed(){await Assert.ThrowsAsync<InvalidOperationException>(()=>GuiRoutingLifetime.StopAsync(()=>throw new InvalidOperationException()));}
 [Theory] [InlineData(ServiceFailure.Stopped)] [InlineData(ServiceFailure.NotInstalled)]
 public async Task KnownAbsentServiceDoesNotBlockClose(ServiceFailure failure){await GuiRoutingLifetime.StopAsync(()=>throw new ServiceException(failure));}
 [Theory] [InlineData(ServiceFailure.Unavailable)] [InlineData(ServiceFailure.AccessDenied)] [InlineData(ServiceFailure.Rejected)] [InlineData(ServiceFailure.Incompatible)]
 public async Task UnconfirmedShutdownKeepsGuiOpen(ServiceFailure failure){await Assert.ThrowsAsync<ServiceException>(()=>GuiRoutingLifetime.StopAsync(()=>throw new ServiceException(failure)));}
 sealed class Client(bool stillOptimizing=false, bool fail=false) : IServiceClient {
  public int Calls;
  public Task<T> Call<T>(string method, object? payload=null, CancellationToken cancellationToken=default) {
   Calls++; Assert.Equal("optimize",method);
   Assert.Contains("\"enabled\":false",System.Text.Json.JsonSerializer.Serialize(payload));
   if(fail)throw new ServiceException(ServiceFailure.Rejected);
   return Task.FromResult((T)(object)new Snapshot { Optimizing=stillOptimizing });
  }
 }
 [Fact] public async Task InitialUnavailableModelStillSendsShutdownAndAppliesConfirmedState() {
  var service=new Client();var model=new DesktopViewModel(service);
  Assert.False(model.Available);
  await GuiRoutingLifetime.StopAsync(()=>model.DisableRoutingForExitAsync());
  Assert.Equal(1,service.Calls);Assert.False(model.Optimizing);
 }
 [Fact] public async Task CancellationIsNotReportedAsConfirmedShutdown() {
  var service=new Client();var model=new DesktopViewModel(service);using var stop=new CancellationTokenSource();stop.Cancel();
  await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>GuiRoutingLifetime.StopAsync(()=>model.DisableRoutingForExitAsync(stop.Token)));
  Assert.Equal(0,service.Calls);
 }
 [Theory] [InlineData(true,false)] [InlineData(false,true)]
 public async Task RealViewModelDoesNotSwallowFailedShutdown(bool stillOptimizing,bool rejected) {
  var service=new Client(stillOptimizing,rejected);var model=new DesktopViewModel(service);
  await Assert.ThrowsAsync<ServiceException>(()=>GuiRoutingLifetime.StopAsync(()=>model.DisableRoutingForExitAsync()));
  Assert.Equal(1,service.Calls);
 }
}
