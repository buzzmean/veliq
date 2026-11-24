using Veliq.Desktop;
using Xunit;
namespace Veliq.Tests;
public sealed class HealthSummaryTests {
 sealed class Down:IServiceClient{public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default)=>Task.FromException<T>(new ServiceException(ServiceFailure.NotInstalled));}
 [Fact]public async Task MissingServiceIsOneProblemWithAdvice(){
  var vm=new DesktopViewModel(new Down());await vm.RefreshAsync();
  var row=Assert.Single(vm.Health);Assert.Equal(HealthLevel.Problem,row.Level);Assert.Equal("Есть проблема",vm.HealthTitle);Assert.Contains("Перезапустите",vm.HealthAdvice);
 }
 [Fact]public void WorkingServiceReadsPlainAndReportKeepsTechnicalDetails(){
  var vm=new DesktopViewModel(new Down());
  var s=new Snapshot{Optimizing=true,Routes=[new(){Id="VPS-PRIMARY",Status="healthy",ObservedAt=DateTimeOffset.UtcNow}]};s.Backend.Ready=true;
  vm.Apply(s);
  Assert.Equal(["Служба VELIQ","Работа на этом ПК","Серверы VELIQ","Браузеры"],vm.Health.Select(r=>r.Name));
  Assert.DoesNotContain(vm.Health,r=>r.Level is HealthLevel.Problem or HealthLevel.Warning);Assert.Equal("Всё работает",vm.HealthTitle);Assert.Equal("",vm.HealthAdvice);
  Assert.All(vm.Health,r=>Assert.DoesNotMatch("UDP|TCP|DIRECT|AUTO|relay|probe",r.State));
  var report=vm.SupportReport("0.3.1");Assert.Contains("VELIQ 0.3.1",report);Assert.Contains("Маршруты:",report);Assert.Contains("VPS-PRIMARY",report);
 }
 [Fact]public void LostServersAreAWarningNotAProblem(){
  var vm=new DesktopViewModel(new Down());var s=new Snapshot{Optimizing=true,Routes=[new(){Id="VPS-PRIMARY",Status="unavailable"}]};s.Backend.Ready=true;vm.Apply(s);
  Assert.Equal(HealthLevel.Warning,vm.HealthLevel);Assert.Equal("Работает, но не всё",vm.HealthTitle);Assert.Contains("пару минут",vm.HealthAdvice);
 }
}
