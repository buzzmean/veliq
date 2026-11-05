using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class ActivationTests {
 [Theory][InlineData("ACTIVATION_INVALID","Неверный код")][InlineData("ACTIVATION_REVOKED","Код отозван")][InlineData("ACTIVATION_LIMIT","Достигнут лимит")][InlineData("ACTIVATION_UNAVAILABLE","Нет связи")]
 public void ErrorsAreHumanAndNeverReflectRawInput(string code,string expected){var state=new ActivationView{Error=code};Assert.Contains(expected,state.Message);Assert.DoesNotContain("серверов",state.Message);}
 sealed class Service:IServiceClient {public bool Fail;public string? Method;public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default){Method=method;if(Fail)throw new ServiceException(ServiceFailure.Rejected,"private-secret-code");return Task.FromResult((T)(object)new ActivationView{State=method=="activation.set"?"ACTIVATING":"CODE_REQUIRED"});}}
 [Fact]public async Task EntryIsOneRequestAndSecretIsNotRetainedInStatus(){var service=new Service();var model=new ActivationModel(service);await model.ActivateAsync("DO_NOT_LOG");Assert.Equal("activation.set",service.Method);Assert.Equal("ACTIVATING",model.Status.State);Assert.DoesNotContain("DO_NOT_LOG",model.Status.Message);service.Fail=true;await model.ActivateAsync("DO_NOT_LOG");Assert.DoesNotContain("private-secret-code",model.Status.Message);Assert.Contains("Нет связи",model.Status.Message);}
 [Fact]public void CertificateExpiryShowsActualDatesOrUnknown(){var state=new ActivationView();Assert.Contains("нет данных",state.CertificateStatus);state.CaNotAfter=DateTimeOffset.UtcNow.AddDays(1).ToString("O");Assert.Contains("требуется продление",state.CertificateStatus);}
}
public sealed class ActivationHardwareTests {
 [Fact]public void HardwareFailureIsExplicitAndDoesNotSuggestNetworkFailure(){
  var state=System.Text.Json.JsonSerializer.Deserialize<ActivationView>("""{"state":"ACTIVATION_ERROR","error":"HARDWARE_ID_UNAVAILABLE","hardware":{"uuid":"ACCEPTED","board_serial":"PLACEHOLDER","mac":"ACCEPTED","reason":"HARDWARE_UUID_AND_BOARD_UNAVAILABLE"},"capture_permitted":false}""",WireJson.Options)!;
  Assert.Contains("Не удалось определить компьютер",state.Message);Assert.Contains("UUID",state.Message);Assert.DoesNotContain("Нет связи",state.Message);Assert.False(state.CapturePermitted);Assert.Equal("PLACEHOLDER",state.Hardware.BoardSerial);
  state.Hardware.Reason="private-secret";Assert.DoesNotContain("private-secret",state.Message);
 }
 [Fact]public void OlderActivationStatusWithoutPermissionFieldRemainsCompatible(){
  var state=System.Text.Json.JsonSerializer.Deserialize<ActivationView>("""{"state":"ACTIVATED","has_identity":true}""",WireJson.Options)!;Assert.True(state.CapturePermitted);
 }
}

public class ActivationReasonTests {
 [Theory][InlineData("ACTIVATION_REVOKED","Код отозван")][InlineData("DEVICE_REVOKED","компьютера отозван")][InlineData("ACTIVATION_EXPIRED","истёк")][InlineData("ACTIVATION_LIMIT","лимит компьютеров")][InlineData("CLUB_ENROLLMENT_CLOSED","закреплены")][InlineData("ACTIVATION_UNAVAILABLE","Нет связи")][InlineData("ACTIVATION_INVALID","Неверный код")]
 public void DistinctSafeMessages(string code,string expected){var message=new ActivationView{Error=code}.Message;Assert.Contains(expected,message);Assert.DoesNotContain(code,message);Assert.DoesNotContain("private-secret",message);}
}
