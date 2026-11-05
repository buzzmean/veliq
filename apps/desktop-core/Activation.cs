namespace Neexitlag.Desktop;
public sealed class ActivationHardwareView {
 public string Uuid {get;set;}=""; public string BoardSerial {get;set;}=""; public string Mac {get;set;}="";
 public string Scheme {get;set;}=""; public string Reason {get;set;}="";
 public string Failure=>Reason switch {
  "HARDWARE_MAC_UNAVAILABLE"=>"недоступен MAC физического адаптера",
  "HARDWARE_UUID_AND_BOARD_UNAVAILABLE"=>"недоступны надёжные UUID и серийный номер платы",
  "HARDWARE_METADATA_QUERY_FAILED"=>"не удалось получить аппаратные сведения Windows",
  "HARDWARE_SALT_INVALID"=>"неверные параметры идентификации сервера",
  _=>"недостаточно надёжных аппаратных компонентов"
 };
}
public sealed class ActivationView {
 public ActivationHardwareView Hardware {get;set;}=new(); public bool CapturePermitted {get;set;}=true;

 public string State {get;set;}="";public string Error {get;set;}="";public bool HasIdentity {get;set;}
 public string CaNotAfter {get;set;}="";public string ServerNotAfter {get;set;}="";
 public string Message=>Error switch {
  "ACTIVATION_INVALID"=>"Неверный код активации. Проверьте код и попробуйте ещё раз.",
  "ACTIVATION_REVOKED"=>"Код отозван администратором. Запросите новый код.",
  "ACTIVATION_EXPIRED"=>"Срок действия кода истёк. Запросите новый код.",
  "DEVICE_REVOKED"=>"Доступ этого компьютера отозван. Обратитесь к администратору.",
  "ACTIVATION_LIMIT"=>"Достигнут лимит компьютеров. Для изменения состава клуба обратитесь в поддержку.",
  "CLUB_ENROLLMENT_CLOSED"=>"Компьютеры клуба уже закреплены. Для добавления или замены ПК обратитесь в поддержку.",
  "MACHINE_DISABLED"=>"Этот компьютер отключён. Обратитесь к администратору.",
  "ACTIVATION_RATE_LIMIT"=>"Слишком много попыток. Подождите немного и повторите.",
  "ACTIVATION_TRUST_NOT_CONFIGURED"=>"Установка не готова к активации. Обновите VELIQ.",
  "HARDWARE_ID_UNAVAILABLE"=>"Не удалось определить компьютер: "+Hardware.Failure+". Сеть и код активации могут быть исправны.",
  "ACTIVATION_STORAGE_FAILED"=>"Не удалось сохранить активацию. Обратитесь к администратору компьютера.",
  "ACTIVATION_IDENTITY_CONFLICT"=>"Данные установки изменились. Администратор должен проверить регистрацию компьютера.",
  ""=>State=="ACTIVATED"?"Код активации: активирован":State=="ACTIVATING"?"Активируем VELIQ…":"Введите код активации",
  _=>"Нет связи с VELIQ. Проверьте подключение и повторите."
 };
 public string CertificateStatus=>"Срок доверия: "+Date(CaNotAfter)+" · Сертификат подключения: "+Date(ServerNotAfter);
 static string Date(string s)=>DateTimeOffset.TryParse(s,out var d)?d.ToLocalTime().ToString("dd.MM.yyyy")+(d<DateTimeOffset.UtcNow.AddDays(10)?" — требуется продление":""):"нет данных";
}
public sealed class ActivationModel(IServiceClient client){
 public ActivationView Status {get;private set;}=new();
 public async Task RefreshAsync(CancellationToken ct=default){try{Status=await client.Call<ActivationView>("activation.status",cancellationToken:ct);}catch(Exception)when(!ct.IsCancellationRequested){Status=new(){State="UNAVAILABLE",Error="ACTIVATION_UNAVAILABLE"};}}
 public async Task ActivateAsync(string code,CancellationToken ct=default){try{Status=await client.Call<ActivationView>("activation.set",new{code},ct);}catch(Exception e)when(!ct.IsCancellationRequested){Status=new(){State="ACTIVATION_ERROR",Error=KnownError(e.Message)};}}
 static string KnownError(string s){string[] codes=["DEVICE_REVOKED","ACTIVATION_STORAGE_FAILED","ACTIVATION_IDENTITY_CONFLICT","ACTIVATION_INVALID","ACTIVATION_REVOKED","ACTIVATION_EXPIRED","ACTIVATION_LIMIT","CLUB_ENROLLMENT_CLOSED","MACHINE_DISABLED","ACTIVATION_RATE_LIMIT","ACTIVATION_TRUST_NOT_CONFIGURED","HARDWARE_ID_UNAVAILABLE"];return codes.FirstOrDefault(c=>s==c||s.EndsWith(": "+c,StringComparison.Ordinal))??"ACTIVATION_UNAVAILABLE";}
}
public sealed partial class DesktopViewModel {
 public ActivationModel? Activation {get;private set;}
 public ActivationModel ActivationClient()=>Activation??=new(client);
}
