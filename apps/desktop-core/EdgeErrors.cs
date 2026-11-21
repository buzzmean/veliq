namespace Neexitlag.Desktop;

public sealed class EdgeActivationException(string phase,string code,string explanation) : Exception($"{phase}: {code}. {explanation}") {
 public string Phase {get;}=phase; public string Code {get;}=code;
}
public static class EdgeErrors {
 static readonly Dictionary<string,string> Messages=new(){
  ["EDGE_IPC_ACCESS_DENIED"]="Named pipe отказал в доступе. Запустите GUI под SID владельца установки без повышения прав.",
  ["EDGE_GUARD_STATE_WRITE_FAILED"]="Служба не смогла опубликовать защищённый recovery guard. Проверьте ACL/доступность каталога состояния службы.",
  ["EDGE_IPC_UNSUPPORTED"]="Установленная служба не поддерживает Edge IPC; обновите службу и проверьте SHA256.",
  ["EDGE_POLICY_ACCESS_DENIED"]="Служба не смогла записать политику Edge в реестр владельца.",
  ["EDGE_POLICY_MANAGED"]="В Edge уже установлена чужая политика прокси. Она не изменена.",
  ["EDGE_OWNER_SID_REQUIRED"]="Не подтверждён SID владельца установки.",
  ["EDGE_PROFILE_MODE_INVALID"]="Для подготовки Edge нужен DIRECT или AUTO. AUTO включается после проверки PAC.",
  ["EDGE_PROFILE_NOT_FOUND"]="Не найден выбранный профиль msedge.exe.",
  ["EDGE_AUTOMATIC_DISABLED"]="В настройках отключена автоматическая маршрутизация.",
  ["EDGE_READINESS_NOT_OBSERVED"]="Edge не подтвердил PAC/CONNECT, владельца или проверочный nonce.",
  ["EDGE_READINESS_EXPIRED"]="Проверка готовности Edge истекла; повторите активацию.",
  ["EDGE_PREPARE_REQUIRED"]="Не завершена подготовка Edge CONNECT/recovery.",
  ["EDGE_OTHER_PROFILE_ACTIVE"]="Уже активирован другой Edge-профиль.",
  ["EDGE_CONFIGURATION_INVALID"]="Некорректное локальное состояние Edge.",
  ["EDGE_LISTENER_BIND_FAILED"]="Не удалось занять локальный порт Edge CONNECT.",
  ["EDGE_TIMEOUT"]="Истёк срок ожидания активации Edge.",
  ["EDGE_RECOVERY_FAILED"]="Не удалось запустить или настроить owner-scoped recovery-процесс Edge.",
  ["EDGE_BROWSER_POLICY_NOT_OBSERVED"]="Проверочный Edge не подтвердил реальную Microsoft Edge PAC-политику.",
  ["EDGE_LAUNCH_FAILED"]="Не удалось завершить подготовку Edge.",
  ["EDGE_SERVICE_UNAVAILABLE"]="Edge IPC недоступен; проверьте службу и владельца установки.",
  ["EDGE_OPERATION_FAILED"]="Не удалось завершить подготовку Edge. Повторная проверка выполняется автоматически."
 };
 public static EdgeActivationException Wrap(string phase,Exception error){
  if(error is EdgeActivationException own)return own;
  var code=Messages.Keys.FirstOrDefault(c=>error.Message.Contains(c,StringComparison.Ordinal));
  if(code is null&&error is ServiceException s){
   code=s.Message.Contains("unsupported IPC",StringComparison.OrdinalIgnoreCase)?"EDGE_IPC_UNSUPPORTED":s.Failure==ServiceFailure.AccessDenied?"EDGE_IPC_ACCESS_DENIED":s.Failure!=ServiceFailure.Rejected?"EDGE_SERVICE_UNAVAILABLE":"EDGE_OPERATION_FAILED";
  }
  code ??= phase switch{"edge.recovery"=>"EDGE_RECOVERY_FAILED","edge.browser_probe"=>"EDGE_BROWSER_POLICY_NOT_OBSERVED","edge.launch"=>"EDGE_LAUNCH_FAILED",_=>"EDGE_OPERATION_FAILED"};
  return new(phase,code,Messages[code]);
 }
}
public sealed partial class DesktopViewModel {
 async Task<T> EdgeCall<T>(string method,object payload,CancellationToken ct){try{return await client.Call<T>(method,payload,ct);}catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}catch(Exception error){throw EdgeErrors.Wrap(method,error);}}
 public async Task RecordEdgeFailureAsync(Profile profile,EdgeActivationException failure,CancellationToken ct=default){
  try{await client.Call<System.Text.Json.JsonElement>("edge.failure",new{profile_id=profile.Id,phase=failure.Phase,code=failure.Code},ct);}catch(Exception){} // Never replace the original error, including with older services.
 }
}
public static class EdgeProfileSelection {
 public static Profile? Select(Profile? selected,IEnumerable<Profile> profiles){
  if(selected is not null&&BrowserCatalog.IsEdge(selected))return selected.Copy();
  var edge=profiles.Where(BrowserCatalog.IsEdge).Take(2).ToArray();
  if(edge.Length>1)throw new EdgeActivationException("edge.prepare","EDGE_PROFILE_NOT_FOUND","Найдено несколько профилей Edge. Выберите нужную строку; другие приложения не изменены.");
  return edge.SingleOrDefault()?.Copy();
 }
}
