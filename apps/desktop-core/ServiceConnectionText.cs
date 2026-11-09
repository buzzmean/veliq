namespace Neexitlag.Desktop;
public static class ServiceConnectionText {
 public static string Describe(Snapshot s) {
  if(s.Connected && s.Optimizing && s.ConnectionReason is "" or "READY"){var p=s.BrowserPolicy;if((p.ChromeConfigured&&!p.ChromeReady)||(p.EdgeConfigured&&!p.EdgeReady))return "Подготавливаем браузер…";return Text.Get("Connected");}
  return s.ConnectionReason switch {
   "ACTIVATION_REQUIRED"=>"Требуется активация",
   "CAPTURE_START_FAILED"=>"Не удалось запустить WinDivert",
   "CAPTURE_NOT_READY"=>"Захват трафика ещё не готов",
   "RELAY_NOT_CONNECTED"=>"Нет готового соединения с релеем",
   _=>s.Optimizing?"Подключение ещё не готово":"Оптимизация выключена"
  };
 }
}
