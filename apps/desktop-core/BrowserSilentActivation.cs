using System.Text.Json;
namespace Veliq.Desktop;
public sealed class BrowserSilentActivation {
 public string[] ConfiguredProfiles {get;set;}=[];
 public string State {get;set;}="NOT_CONFIGURED";
 public string Reason {get;set;}="";
 public long ApplyToRequestMs {get;set;}=-1;
 public int ObservedRequests {get;set;}
 public const string PendingNotice="PAC настроен без закрытия браузера. Ожидается подхват policy; если браузер не перечитает её, маршрут применится при следующем запуске браузера. Старые TCP закреплены до закрытия.";
 public string Notice=>State=="POLICY_SUSPENDED"?"PAC снят: "+Reason+". Браузер использует прямую сеть; подключение ещё не готово.":State=="PAC_REQUEST_OBSERVED"?"PAC: запрос браузера подтверждён; применение → запрос "+ApplyToRequestMs+" мс. Это не проверка доступности сайта.":State=="POLICY_OR_LISTENER_UNAVAILABLE"?"PAC: policy или listener недоступен. При отказе прокси разрешён DIRECT.":State=="POLICY_PENDING_BROWSER_REFRESH"?PendingNotice:"Тихая PAC ещё не настроена; рабочий маршрут браузера не подтверждён.";
}
public sealed partial class DesktopViewModel {
 public Task<JsonElement> GuardSilentChromeAsync(Profile p,CancellationToken ct=default)=>client.Call<JsonElement>("browser.silent.guard",new{profile_id=p.Id},ct);
 public async Task ApplySilentBrowserAsync(Profile original,bool edge,CancellationToken ct=default){
  var ticket=CaptureBrowserPreparation();
  var copy=original.Copy();copy.Mode="AUTO";copy.PolicyData??=new();
  if(edge)copy.PolicyData["app_preset"]=JsonSerializer.SerializeToElement("edge-sites");
  await client.Call<Profile[]>("profile.set",copy,ct);
  try{CheckBrowserPreparation(ticket);await client.Call<JsonElement>(edge?"edge.silent.apply":"browser.silent.apply",new{profile_id=original.Id},ct);}
  catch(Exception error){
   try{CheckBrowserPreparation(ticket);}catch(BrowserPreparationDeferredException){RecordGuiFailure(error,edge?"edge.silent.apply":"browser.silent.apply");throw;} // Preserve original diagnostic, never undo later user state.
   try{await client.Call<Profile[]>("profile.set",original.Copy(),ct);}catch{throw new ServiceException(ServiceFailure.Rejected,"BROWSER_PROFILE_ROLLBACK_FAILED");}
   throw;
  }
  startupChromeProfiles.Remove(copy.Id);
  ClearBrowserLaneIssue(edge ? "Edge" : "Chrome", edge ? "edge.silent.apply" : "browser.silent.apply");
  ClearBrowserPreparationIssue();
  await RefreshAsync(ct);
 }
}
