namespace Neexitlag.Desktop;

public sealed class AccountConnectionView {
 public string State {get;set;}="NOT_LINKED";
 public string Error {get;set;}="";
 public string Kind {get;set;}="";
 public string Name {get;set;}="";
 public string Email {get;set;}="";
 public string CabinetUrl {get;set;}="";
 public string VerificationUrl {get;set;}="";
 public bool ImagePreparation {get;set;}
 public bool Linked=>State=="LINKED";
 public bool ImageReady=>State=="IMAGE_READY";
 public string KindLabel=>Kind=="club"?"Клуб":Kind=="player"?"Пользователь":"Аккаунт не подключён";
 public string Summary=>Kind.Length==0?KindLabel:KindLabel+(Name.Length>0?" · "+Name:Email.Length>0?" · "+Email:"");
 public string Message=>Error switch {
  "ACCOUNT_NOT_CONFIGURED"=>"Сервис входа ещё не подключён. Повторите после его настройки.",
  "ACCOUNT_LINK_EXPIRED"=>"Ссылка для входа устарела. Начните подключение снова.",
  "ACCOUNT_DEVICE_ALREADY_OWNED"=>"Компьютер подключён к другому аккаунту. Сначала освободите его в прежнем личном кабинете.",
  "ACCOUNT_SUBSCRIPTION_REQUIRED"=>"Выберите свою подписку в личном кабинете. Для образа нужна клубная подписка.",
  "CLUB_ENROLLMENT_CLOSED"=>"Компьютеры клуба закреплены. Для добавления или замены ПК обратитесь в поддержку.",
  "ACTIVATION_LIMIT"=>"Достигнут лимит компьютеров клуба. Обратитесь в поддержку.",
  "SUBSCRIPTION_EXPIRED"=>"Продлите подписку в личном кабинете и повторите подключение.",
  "ACCOUNT_IMAGE_LIMIT"=>"Достигнут лимит клубных образов. Отзовите ненужное разрешение в личном кабинете.",
  "ACCOUNT_IMAGE_NOT_CLEAN"=>"Образ уже содержит активацию. Подготовьте отдельный чистый образ.",
  ""=>State switch {
   "LINKED"=>"Этот компьютер подключён к аккаунту VELIQ.",
   "IMAGE_READY"=>"Клубный образ подключён. Выключите компьютер и сохраните образ. При первом запуске на каждом ПК VELIQ подключится автоматически.",
   "STARTING"=>"Готовим подключение…",
   "WAITING_FOR_BROWSER"=>ImagePreparation?"Войдите в браузере как владелец клуба и подтвердите подготовку образа.":"Введите почту и код из письма в приложении, затем подтвердите компьютер.",
   "EXPIRED"=>"Ссылка устарела. Нажмите кнопку входа ещё раз.",
   "UNAVAILABLE"=>"Нет связи со службой VELIQ. Проверьте установку.",
   _=>"Войдите или зарегистрируйтесь. Компьютер подключится после подтверждения в личном кабинете."
  },
  _=>"Не удалось подключить аккаунт. Проверьте интернет и повторите."
 };
 public Uri? CabinetUri=>SafeUri(CabinetUrl,false);
 public Uri? VerificationUri=>SafeUri(VerificationUrl,true);
 static Uri? SafeUri(string raw,bool verification){
  if(!Uri.TryCreate(raw,UriKind.Absolute,out var uri)||uri.Scheme!="https"||uri.UserInfo.Length>0||uri.Query.Length>0||uri.AbsolutePath!="/account.html")return null;
  if(verification&&!System.Text.RegularExpressions.Regex.IsMatch(uri.Fragment,"^#device=[a-f0-9]{32}$"))return null;
  if(!verification&&uri.Fragment.Length>0)return null;return uri;
 }
}
public sealed class AccountConnectionModel(IServiceClient client){
 public AccountConnectionView Status {get;private set;}=new();
 public async Task RefreshAsync(CancellationToken ct=default){
  try{Status=await client.Call<AccountConnectionView>("account.status",cancellationToken:ct);}
  catch(Exception)when(!ct.IsCancellationRequested){Status=new(){State="UNAVAILABLE"};}
 }
 public async Task StartAsync(CancellationToken ct=default){
  try{Status=await client.Call<AccountConnectionView>("account.link.start",cancellationToken:ct);}
  catch(Exception)when(!ct.IsCancellationRequested){Status=new(){State="ERROR",Error="ACCOUNT_LINK_UNAVAILABLE"};}
 }
}
public sealed partial class DesktopViewModel {
 public AccountConnectionModel? AccountConnection {get;private set;}
 public AccountConnectionModel AccountConnectionClient()=>AccountConnection??=new(client);
}
