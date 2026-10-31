namespace Neexitlag.Desktop;
public sealed class SubscriptionView {
 public const string AccountUrl="https://veliq.app/account.html";
 public string State {get;set;}="UNKNOWN"; public DateTimeOffset? PaidUntil {get;set;} public DateTimeOffset? GraceUntil {get;set;}
 public bool Expired=>State=="EXPIRED";
 public bool Known=>State is "ACTIVE" or "EXPIRED";
 /// Строка в Настройках: только дата или «закончилась», без технических подробностей.
 public string Summary=>State switch {
  "EXPIRED"=>"Подписка закончилась",
  "ACTIVE" when PaidUntil is {} d=>"Подписка до "+d.ToLocalTime().ToString("dd.MM.yyyy"),
  _=>""
 };
 public string Hint=>State switch {
  "EXPIRED"=>"Интернет работает как без VELIQ. Продлите подписку — VELIQ включится сам.",
  "ACTIVE" when PaidUntil is {} d && d<DateTimeOffset.UtcNow.AddDays(3)=>"Подписка скоро закончится. Продлить можно в личном кабинете.",
  _=>""
 };
}
public sealed class SubscriptionModel(IServiceClient client){
 public SubscriptionView Status {get;private set;}=new();
 // Старая служба без подписок отвечает ошибкой: показываем «неизвестно», ничего не блокируем.
 public async Task RefreshAsync(bool recheck=false,CancellationToken ct=default){try{Status=await client.Call<SubscriptionView>(recheck?"subscription.refresh":"subscription.status",cancellationToken:ct);}catch(Exception)when(!ct.IsCancellationRequested){Status=new();}}
}
public sealed partial class DesktopViewModel {
 public SubscriptionModel? Subscription {get;private set;}
 public SubscriptionModel SubscriptionClient()=>Subscription??=new(client);
}
