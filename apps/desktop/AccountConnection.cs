using System.Windows;
namespace Neexitlag.Desktop;
public partial class MainWindow {
 bool openingAccount;
 async Task RefreshAccountConnectionAsync(){
  var account=model.AccountConnectionClient();await account.RefreshAsync(lifetime.Token);
  var s=account.Status;
  AccountSummary.Text=s.Summary;AccountHint.Text=s.Message;AccountOnboardingHint.Text=s.Message;
  AccountTitle.Text=s.ImagePreparation?"Подключить клубный образ":"Войти в VELIQ";
  AccountLead.Text=s.ImagePreparation?"Войдите как владелец клуба. Гостям не потребуется вход после перезагрузки.":"Войдите или зарегистрируйтесь в браузере. Копировать код активации не нужно.";
  AccountConnect.IsEnabled=!openingAccount&&!s.ImageReady;
  AccountConnect.Content=s.State=="WAITING_FOR_BROWSER"?"Открыть страницу входа":"Войти или зарегистрироваться";
  if(s.ImageReady){ActivationPanel.Visibility=Visibility.Visible;LegacyActivation.Visibility=Visibility.Collapsed;}
 }
 static void OpenAccountUri(Uri uri)=>System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(uri.AbsoluteUri){UseShellExecute=true});
 async void ConnectAccount(object sender,RoutedEventArgs e)=>await Execute(StartAccountConnectionAsync);
 async Task StartAccountConnectionAsync(){
  if(openingAccount)return;openingAccount=true;AccountConnect.IsEnabled=false;
  try{
   var account=model.AccountConnectionClient();await account.StartAsync(lifetime.Token);
   var deadline=DateTime.UtcNow.AddSeconds(20);
   while(account.Status.State=="STARTING"&&DateTime.UtcNow<deadline){await Task.Delay(500,lifetime.Token);await account.RefreshAsync(lifetime.Token);}
   if(account.Status.VerificationUri is {} uri)OpenAccountUri(uri);
   await RefreshAccountConnectionAsync();
  }finally{openingAccount=false;AccountConnect.IsEnabled=!model.AccountConnectionClient().Status.ImageReady;}
 }
 async void OpenAccountCabinet(object sender,RoutedEventArgs e)=>await Execute(async()=>{
  var account=model.AccountConnectionClient();await account.RefreshAsync(lifetime.Token);
  if(account.Status.CabinetUri is {} uri)OpenAccountUri(uri);else await StartAccountConnectionAsync();
 });
}
