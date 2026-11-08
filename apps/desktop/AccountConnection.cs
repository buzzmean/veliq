using System.Windows;
namespace Neexitlag.Desktop;
public partial class MainWindow {
 bool openingAccount;
 async Task RefreshAccountConnectionAsync(){
  var account=model.AccountConnectionClient();await account.RefreshAsync(lifetime.Token);
  var s=account.Status;
  AccountSummary.Text=s.Summary;AccountHint.Text=s.Message;AccountOnboardingHint.Text=s.Message;
  AccountTitle.Text=s.ImagePreparation?"Подключить клубный образ":"Войти в VELIQ";
  AccountLead.Text=s.ImagePreparation?"Войдите как владелец клуба. Гостям не потребуется вход после перезагрузки.":"Введите почту и код из письма в приложении.";
  AccountConnect.IsEnabled=!openingAccount&&!s.ImageReady;
  AccountConnect.Content="Войти или зарегистрироваться";
  if(s.ImageReady){ActivationPanel.Visibility=Visibility.Visible;LegacyActivation.Visibility=Visibility.Collapsed;}
 }
 static void OpenAccountUri(Uri uri)=>System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(uri.AbsoluteUri){UseShellExecute=true});
 async void ConnectAccount(object sender,RoutedEventArgs e)=>await Execute(StartAccountConnectionAsync);
 async Task StartAccountConnectionAsync(){
  if(openingAccount)return;openingAccount=true;AccountConnect.IsEnabled=false;
  try{
   var account=model.AccountConnectionClient();await account.RefreshAsync(lifetime.Token);
   if(!account.Status.ImagePreparation){
    var signIn=new WelcomeWindow(new WindowsServiceClient(),()=>{},false,forceSignIn:true){Owner=this};
    signIn.ShowDialog();await RefreshAccountConnectionAsync();return;
   }
   await account.StartAsync(lifetime.Token);
   var deadline=DateTime.UtcNow.AddSeconds(20);
   while(account.Status.State=="STARTING"&&DateTime.UtcNow<deadline){await Task.Delay(500,lifetime.Token);await account.RefreshAsync(lifetime.Token);}
   if(account.Status.VerificationUri is {} uri)OpenAccountUri(uri);
   await RefreshAccountConnectionAsync();
  }finally{openingAccount=false;AccountConnect.IsEnabled=!model.AccountConnectionClient().Status.ImageReady;}
 }
 async void OpenAccountCabinet(object sender,RoutedEventArgs e)=>await Execute(async()=>{
  var account=model.AccountConnectionClient();await account.RefreshAsync(lifetime.Token);
  if(account.Status.CabinetUri is {} uri){new NativeCabinetWindow(uri){Owner=this}.ShowDialog();await RefreshAccountConnectionAsync();}else await StartAccountConnectionAsync();
 });
}
