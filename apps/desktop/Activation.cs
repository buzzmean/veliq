using System.Windows;
namespace Neexitlag.Desktop;
public partial class MainWindow {
 bool activationBusy,activationEdit,activationSubmitted;
 async Task RefreshActivationAsync(){
  if(activationBusy)return;
  var activation=model.ActivationClient();await activation.RefreshAsync(lifetime.Token);
  var status=activation.Status;
  ActivationSummary.Text=status.Message;ActivationCertificates.Text=status.CertificateStatus;
  if(!activationEdit){ActivationPanel.Visibility=!status.HasIdentity&&status.State is "CODE_REQUIRED" or "ACTIVATING" or "ACTIVATION_ERROR"?Visibility.Visible:Visibility.Collapsed;}
  ActivationError.Text=status.Message;
  await RefreshAccountConnectionAsync();
  if(status.State=="ACTIVATED"&&(!activationEdit||activationSubmitted)){activationEdit=false;ActivationPanel.Visibility=Visibility.Collapsed;ActivationCode.Password="";}
 }
 void ChangeActivation(object sender,RoutedEventArgs e){activationEdit=true;activationSubmitted=false;ActivationPanel.Visibility=Visibility.Visible;ActivationCode.Password="";ActivationError.Text="Введите новый код активации";ActivationCode.Focus();}
 async void SubmitActivation(object sender,RoutedEventArgs e){
  if(activationBusy)return;activationBusy=true;ActivationSubmit.IsEnabled=false;
  try{activationSubmitted=true;var code=ActivationCode.Password;ActivationCode.Password="";await model.ActivationClient().ActivateAsync(code,lifetime.Token);ActivationError.Text=model.ActivationClient().Status.Message;}
  catch(OperationCanceledException)when(lifetime.IsCancellationRequested){}
  finally{activationBusy=false;ActivationSubmit.IsEnabled=true;}
 }
}
