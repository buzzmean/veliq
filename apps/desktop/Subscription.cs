using System.Windows;
namespace Neexitlag.Desktop;
public partial class MainWindow {
 async Task RefreshSubscriptionAsync(bool recheck=false){
  var subscription=model.SubscriptionClient();await subscription.RefreshAsync(recheck,lifetime.Token);
  var status=subscription.Status;
  SubscriptionSummary.Text=status.Summary;SubscriptionHint.Text=status.Hint;
  SubscriptionRow.Visibility=status.Known?Visibility.Visible:Visibility.Collapsed;
  SubscriptionPanel.Visibility=status.Expired&&ActivationPanel.Visibility!=Visibility.Visible?Visibility.Visible:Visibility.Collapsed;
 }
 void RenewSubscription(object sender,RoutedEventArgs e){
  try{System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(SubscriptionView.AccountUrl){UseShellExecute=true});}catch(Exception){}
 }
 async void RecheckSubscription(object sender,RoutedEventArgs e)=>await Execute(()=>RefreshSubscriptionAsync(true));
}
