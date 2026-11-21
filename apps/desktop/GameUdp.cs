using System.Windows;
namespace Neexitlag.Desktop;
public partial class MainWindow {
    async void ToggleGameUdp(object sender,RoutedEventArgs e){
        if(sender is FrameworkElement {DataContext:GameUdpProfile p})await Execute(()=>model.SetGameUdpAsync(p.ProfileId,!p.Engine.Enabled,lifetime.Token));
    }
    async void EnableSelectedGameUdp(object sender,RoutedEventArgs e){
        if(AppGrid.SelectedItem is not ApplicationRow row){model.ReportGameUdpSelectionRequired();return;}
        await Execute(()=>model.SetGameUdpAsync(row.Profile.Id,true,lifetime.Token));
    }
}
