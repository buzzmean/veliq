using System.Windows;
namespace Veliq.Desktop;
public partial class MainWindow
{
    async void InstallUpdate(object sender, RoutedEventArgs e) => await model.ApplyUpdateAsync(lifetime.Token);
}
