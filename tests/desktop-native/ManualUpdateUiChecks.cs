using System.Windows;
using System.Windows.Controls;
using Neexitlag.Desktop;
using Button = System.Windows.Controls.Button;
internal static partial class Program
{
    sealed class UpdateUiService : IServiceClient
    {
        public int Installs;
        public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
        {
            if (method != "update.install") throw new ServiceException(ServiceFailure.NotInstalled);
            Installs++;
            return Task.FromResult((T)(object)new UpdateSnapshot { State = "INSTALLING" });
        }
    }
    static void ManualUpdateButton()
    {
        var service = new UpdateUiService();
        var window = new MainWindow(new() { MinimizeToTray = false }, false, false, settings, service);
        window.Show(); Pump();
        var model = (DesktopViewModel)window.DataContext;
        model.Apply(new Snapshot());
        var button = (Button)window.FindName("InstallUpdateButton");
        {
            // The same actual compiled control is checked at the minimum window size.
            window.Width = 960; window.Height = 640;
            model.ApplyUpdate(new() { State = "DOWNLOADING", DownloadedBytes = 50, TotalBytes = 100 }); Pump();
            Require(button.IsVisible && !button.IsEnabled, "Download button state");
            SaveImage(window, "manual-update-downloading");
            model.ApplyUpdate(new() { State = "READY", AvailableBuild = 713, AvailableVersion = "0.3.713" }); Pump();
            Require(button.IsVisible && button.IsEnabled && button.ActualWidth >= 36, "Ready button state");
            SaveImage(window, "manual-update-ready");
        }
        Require(service.Installs == 0, "Opening the window triggered installation");
        button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); Pump();
        Require(service.Installs == 1 && !button.IsEnabled, "Button did not reach the owner install request");
        model.ApplyUpdate(new() { State = "DISABLED" }); Pump();
        Require(!button.IsVisible, "Managed image exposes update action");
        window.Close(); Pump(); Pass("Manual update progress, ready action and club hiding");
    }
}
