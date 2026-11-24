using System.Windows;

namespace Veliq.Desktop;

public partial class MainWindow
{
    Task<bool> ConfirmRelayChoiceAsync(Profile profile) => Task.FromResult(
        MessageBox.Show(this, string.Format(Text.Russian, Text.Get("RelayWarningMessage"), profile.Name),
            Text.Get("RelayWarningTitle"), MessageBoxButton.YesNo, MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes);
}
