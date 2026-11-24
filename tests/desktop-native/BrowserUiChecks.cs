using System.Windows;
using System.Windows.Controls;
using Veliq.Desktop;
using Button = System.Windows.Controls.Button;

internal static partial class Program
{
    static void BrowserAndPrompt()
    {
        {
            var window = Window(new() { MinimizeToTray = false });
            window.Show();
            Pump();
            var model = (DesktopViewModel)window.DataContext;
            var chrome = new Profile { Id = "chrome", Mode = "AUTO", Executables = ["chrome.exe"] };
            var edge = new Profile { Id = "edge", Mode = "AUTO", Executables = ["msedge.exe"] };
            var state = new Snapshot { Connected = true, Optimizing = true, Profiles = [chrome, edge],
                BrowserPolicy = new() { ChromeConfigured = true, ChromeReady = true, EdgeConfigured = true } };
            state.Backend.Ready = true;
            ProcessIdentity[] chromeProcess = [new() { Path = @"C:\Chrome\chrome.exe" }];
            ProcessIdentity[] browsers = [.. chromeProcess, new() { Path = @"C:\Edge\msedge.exe" }];
            var nav = (StackPanel)window.FindName("NavTop");

            void Check(string image, ProcessIdentity[] processes, string expected)
            {
                model.Apply(state, processes);
                void Navigate(string page) => nav.Children.OfType<Button>().Single(b => (string)b.Tag == page).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Navigate("Applications");
                Pump();
                Require(((FrameworkElement)window.FindName("Applications")).Visibility == Visibility.Visible, "Services navigation blocked by browser readiness");
                Navigate("Home");
                Pump();
                Require(((FrameworkElement)window.FindName("Home")).Visibility == Visibility.Visible, "Home navigation blocked by browser readiness");
                Require(model.OptimizationStatus == Text.Get("OptimizationOn") && model.CanControl, "Browser status blocked general controls");
                Require(model.BrowserReadinessText.Contains("Chrome — обмен подтверждён") && model.BrowserReadinessText.Contains(expected), model.BrowserReadinessText);
                SaveImage(window, image);
            }

            Check("browser-edge-closed", chromeProcess, "Edge — не запущен");
            state.BrowserPolicy.EdgeReady = true;
            Check("browser-both-ready", browsers, "Edge — обмен подтверждён");
            state.BrowserPolicy.EdgeReady = false;
            state.BrowserPolicy.EdgeReason = "EDGE_POLICY_ACCESS_DENIED";
            Check("browser-edge-failed", browsers, "Edge — не удалось применить настройки подключения");
            window.Close();
            Pump();
            Pass("Home and Services navigation stays available for closed, ready, and failed Edge");
        }

        {
            var owner = new Window { Width = 600, Height = 450, ShowInTaskbar = false };
            owner.Show();
            try
            {
                var message = new PromptWindow(owner, "SettingsSaved", false);
                var confirm = new PromptWindow(owner, "RemoveApplication", true);
                foreach (var (dialog, key, image, confirmMode) in new[] { (message, "SettingsSaved", "prompt-settings-saved", false), (confirm, "RemoveApplication", "prompt-confirmation", true) })
                {
                    dialog.Show();
                    Pump();
                    var content = (StackPanel)dialog.Content;
                    var text = content.Children.OfType<TextBlock>().Single();
                    Brush(dialog.Background, "#FF0A0A0B", "Prompt background");
                    Brush(text.Foreground, "#FFFFFFFF", "Prompt copy foreground");
                    Require(text.Text == Text.Get(key), "Prompt text does not match its resource");
                    var buttons = content.Children.OfType<StackPanel>().Single().Children.OfType<Button>().ToArray();
                    Require(buttons.Count(b => b.IsDefault) == 1 && buttons.Count(b => b.IsCancel) == (confirmMode ? 1 : 0), "Prompt keyboard actions changed");
                    SaveImage(dialog, image);
                    dialog.Close();
                }
            }
            finally { owner.Close(); }
            Pass("Dark shared settings notice and confirmation with readable foreground and keyboard actions");
        }
    }
}
