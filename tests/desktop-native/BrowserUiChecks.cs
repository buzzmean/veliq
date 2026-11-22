using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Neexitlag.Desktop;
using Button = System.Windows.Controls.Button;

internal static partial class Program
{
    sealed class YouTubeSettingsService : IServiceClient
    {
        public bool Automatic { get; set; }
        public int Writes { get; private set; }

        public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
        {
            if (method == "browser.youtube.local.set")
                Writes++;
            else if (method != "browser.youtube.local.status")
                throw new ServiceException(ServiceFailure.Rejected, method);
            string json = Automatic
                ? """{"automatic":true,"manageable":false,"enabled":true,"active":true,"reason":"READY"}"""
                : """{"manageable":true,"enabled":false,"active":false,"reason":"OFF"}""";
            return Task.FromResult(JsonSerializer.Deserialize<T>(json, WireJson.Options)!);
        }
    }

    static void YouTubeSettingsCompatibility()
    {
        var fixture = new YouTubeSettingsService();
        var window = new MainWindow(new() { MinimizeToTray = false }, false, false, settings, fixture);
        window.Show();
        try
        {
            ((DesktopViewModel)window.DataContext).Apply(new() { Connected = true });
            var panel = (Border)window.FindName("YouTubeLocalPanel");
            var toggle = (System.Windows.Controls.CheckBox)window.FindName("YouTubeLocalToggle");
            window.ShowPage("Settings");
            Require(panel.Visibility == Visibility.Visible && toggle.IsEnabled, "Legacy YouTube can no longer be managed");
            fixture.Automatic = true;
            window.ShowPage("Settings");
            Require(panel.Visibility == Visibility.Collapsed && !toggle.IsEnabled, "Automatic YouTube still presents a manual toggle");
            toggle.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));
            Require(fixture.Writes == 0, "Automatic YouTube still sent a preference write");
            fixture.Automatic = false;
            window.ShowPage("Settings");
            Require(panel.Visibility == Visibility.Visible && toggle.IsEnabled, "Legacy YouTube setting did not return after rollback");
        }
        finally { window.Close(); Pump(); }
        Pass("YouTube switch follows automatic service capability and legacy rollback");
    }

    static void BrowserAndPrompt()
    {
        YouTubeSettingsCompatibility();
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
