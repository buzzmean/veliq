using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Globalization;
using Veliq.Desktop;
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
            // Exercise the compiled BAML at the smallest supported client size.
            window.Width = 960; window.Height = 640;
            model.ApplyUpdate(new() { State = "DOWNLOADING", CurrentBuild = "712", AvailableBuild = 713, DownloadedBytes = 50, TotalBytes = 100 }); Pump();
            Require(button.IsVisible && !button.IsEnabled, "Download button state");
            SaveImage(window, "manual-update-downloading");
            model.ApplyUpdate(new() { State = "READY", CurrentBuild = "712", AvailableBuild = 713, AvailableVersion = "0.3.713" }); Pump();
            Require(button.IsVisible && button.IsEnabled, "Ready button state");
            Require(ReferenceEquals(button.Parent, window.FindName("SidebarFooterActions")), "Update action must share the footer with About");
            CheckSidebarGeometry(window, button);
            button.Focus(); Pump();
            Require(button.IsKeyboardFocused, "Update action is unreachable by keyboard");
            var surface = (Border)button.Template.FindName("UpdateSurface", button);
            Brush(surface.Background, "#FFFFFFFF", "Ready update circle must have a light surface");
            Brush(button.Foreground, "#FF0A0A0B", "Update glyph must contrast with the surface");
            Brush(surface.BorderBrush, "#FFF0502A", "Keyboard focus has no visible outline");
            Require(ToolTipService.GetShowOnDisabled(button), "Download progress tooltip is unavailable while the button is disabled");
            Require(window.FindName("YouTubeLocalPanel") is null, "Experimental YouTube settings remain visible");
            Require(((FrameworkElement)window.FindName("ActivationCertificates")).Visibility == Visibility.Collapsed, "Certificate dates exposed in normal settings");
            Require(window.FindName("PlannedGameOptimization") is Border && window.FindName("PlannedSystemOptimization") is Border, "Planned features must be labelled non-interactive items");
            SaveImage(window, "manual-update-ready");
            SaveImage((FrameworkElement)window.FindName("SidebarRail"), "sidebar-minimum");
            window.Width = 1180; window.Height = 780; Pump();
            CheckSidebarGeometry(window, button);
            SaveImage(window, "sidebar-normal");
            window.Width = 1440; window.Height = 960;
            ((FrameworkElement)window.Content).LayoutTransform = new ScaleTransform(1.5, 1.5); Pump();
            CheckSidebarGeometry(window, button);
            SaveImage(window, "sidebar-content-scale150");
            ((FrameworkElement)window.Content).LayoutTransform = Transform.Identity;
            window.Width = 960; window.Height = 640; Pump();
            var about = (Button)((System.Windows.Controls.Panel)window.FindName("NavBottom")).Children[0];
            about.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); Pump();
            Require(Nav.GetIsCurrent(about) && ((FrameworkElement)window.FindName("About")).IsVisible, "Footer About navigation lost its selected state");
            window.ShowPage("Home"); Pump();
        }
        Require(service.Installs == 0, "Opening the window triggered installation");
        button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); Pump();
        Require(service.Installs == 1 && !button.IsEnabled, "Button did not reach the owner install request");
        model.ApplyUpdate(new() { State = "DISABLED" }); Pump();
        Require(!button.IsVisible, "Managed image exposes update action");
        model.ApplyUpdate(new() { State = "INSTALL_FAILED", CurrentBuild = "713", AvailableBuild = 713 }); Pump();
        Require(!button.IsVisible, "Old failure advertises the already installed build");
        SaveImage(window, "manual-update-current");
        window.Exit(); Pump(); Pass("Footer update circle, uncut planned labels and aligned badges at minimum/normal/150% content scale; current and club hiding");
    }
    static void CheckSidebarGeometry(MainWindow window, Button button)
    {
        System.Windows.Rect Bounds(FrameworkElement element) => element.TransformToAncestor(window).TransformBounds(new System.Windows.Rect(0, 0, element.ActualWidth, element.ActualHeight));
        var rail = Bounds((FrameworkElement)window.FindName("SidebarRail"));
        var footer = Bounds((FrameworkElement)window.FindName("SidebarFooterActions"));
        var status = Bounds((FrameworkElement)window.FindName("SidebarStatus"));
        var update = Bounds(button);
        Require(button.ActualWidth == 28 && button.ActualHeight == 28, "Update circle inherited a minimum height and became an oval");
        Require(footer.Bottom <= status.Top && update.Top >= footer.Top && update.Bottom <= footer.Bottom, "Update overlaps the connection status");
        Require(update.Right < rail.Right && update.Left > rail.Left, "Update control is clipped by the rail");
        System.Windows.Rect? previousBadge = null;
        foreach (var suffix in new[] { "Game", "System" })
        {
            var row = (Border)window.FindName("Planned" + suffix + "Optimization");
            var label = (TextBlock)window.FindName("Planned" + suffix + "Label");
            var badge = (Border)window.FindName("Planned" + suffix + "Badge");
            var text = new FormattedText(label.Text, CultureInfo.GetCultureInfo("ru-RU"), System.Windows.FlowDirection.LeftToRight,
                new Typeface(label.FontFamily, label.FontStyle, label.FontWeight, label.FontStretch), label.FontSize, label.Foreground,
                VisualTreeHelper.GetDpi(label).PixelsPerDip);
            Require(row.ActualHeight == 40 && label.ActualWidth >= text.WidthIncludingTrailingWhitespace - 0.5 && label.ActualHeight <= text.Height + 1,
                "Planned navigation label wraps or is cut: " + label.Text);
            var labelBounds = Bounds(label); var badgeBounds = Bounds(badge);
            Require(labelBounds.Right <= badgeBounds.Left && badgeBounds.Right < rail.Right, "Coming-soon badge overlaps or leaves the rail");
            Require(Math.Abs(labelBounds.Top + labelBounds.Height / 2 - badgeBounds.Top - badgeBounds.Height / 2) < 1, "Coming-soon badge is not vertically aligned with its label");
            if (previousBadge is { } previous) Require(Math.Abs(previous.Right - badgeBounds.Right) < 0.5, "Coming-soon badges use different right columns");
            previousBadge = badgeBounds;
        }
    }
}
