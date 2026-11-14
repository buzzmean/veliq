using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
namespace Neexitlag.Desktop;
public sealed class PromptWindow : Window
{
    internal PromptWindow(Window owner, string key, bool confirm)
    {
        Owner = owner;
        Title = "VELIQ";
        Icon = owner.Icon;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;
        SizeToContent = SizeToContent.Height;
        Width = 440;
        Background = (Brush)FindResource("Bg");
        Foreground = (Brush)FindResource("Text");
        FontFamily = (FontFamily)FindResource("VeliqFont");
        WindowTheme.UseDarkCaption(this);
        ShowInTaskbar = false;
        var panel = new StackPanel { Margin = new Thickness(24) };
        panel.Children.Add(new TextBlock { Text = Text.Get(key), TextWrapping = TextWrapping.Wrap, FontSize = 15, Margin = new Thickness(0, 0, 0, 20) });
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        if (confirm)
        {
            var cancel = new Button { Content = Text.Get("Cancel"), IsCancel = true };
            cancel.Click += (_, _) => DialogResult = false;
            buttons.Children.Add(cancel);
        }
        var ok = new Button { Content = Text.Get(confirm ? "Remove" : "Ok"), IsDefault = true, Style = (Style)FindResource("Primary"), Margin = new Thickness(0) };
        ok.Click += (_, _) => DialogResult = true;
        buttons.Children.Add(ok);
        panel.Children.Add(buttons);
        Content = panel;
    }
    public static bool Show(Window owner, string key, bool confirm) => new PromptWindow(owner, key, confirm).ShowDialog() == true;
}
