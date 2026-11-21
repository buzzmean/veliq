using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
namespace Neexitlag.Desktop;
// Dark caption to match Assets/Theme.xaml; silently ignored on Windows builds without these DWM attributes.
static class WindowTheme
{
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
    const int ImmersiveDarkMode = 20, ImmersiveDarkModeLegacy = 19, BorderColor = 34, CaptionColor = 35;
    const int Ink950 = 0x000B0A0A; // COLORREF of #0A0A0B
    public static void UseDarkCaption(Window window) => window.SourceInitialized += (_, _) =>
    {
        try
        {
            var handle = new WindowInteropHelper(window).Handle;
            int on = 1, color = Ink950;
            if (DwmSetWindowAttribute(handle, ImmersiveDarkMode, ref on, sizeof(int)) != 0)
                DwmSetWindowAttribute(handle, ImmersiveDarkModeLegacy, ref on, sizeof(int));
            DwmSetWindowAttribute(handle, CaptionColor, ref color, sizeof(int));
            DwmSetWindowAttribute(handle, BorderColor, ref color, sizeof(int));
        }
        catch (DllNotFoundException) { }
        catch (EntryPointNotFoundException) { }
    };
}
// Tray glyphs from brand/icons: off / connecting / on / error, "dark" for a dark taskbar, "light" for a light one.
static class TrayIcons
{
    public static string State(DesktopViewModel model) => model.Busy ? "connecting" : model.Optimizing ? "on" : !model.Available && model.Error.Length > 0 ? "error" : "off";
    public static System.Drawing.Icon Load(string state)
    {
        var theme = LightTaskbar() ? "light" : "dark";
        using var stream = System.Windows.Application.GetResourceStream(new Uri($"pack://application:,,,/VELIQ;component/Assets/Tray/tray-{state}-{theme}.ico"))!.Stream;
        return new System.Drawing.Icon(stream, System.Windows.Forms.SystemInformation.SmallIconSize);
    }
    static bool LightTaskbar()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("SystemUsesLightTheme") is int value && value == 1;
        }
        catch (Exception) { return false; }
    }
    public static string Tooltip(string status)
    {
        var text = "VELIQ: " + status;
        return text.Length <= 63 ? text : text[..63]; // NotifyIcon.Text limit
    }
}
// Dark tray menu (WinForms ContextMenuStrip) in the same palette.
sealed class TrayMenuRenderer : System.Windows.Forms.ToolStripProfessionalRenderer
{
    static readonly System.Drawing.Color Text = System.Drawing.Color.White, Faint = System.Drawing.Color.FromArgb(0x8E, 0x93, 0x9C);
    public TrayMenuRenderer() : base(new TrayMenuColors()) { RoundedEdges = false; }
    protected override void OnRenderItemText(System.Windows.Forms.ToolStripItemTextRenderEventArgs e)
    {
        e.TextColor = e.Item.Enabled ? Text : Faint;
        base.OnRenderItemText(e);
    }
    public static void Apply(System.Windows.Forms.ContextMenuStrip menu)
    {
        menu.Renderer = new TrayMenuRenderer();
        menu.BackColor = TrayMenuColors.Raised;
        menu.ForeColor = Text;
        menu.ShowImageMargin = false;
        menu.Padding = new System.Windows.Forms.Padding(4);
    }
}
sealed class TrayMenuColors : System.Windows.Forms.ProfessionalColorTable
{
    internal static readonly System.Drawing.Color Raised = System.Drawing.Color.FromArgb(0x13, 0x14, 0x17), Hover = System.Drawing.Color.FromArgb(0x22, 0x25, 0x2A), Line = System.Drawing.Color.FromArgb(0x30, 0x34, 0x3B);
    public override System.Drawing.Color ToolStripDropDownBackground => Raised;
    public override System.Drawing.Color MenuBorder => Line;
    public override System.Drawing.Color MenuItemBorder => Hover;
    public override System.Drawing.Color MenuItemSelected => Hover;
    public override System.Drawing.Color MenuItemSelectedGradientBegin => Hover;
    public override System.Drawing.Color MenuItemSelectedGradientEnd => Hover;
    public override System.Drawing.Color MenuItemPressedGradientBegin => Hover;
    public override System.Drawing.Color MenuItemPressedGradientEnd => Hover;
    public override System.Drawing.Color ImageMarginGradientBegin => Raised;
    public override System.Drawing.Color ImageMarginGradientMiddle => Raised;
    public override System.Drawing.Color ImageMarginGradientEnd => Raised;
    public override System.Drawing.Color SeparatorDark => Line;
    public override System.Drawing.Color SeparatorLight => Raised;
}
