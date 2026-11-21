using System.Text.Json;
using Microsoft.Win32;
namespace Neexitlag.Desktop;
public sealed class LocalPreferences
{
    public bool StartMinimized
    {
        get; set;
    }
    public bool MinimizeToTray { get; set; } = true;
    public bool ShowTechnical { get; set; }
    static string PathName => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VELIQ", "desktop.json");
    public static LocalPreferences Load(string? path = null)
    {
        try
        {
            return JsonSerializer.Deserialize<LocalPreferences>(File.ReadAllText(path ?? PathName)) ?? new();
        }
        catch { return new(); }
    }
    public void Save(string? path = null)
    {
        path ??= PathName;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(this));
        File.Move(temporary, path, true);
    }
    public static bool AutoStart
    {
        get
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            return key?.GetValue("VELIQ") != null || key?.GetValue(LegacyRunValue) != null;
        }
    }
    public static void SetAutoStart(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
        key.DeleteValue(LegacyRunValue, false);
        if (enabled && Environment.ProcessPath is string path)
            key.SetValue("VELIQ", '"' + path + '"');
        else
            key.DeleteValue("VELIQ", false);
    }
    const string LegacyRunValue = "NeExitLag";

    // Pre-rebrand builds kept per-user state in %LOCALAPPDATA%\NeExitLag and the
    // autostart value under that name. Move both once; never overwrite new state.
    public static void MigrateLegacyUserData()
    {
        try
        {
            var root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var legacy = Path.Combine(root, "NeExitLag");
            var current = Path.Combine(root, "VELIQ");
            if (Directory.Exists(legacy) && !Directory.Exists(current))
                Directory.Move(legacy, current);
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
            if (key?.GetValue(LegacyRunValue) != null && Environment.ProcessPath is string path)
            {
                key.SetValue("VELIQ", '"' + path + '"');
                key.DeleteValue(LegacyRunValue, false);
            }
        }
        catch (Exception) { }
    }
}
