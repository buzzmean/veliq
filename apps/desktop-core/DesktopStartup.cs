namespace Veliq.Desktop;

public static class DesktopStartup
{
    public static bool IsAutomatic(IEnumerable<string> arguments, bool freshSetup) =>
        !freshSetup && arguments.Contains("--autostart", StringComparer.OrdinalIgnoreCase);

    public static bool StayInTray(bool automatic, bool foregroundRequested) =>
        automatic && !foregroundRequested;
}
