using System.Globalization;
using System.Resources;
namespace Veliq.Desktop;
public static class Text
{
    static readonly ResourceManager Resources = new("Veliq.Desktop.Resources.Strings", typeof(Text).Assembly);
    public static readonly CultureInfo Russian = CultureInfo.GetCultureInfo("ru-RU");
    public static CultureInfo UICulture { get; set; } = Russian;
    public static string Get(string key) => Resources.GetString(key, UICulture) ?? throw new InvalidOperationException($"Missing UI resource: {key}");
    public static string Route(string? id) => string.IsNullOrEmpty(id) ? Get("NoData") : id == "DIRECT" ? Get("Direct") : id == "DIRECT_PLUS" ? Get("DirectPlus") : id;
    public static string Mode(string mode) => Get(mode switch { "AUTO" => "Auto", "DIRECT_PLUS" => "DirectPlus", "MANUAL" => "ViaServer", "BLOCK" => "Block", _ => "Direct" });
    public static string Status(string status) => Get(status switch { "healthy" or "measured" => "Working", "error" => "Error", "not configured" => "NotConfigured", _ => "NotAvailable" });
    public static string Failure(Exception error) => error is ChromeActivationException ? error.Message : error is ServiceException se ? Get(se.Failure switch { ServiceFailure.NotInstalled => "ServiceMissing", ServiceFailure.Stopped => "ServiceStopped", ServiceFailure.Incompatible => "ServiceIncompatible", ServiceFailure.AccessDenied => "ServiceDenied", ServiceFailure.Rejected => "CommandRejected", _ => "ServiceUnavailable" }) : Get("UnexpectedError");
    public static string Milliseconds(double value) => $"{value.ToString("F1", Russian)} {Get("Millisecond")}";
    public static string Percent(double value) => value.ToString("P1", Russian);
    public static string Bytes(ulong value)
    {
        string[] units = ["Byte", "Kilobyte", "Megabyte", "Gigabyte"];
        double n = value;
        int i = 0;
        while (n >= 1024 && i < 3)
        {
            n /= 1024;
            i++;
        }
        return $"{n.ToString(i == 0 ? "N0" : "N1", Russian)} {Get(units[i])}";
    }
}
