using System.Text.Json;
namespace Veliq.Desktop;
public static class ClubPresentation
{
    public static bool Enabled(string? json)
    {
        try { using var d=JsonDocument.Parse(json??"");return d.RootElement.GetProperty("version").GetInt32()==1&&d.RootElement.GetProperty("enabled").GetBoolean(); }
        catch(Exception e) when(e is JsonException or InvalidOperationException or KeyNotFoundException or FormatException){return false;}
    }
    public static string Summary(bool connected,bool optimizing,bool capture) =>
        connected&&optimizing&&capture ? "VELIQ · защита включена" : "VELIQ · подготовка подключения…";
    public static string GameLine(GameUdpStatus status)
    {
        var pubg=status.Profiles.FirstOrDefault(p=>p.ProfileId=="pubg"||p.Engine.InitialPolicy=="LOCAL_FIRST_UNCONFIRMED_ENDPOINT");
        return pubg is null?"PUBG: пока не обнаружена":"PUBG: "+pubg.Summary;
    }
}
