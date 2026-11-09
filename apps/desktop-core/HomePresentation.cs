namespace Neexitlag.Desktop;
// Home screen texts per app-ui/index.html states: off / connecting / on / error.
public sealed partial class DesktopViewModel
{
    Route? BestRelay => Snapshot?.Routes.Where(r => r.Id != "DIRECT" && Fresh(r)).OrderBy(r => r.Id == Snapshot.Primary ? 0 : 1).ThenBy(r => r.Score ?? double.MaxValue).FirstOrDefault();
    public string HomeLead => Text.Get(!Available ? "HomeErrorLead" : Busy || Optimizing && Connection != Text.Get("Connected") ? "HomeConnectingLead" : Optimizing ? "HomeOnLead" : "HomeOffLead");
    public string Server => Available && BestRelay is { } r ? Text.Route(r.Id) : "—";
    public string ServerHint => Text.Get(Available && BestRelay is not null ? "ServerAuto" : "ServerPending");
    public string GoSub => !Available ? Text.Get("GoSubError") : Busy ? Text.Get("GoSubConnecting") : !Optimizing ? Text.Get("GoSubOff")
        : BestRelay is { } r ? $"{Text.Route(r.Id)}, {Text.Milliseconds(r.RttMs)}" : Text.Get("GoSubOn");
    void NotifyBusyHome(){Changed(nameof(HomeLead));Changed(nameof(GoSub));}
}
