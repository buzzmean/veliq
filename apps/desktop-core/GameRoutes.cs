using System.Collections.ObjectModel;
namespace Neexitlag.Desktop;
// «Игры» as Q badges (app-ui shape) with a route strip; labels are the community names, not forced codes.
public sealed partial class GameCard
{
    static readonly Dictionary<string,string> Badges=new(){["valorant"]="Valorant",["lol"]="LoL",["cs2"]="CS2",["dota2"]="Dota 2",["pubg"]="PUBG",
        ["fortnite"]="Fortnite",["apex"]="Apex",["rust"]="Rust",["gtav"]="GTA V",["rdr2"]="RDR 2"};
    public string Badge=>Badges.TryGetValue(Id,out var b)?b:Name;
    public double BadgeSize=>Badge.Length<=4?30:Badge.Length<=6?24:19;
    public string Details=>$"{Launcher} · {Definition.AntiCheat}";
    string? relayId;bool selected;
    public string? RelayId {get=>relayId;set{if(Set(ref relayId,value))RouteChanged();}}
    public bool IsSelected {get=>selected;set=>Set(ref selected,value);}
    public bool IsCustom=>Mode!="DIRECT";
    public string RouteKey=>Mode=="MANUAL"?"MANUAL:"+RelayId:Mode;
    public string RouteLabel=>Mode switch{"AUTO"=>"Авто","DIRECT_PLUS"=>"Локально","MANUAL"=>RelayId is {Length:>0} r?"Сервер "+Text.Route(r):"Через сервер",_=>"Напрямую"};
    void RouteChanged(){Changed(nameof(RouteLabel));Changed(nameof(IsCustom));Changed(nameof(RouteKey));RouteKeyChanged?.Invoke();}
    internal Action? RouteKeyChanged;
}
public sealed class RouteOption(string key,string mode,string? relayId,string label,string hint):Observable
{
    public string Key{get;}=key;public string Mode{get;}=mode;public string? RelayId{get;}=relayId;public string Label{get;}=label;public string Hint{get;}=hint;
    bool selected;public bool IsSelected{get=>selected;set=>Set(ref selected,value);}
}
public sealed partial class GameCatalogViewModel
{
    public ObservableCollection<RouteOption> Routes {get;}=[new("DIRECT","DIRECT",null,"Напрямую","как без VELIQ"),new("DIRECT_PLUS","DIRECT_PLUS",null,"Локально","новые игровые UDP-подключения без VPS"),new("AUTO","AUTO",null,"Авто","VELIQ выберет сам")];
    GameCard? selected;
    public GameCard? Selected {get=>selected;private set{if(Set(ref selected,value))Changed(nameof(HasSelection));}}
    public bool HasSelection=>Selected is not null;
    (string Mode,string? RelayId) savedRoute;
    // A second click on the open game closes the strip.
    public void Select(GameCard g){if(Selected==g){Close();return;}Close();g.IsSelected=true;g.RouteKeyChanged=MarkRoute;savedRoute=(g.Mode,g.RelayId);Selected=g;MarkRoute();}
    // Closing without «Применить» drops the unsaved choice so the badge keeps showing the saved route.
    public void Close(bool keepChoice=false){if(Selected is not {} g)return;if(!keepChoice){g.Mode=savedRoute.Mode;g.RelayId=savedRoute.RelayId;}g.IsSelected=false;g.RouteKeyChanged=null;Selected=null;}
    public void ChooseRoute(RouteOption o){if(Selected is not {} g)return;g.RelayId=o.RelayId;g.Mode=o.Mode;MarkRoute();}
    void MarkRoute(){foreach(var o in Routes)o.IsSelected=Selected?.RouteKey==o.Key;}
    // Only relays the service reports right now; nothing invented.
    async Task LoadRelaysAsync(CancellationToken ct){
        try{
            var status=await client.Call<Snapshot>("status",cancellationToken:ct);
            var relays=status?.Routes.Where(r=>r.Id!="DIRECT"&&r.Status is "healthy" or "degraded").Select(r=>r.Id).Distinct().ToArray()??[];
            foreach(var o in Routes.Where(o=>o.Mode=="MANUAL").ToArray())if(!relays.Contains(o.RelayId))Routes.Remove(o);
            foreach(var id in relays)if(!Routes.Any(o=>o.RelayId==id))Routes.Add(new("MANUAL:"+id,"MANUAL",id,"Сервер "+Text.Route(id),"может добавить пинг"));
            MarkRoute();
        }catch(Exception e) when (e is ServiceException or InvalidOperationException or NullReferenceException){}
    }
}
