using System.Collections.ObjectModel;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
namespace Neexitlag.Desktop;

public sealed record GameDefinition(string Id, string Name, string Icon, string[] Executables, string Launcher, string AntiCheat, string DefaultMode, string UdpPreset, bool LauncherNeedsBypass, string[]? NetworkReferences = null);
// Informational data only. Never consumed by capture/profile/routing code.
public sealed record GameNetworkReference(string Id, string Name, string[] TcpPorts, string[] UdpPorts, string Evidence);
public sealed record GameCatalogData(int Version, GameDefinition[] Games, GameNetworkReference[]? NetworkInformation = null);
public static class GameCatalog
{
    public const string BundledSha256 = "53B349B99631C9F139EBCACC5A03E37AFC18FD52542B51C9F4038CC433849861";
    // No unsigned imports/network updates. Catalog trust follows the installed
    // assembly. A public update envelope requires an owner-pinned signing key.
    public static GameCatalogData Bundled() {
        using var stream=typeof(GameCatalog).Assembly.GetManifestResourceStream("Neexitlag.Desktop.Resources.GameCatalog.json") ?? throw new InvalidDataException("GAME_CATALOG_MISSING");
        using var buffer=new MemoryStream();stream.CopyTo(buffer);
        return Parse(buffer.ToArray(),BundledSha256);
    }
    public static GameCatalogData Parse(byte[] json,string expectedSha256) {
        if(json.Length>65536 || !Convert.ToHexString(SHA256.HashData(json)).Equals(expectedSha256,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("GAME_CATALOG_INTEGRITY_FAILED");
        var c=JsonSerializer.Deserialize<GameCatalogData>(json,new JsonSerializerOptions{PropertyNameCaseInsensitive=true}) ?? throw new InvalidDataException("GAME_CATALOG_INVALID");
        if(c.Version!=1 || c.Games is null || c.Games.Length is <1 or >64 || c.Games.Select(g=>g.Id).Distinct().Count()!=c.Games.Length)throw new InvalidDataException("GAME_CATALOG_VERSION_OR_DUPLICATE");
        foreach(var g in c.Games)if(g.Id.Length is <1 or >32 || g.Name.Length is <1 or >100 || g.DefaultMode!="DIRECT" || g.Executables is null || g.Executables.Length is <1 or >4 || g.Executables.Any(e=>e.Length>120||e.Contains('/')||e.Contains('\\')||!e.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)))throw new InvalidDataException("GAME_CATALOG_SCOPE_INVALID");
        return c;
    }
    public static string RiotActivity(JsonElement status) {
        if(status.ValueKind==JsonValueKind.Object && status.TryGetProperty("records",out var records) && records.ValueKind==JsonValueKind.Array)
            foreach(var r in records.EnumerateArray())
                if(r.TryGetProperty("received_bytes",out var rx) && rx.TryGetUInt64(out var bytes) && bytes>0 && r.TryGetProperty("policy",out var p) && p.TryGetProperty("action",out var a) && a.GetString() is "DIRECT_PLUS" or "RELAY_REQUIRED" or "RELAY")
                    return "Лаунчер: наблюдается LOCAL/RELAY обмен; запуск ещё не подтверждён";
        return "Лаунчер: ожидаем подтверждённый обход; DIRECT может быть достаточен";
    }
    public static GameCatalogData VerifySigned(byte[] json,byte[] signature,RSA ownerPinnedKey) {
        if(json.Length>65536 || !ownerPinnedKey.VerifyData(json,signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pss))throw new InvalidDataException("GAME_CATALOG_SIGNATURE_INVALID");
        return Parse(json,Convert.ToHexString(SHA256.HashData(json)));
    }
}
public sealed partial class GameCard(GameDefinition definition):Observable {
    public GameDefinition Definition {get;}=definition;
    public string Id=>Definition.Id;public string Name=>Definition.Name;public string Icon=>Definition.Icon;
    public string Launcher=>Definition.Launcher;public string AntiCheat=>"Античит: "+Definition.AntiCheat;
    public bool CanRepair=>Definition.LauncherNeedsBypass;
    public string Compatibility=>Definition.AntiCheat.Contains("Vanguard")||Definition.AntiCheat.Contains("FACEIT") ? "У игры строгий античит, поэтому VELIQ меняет её маршрут только по вашему выбору." : "";
    string mode="DIRECT";
    public string Mode {get=>mode;set{if(Set(ref mode,value))RouteChanged();}}
    public Profile? Profile {get;set;}
}
public sealed partial class GameCatalogViewModel(IServiceClient client):Observable {
    public event Action<Exception,string>? Failed;
    static string FailureText(Exception e)=>e is ServiceException {Message:"CLUB_ADMIN_MANAGED"}?"Настройками клуба управляет администратор":e is ServiceException {Message:"GAME_UDP_ANTICHEAT_COMPATIBILITY_UNVERIFIED"}?GameUdpMessages.Reason(e.Message):Text.Failure(e);
    readonly GameCard[] all=GameCatalog.Bundled().Games.Select(g=>new GameCard(g)).ToArray();
    public ObservableCollection<GameCard> Games {get;}=[];
    public Choice[] Modes {get;}=[new("AUTO","AUTO"),new("DIRECT","DIRECT"),new("DIRECT_PLUS","DIRECT+"),new("MANUAL","RELAY")];
    string search="",notice="";bool busy;
    public string Search {get=>search;set{if(Set(ref search,value))Filter();}}
    public string Notice {get=>notice;private set=>Set(ref notice,value);}
    public bool Busy {get=>busy;private set{if(Set(ref busy,value))Changed(nameof(CanInteract));}}
    public bool CanInteract=>!Busy;
    public void Filter(){Games.Clear();foreach(var g in all.Where(g=>g.Name.Contains(Search.Trim(),StringComparison.OrdinalIgnoreCase)||g.Launcher.Contains(Search.Trim(),StringComparison.OrdinalIgnoreCase)))Games.Add(g);}
    public async Task RefreshAsync(CancellationToken ct=default){
        if(Busy)return;Busy=true;
        try {
            var profiles=await client.Call<Profile[]>("profiles",cancellationToken:ct);
            GameUdpStatus? udp=null;try{udp=await client.Call<GameUdpStatus>("gameudp.status",cancellationToken:ct);}catch(ServiceException){}
            foreach(var g in all){g.Profile=profiles.FirstOrDefault(p=>p.Executables.Any(e=>g.Definition.Executables.Any(n=>ApplicationRow.Matches(n,e))));g.Mode=g.Profile?.Mode??g.Definition.DefaultMode;g.RelayId=g.Profile?.RelayId;var gameUdp=udp?.Profiles.FirstOrDefault(p=>p.ProfileId==g.Profile?.Id);if(gameUdp is not null){if(gameUdp.Engine.Enabled && g.Profile?.Mode is "DIRECT" or "AUTO")g.Mode=gameUdp.Engine.LocalOnly?"DIRECT_PLUS":"AUTO";}}
            Filter();await LoadRelaysAsync(ct);Notice="";
        }catch(Exception e){Failed?.Invoke(e,"gamecatalog.refresh");Notice="Служба VELIQ недоступна: "+FailureText(e);}finally{Busy=false;}
    }
    public async Task ApplyAsync(GameCard g,CancellationToken ct=default){
        if(Busy)return;Busy=true;
        try {
            if(!Modes.Any(m=>m.Value==g.Mode))throw new InvalidOperationException("Неизвестный режим");
            var p=g.Profile?.Copy()??new Profile{Id="game-"+g.Id,Name=g.Name,Executables=[..g.Definition.Executables],Custom=true};
            if(g.Mode=="DIRECT_PLUS"){
                if(g.Definition.UdpPreset.Length==0||p.Executables.Length!=1||!p.Executables[0].Contains('\\')){Notice="Локальный обход для этой игры пока не проверен, маршрут не изменён.";return;}
                if(p.Mode is not ("DIRECT" or "AUTO")){Notice="Сначала сохраните «Напрямую» или «Авто», потом включите «Локально».";return;}
                await client.Call<GameUdpStatus>("gameudp.set",new{profile_id=p.Id,enabled=true,local_only=true},ct);
                Notice="Включён локальный режим без VPS для новых подключений. Старые соединения сохраняют маршрут; успешный вход в матч ещё нужно проверить.";Close(true);return;
            }
            if(g.Mode=="MANUAL"){
                var status=await client.Call<Snapshot>("status",cancellationToken:ct);
                var relay=status.Routes.FirstOrDefault(r=>r.Id!="DIRECT"&&r.Status is "healthy" or "degraded"&&(g.RelayId is null||r.Id==g.RelayId));
                if(relay is null){Notice="Сервер VELIQ сейчас недоступен, маршрут не изменён.";return;}p.RelayId=relay.Id;
            }else p.RelayId=null;
            p.Mode=g.Mode;
            await client.Call<Profile[]>("profile.set",p,ct);
            if((g.Mode=="DIRECT"||g.Mode=="AUTO")&&g.Definition.UdpPreset.Length>0&&g.Profile is not null)await client.Call<GameUdpStatus>("gameudp.set",new{profile_id=p.Id,enabled=false},ct);
            g.Profile=p;Notice=p.Mode=="MANUAL"?"Игра пойдёт через сервер VELIQ. Если её серверы доступны напрямую, пинг может вырасти.":"Маршрут сохранён и сработает при следующем запуске игры.";Close(true);
        }catch(Exception e){Failed?.Invoke(e,"gamecatalog.apply");Notice="Маршрут не сохранён: "+FailureText(e);}finally{Busy=false;}
    }
    public async Task RepairLauncherAsync(GameCard g,CancellationToken ct=default){
        if(!g.CanRepair||Busy)return;Busy=true;
        try {var profiles=await client.Call<Profile[]>("profiles",cancellationToken:ct);var p=profiles.FirstOrDefault(p=>p.Id=="riot-client")?.Copy();if(p is null){Notice="Обновите VELIQ, чтобы починить запуск Riot Client.";return;}p.Mode="AUTO";p.RelayId=null;await client.Call<Profile[]>("profile.set",p,ct);Notice="Riot Client теперь подключается через VELIQ. Настройки игры и античит не тронуты.";}catch(Exception e){Failed?.Invoke(e,"gamecatalog.launcher");Notice="Не удалось настроить лаунчер: "+FailureText(e);}finally{Busy=false;}
    }
}
