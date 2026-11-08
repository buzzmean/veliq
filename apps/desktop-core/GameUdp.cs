using System.Collections.ObjectModel;
namespace Neexitlag.Desktop;

public sealed class GameUdpStatus
{
    public GameUdpProfile[] Profiles { get; set; } = [];
    public GameUdpGuard Guard { get; set; } = new();
    public string Error { get; set; } = "";
}
public sealed class GameUdpGuard { public string DriverAntiCheat {get;set;}=""; public string Error {get;set;}=""; public bool Conflict {get;set;} }
public sealed class GameUdpProfile
{
    public string ProfileId {get;set;}="";
    public bool Ready {get;set;}
    public string Activity {get;set;}="";
    public string Name {get;set;}="";
    public string State {get;set;}="";
    public string Reason {get;set;}="";
    public string AntiCheat {get;set;}="";
    public GameUdpEngine Engine {get;set;}=new();
    public string ButtonLabel=>Engine.Enabled?"Выключить UDP-обход":"Включить UDP-обход";
    public string Summary {
        get {
            if (!Engine.Enabled) return "Игровой UDP-обход выключен. Обычный маршрут приложения сохранён.";
            if(Engine.LocalOnly && Engine.Flows.Any(f=>f.Stage=="RELAY" && f.LastOutgoing!=default && DateTimeOffset.UtcNow-f.LastOutgoing<TimeSpan.FromSeconds(5)))return "Локальный режим выбран для новых подключений. Старый поток ещё идёт через VPS; переподключитесь к игровому серверу для проверки без VPS.";
            if (Reason!="") return "UDP-обход приостановлен: "+GameUdpMessages.Reason(Reason);
            var f=Engine.Flows.OrderByDescending(f=>f.FlowId).FirstOrDefault();
            if(f is null && Engine.LocalOnly)return "Готов для новых UDP-потоков: DIRECT → локальный обход. VPS запрещён; вход в матч ещё не проверен.";
            if(f is null)return Engine.InitialPolicy=="LOCAL_FIRST_UNCONFIRMED_ENDPOINT"
                ? "Обход включён для новых потоков · локальная приманка K12/N2. Ожидаем игровой UDP-трафик."
                : "Готов для новых UDP-потоков: DIRECT → локальный обход → релей.";
            if(f.State is "INSUFFICIENT_REPLIES" or "CADENCE_PROBATION")return f.Stage+" · "+f.Destination+" · устойчивых ответов нет. Следующая попытка — при новом подключении.";
            if(f.LastOutgoing!=default && DateTimeOffset.UtcNow-f.LastOutgoing>TimeSpan.FromSeconds(5))return "Свежий игровой трафик не наблюдается. Последний маршрут: "+f.Stage;
            if(f.State=="LOCAL_PRIMING_INCOMPLETE")return "Приманка отправлена не полностью · "+GameUdpMessages.Reason(f.Reason);
            if(f.Reason=="EXISTING_UDP_PINNED_DIRECT_NO_FIRST_FLIGHT_PROOF")return GameUdpMessages.Reason(f.Reason);
            if(f.State=="TRANSPORT_FAILED")return "Игровой поток: "+GameUdpMessages.Reason(f.Reason);
            if(f.LastOutgoing!=default && (f.LastReply==default || DateTimeOffset.UtcNow-f.LastReply>TimeSpan.FromSeconds(5)))return f.Stage+" · "+f.Destination+" · свежих ответов сервера не наблюдается; вход в матч не подтверждён.";
            return f.Stage switch {
                "LOCAL_UDP" when f.FakePackets>0=>"Локальная попытка · "+f.Destination+" · приманок: "+f.FakePackets+" · ответов: "+f.InboundPackets,
                "LOCAL_UDP"=>"Приманка не отправлена · "+GameUdpMessages.Reason(f.Reason),
                "RELAY"=>"Игровой поток через релей · "+f.Destination+" · ответов: "+f.InboundPackets,
                _=>"DIRECT · "+f.Destination+" · ответов: "+f.InboundPackets
            };
        }
    }
}
public sealed class GameUdpEngine { public bool LocalOnly {get;set;} public string InitialPolicy {get;set;}=""; public bool Enabled {get;set;} public GameUdpFlow[] Flows {get;set;}=[]; }
public sealed class GameUdpFlow {
    public DateTimeOffset LastOutgoing {get;set;} public DateTimeOffset LastReply {get;set;}
    public string SelectionReason {get;set;}="";public ulong FlowId {get;set;} public string Stage {get;set;}="";public string Destination {get;set;}="";
    public ulong FakePackets {get;set;} public ulong FakeBytes {get;set;} public ulong OutgoingPackets {get;set;} public ulong InboundPackets {get;set;} public string State {get;set;}=""; public string Reason {get;set;}="";
}
public static class GameUdpMessages {
    public static string Reason(string code)=>code switch {
        "DISABLED_BY_USER"=>"режим выключен",
        "GAME_UDP_LOCAL_ONLY_EXHAUSTED"=>"локальные варианты исчерпаны; VPS запрещён, новые потоки остаются DIRECT до следующего окна подбора",
        "OPTIMIZATION_DISABLED"=>"оптимизация выключена",
        "GAME_RELAY_OPEN_FAILED"=>"не удалось открыть релей; DIRECT-подмены нет",
        "GAME_RELAY_TRANSPORT_FAILED"=>"соединение с релеем потеряно; DIRECT-подмены нет",
        "GAME_UDP_LADDER_EXHAUSTED"=>"варианты исчерпаны; ждём следующего окна подбора",
        "GAME_PROFILE_OVERRIDDEN_OR_REMOVED"=>"обычная политика профиля имеет приоритет",
        "UDP_CONFLICT_CHECK_PENDING"=>"проверяем другие сетевые перехватчики",
        "UDP_CONFLICT_DETECTOR_UNAVAILABLE"=>"не удалось безопасно проверить сетевые перехватчики",
        "GAME_UDP_CONFIG_INVALID"=>"настройки режима повреждены; приманки отключены",
        "ACTIVATION_REQUIRED"=>"нужна активация",
        "CAPTURE_NOT_READY"=>"сетевой перехват ещё не готов",
        "EXTERNAL_VPN_ACTIVE"=>"обнаружен внешний VPN",
        "FOREIGN_UDP_INTERCEPTOR" or "FOREIGN_UDP_INTERCEPTOR_OR_OBSERVER_PENDING"=>"работает другой сетевой перехватчик; двойная обработка отключена",
        "GAME_UDP_ANTICHEAT_COMPATIBILITY_UNVERIFIED" or "DRIVER_ANTICHEAT_COMPATIBILITY_UNVERIFIED"=>"для этой игры активен или требуется Vanguard/FACEIT; совместимость не проверена",
        "GAME_PROCESS_CHECK_PENDING"=>"проверяем запущенные сетевые программы",
        "GAME_PROCESS_LIST_UNAVAILABLE" or "GAME_PROCESS_LIST_INCOMPLETE"=>"не удалось проверить другие сетевые программы",
        "UDP_REFLECT_OBSERVER_FAILED" or "UDP_REPLY_OBSERVER_FAILED" or "UDP_REFLECT_EVENT_INVALID" or "UDP_REFLECT_FILTER_BOUND" or "UDP_FOREIGN_HANDLE_LIMIT"=>"детектор сетевых конфликтов не готов; режим приостановлен",
        "GAME_NOT_DISCOVERED"=>"ищем установленную игру",
        "SUSTAINED_REPLY_NOT_OBSERVED"=>"ожидаем устойчивые ответы сервера",
        "DECOY_RATE_LIMITED_ORIGINAL_PASSTHROUGH" or "GLOBAL_DECOY_RATE_LIMITED"=>"достигнут лимит приманок; оригиналы проходят без задержки",
        "DECOY_SEND_FAILED_ORIGINAL_PASSTHROUGH"=>"не удалось отправить приманку; оригиналы проходят напрямую",
        "EXISTING_UDP_PINNED_DIRECT_NO_FIRST_FLIGHT_PROOF"=>"старый UDP-поток сохранён напрямую; обход начнётся со следующего подключения",
        "NETWORK_FINGERPRINT_PENDING"=>"проверяем текущую сеть",
        _=>code.Length<=80 && code.All(c=>c is >='A' and <='Z' or >='0' and <='9' or '_')?code:"сбой службы; подробности в диагностике"
    };
}
public sealed partial class DesktopViewModel {
    public ObservableCollection<GameUdpProfile> GameUdpProfiles {get;}=[];
    string? lastGameUdp;
    public void ApplyGameUdp(GameUdpStatus status){var wire=System.Text.Json.JsonSerializer.Serialize(status);if(wire==lastGameUdp)return;lastGameUdp=wire;GameUdpProfiles.Clear();foreach(var p in status.Profiles.OrderBy(p=>p.Name,StringComparer.CurrentCultureIgnoreCase))GameUdpProfiles.Add(p);}
    public async Task RefreshGamesAsync(CancellationToken ct=default)=>ApplyGameUdp(await client.Call<GameUdpStatus>("gameudp.status",cancellationToken:ct));
    public async Task SetGameUdpAsync(string profileId,bool enabled,CancellationToken ct=default){
        try {ApplyGameUdp(await client.Call<GameUdpStatus>("gameudp.set",new{profile_id=profileId,enabled,local_only=true},ct));Notice=enabled?"Локальный UDP-режим без VPS включён для новых потоков. Старые соединения сохраняют маршрут; вход в матч ещё нужно проверить.":"Игровой UDP-обход выключен.";}
        catch(ServiceException e){ReportAuxiliaryFailure(e,"gameudp.set");Notice="Не удалось изменить игровой UDP-обход: "+GameUdpMessages.Reason(e.Message);}
    }
}
public sealed partial class DesktopViewModel {
    public void ReportGameUdpSelectionRequired()=>Notice="Выберите игровой профиль с полным путём .exe. Для готовых Steam-профилей достаточно кнопки в разделе «Игровой UDP-обход».";
}
