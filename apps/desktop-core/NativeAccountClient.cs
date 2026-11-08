using System.Net;
using System.Net.Http;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Neexitlag.Desktop;

public sealed class NativeAccountException(string code) : Exception(code)
{
    public string Code { get; } = code;
    public string UserMessage => Code switch {
        "ACCOUNT_SESSION_SAVE_FAILED" => "Вы вошли в кабинет, но сохранить вход на этом ПК не удалось.",
        "EMAIL_INVALID" => "Проверьте адрес электронной почты.",
        "LOGIN_CODE_INVALID" => "Код неверный или устарел. Попробуйте ещё раз.",
        "ACCOUNT_RATE_LIMIT" => "Слишком много попыток. Попробуйте через несколько минут.",
        "MAIL_UNAVAILABLE" or "MAIL_NOT_CONFIGURED" => "Не удалось отправить письмо. Попробуйте позже.",
        "ACCOUNT_LINK_EXPIRED" => "Время подключения истекло. Начните вход заново.",
        "ACCOUNT_LOGIN_REQUIRED" => "Подтвердите почту ещё раз.",
        "ACCOUNT_DISABLED" => "Доступ к аккаунту ограничен. Обратитесь в поддержку.",
        "ACCOUNT_SUBSCRIPTION_REQUIRED" or "SUBSCRIPTION_EXPIRED" => "Нет действующей подписки для подключения.",
        "ACTIVATION_LIMIT" => "В подписке нет свободного места для этого компьютера.",
        "ACCOUNT_DEVICE_ALREADY_OWNED" => "Этот компьютер уже подключён к другому аккаунту.",
        "ACCOUNT_PROFILE_CONFLICT" => "Тип аккаунта не подходит для личного компьютера.",
        "ACCOUNT_PROFILE_INVALID" => "Проверьте имя: не более 80 символов.",
        "ACCOUNT_DEVICE_INVALID" or "SEAT_NOT_FOUND" => "Компьютер уже отключён или недоступен этому аккаунту. Обновите список.",
        "CLUB_ENROLLMENT_CLOSED" => "Набор компьютеров клуба закрыт. Обратитесь в поддержку для замены или добавления ПК.",
        "ACCOUNT_ORIGIN_REJECTED" or "ACCOUNT_NOT_CONFIGURED" => "Сервис входа пока недоступен.",
        _ => "Не удалось подключиться. Проверьте интернет и повторите попытку."
    };
}

public sealed class NativeSubscription
{
    public string Id { get; set; } = "";
    public string Kind { get; set; } = "";
    public int Seats { get; set; }
    public int UsedSeats { get; set; }
    public bool CanConnect { get; set; }
    public bool Lifetime { get; set; }
    public DateTimeOffset? PaidUntil { get; set; }
    public List<NativeAccountDevice> Devices { get; set; } = [];
    public string Label => (Kind == "club" ? "Клубная подписка" : "Личная подписка") + $" · подключено ПК: {UsedSeats}";
    public string AccessLabel => Lifetime ? "Бессрочно" : PaidUntil is {} date ? "Оплачено до " + date.ToLocalTime().ToString("dd.MM.yyyy") : "Нет оплаченного периода";
    public string SeatsLabel => Kind == "club" ? $"Компьютеры: {UsedSeats} из {Seats}" : $"Подключено компьютеров: {UsedSeats}";
    public string ConnectionLabel => CanConnect ? "Подключение новых компьютеров доступно" : "Подключение новых компьютеров недоступно — проверьте подписку или обратитесь в поддержку";
}
public sealed class NativeAccountDevice
{
    public string Name { get; set; } = "";
    public string Machine { get; set; } = "";
    public DateTimeOffset? LastSeen { get; set; }
    public string LastSeenLabel => LastSeen is {} date ? "Был в сети: " + date.ToLocalTime().ToString("dd.MM.yyyy HH:mm") : "Время подключения неизвестно";
}
public sealed class NativeAccountPayment
{
    public string Id { get; set; } = "";
    public string Status { get; set; } = "";
    public long AmountKopecks { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string Summary => CreatedAt.ToLocalTime().ToString("dd.MM.yyyy") + " · " + (AmountKopecks / 100m).ToString("N2", System.Globalization.CultureInfo.GetCultureInfo("ru-RU")) + " ₽ · " + (Status switch { "paid" => "Оплачен", "pending" => "Ожидает оплаты", "failed" => "Не выполнен", "refunded" => "Возврат", _ => "Статус уточняется" });
}
public sealed class NativeAccountSnapshot
{
    public string Email { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Name { get; set; } = "";
    public List<NativeSubscription> Subscriptions { get; set; } = [];
    public List<NativeAccountPayment> Payments { get; set; } = [];
    public bool PaymentsEnabled { get; set; }
    public string RoleLabel => Kind == "club" ? "Клуб" : Kind == "player" ? "Пользователь" : "Завершите регистрацию";
}
public interface INativeCabinetClient : INativeAccountClient
{
    Task<NativeAccountSnapshot> CreateProfileAsync(string kind, string name, CancellationToken ct);
    Task ReleaseDeviceAsync(string subscription, string machine, CancellationToken ct);
    Task ApproveDeviceAsync(Uri verification, string subscription, CancellationToken ct);
}
public sealed class NativeDeviceLink
{
    public string Name { get; set; } = "";
    public string Mode { get; set; } = "";
    public bool Approved { get; set; }
}
public interface INativeAccountClient : IDisposable
{
    Task SendCodeAsync(string email, CancellationToken ct);
    Task<NativeAccountSnapshot> VerifyAsync(string email, string code, CancellationToken ct);
    Task<NativeAccountSnapshot> CreatePersonalProfileAsync(string name, CancellationToken ct);
    Task<NativeAccountSnapshot> RefreshAsync(CancellationToken ct);
    Task<NativeDeviceLink> DeviceAsync(CancellationToken ct);
    Task ApproveAsync(string subscription, CancellationToken ct);
    Task LogoutAsync(CancellationToken ct);
}

// The desktop can supply an origin-scoped jar for a remembered personal login.
// Device identity stays in the service and is never a cabinet credential.
public sealed class NativeAccountClient : INativeCabinetClient
{
    const int MaxBody = 1024 * 1024;
    static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower, PropertyNameCaseInsensitive = true };
    readonly HttpClient http;
    readonly Uri origin;
    string link;
    NativeAccountSnapshot? account;
    public NativeAccountClient(Uri verification, HttpMessageHandler? handler = null, CookieContainer? cookies = null) : this(verification, true, handler, cookies) { }
    public static NativeAccountClient ForCabinet(Uri cabinet, HttpMessageHandler? handler = null, CookieContainer? cookies = null) => new(cabinet, false, handler, cookies);
    NativeAccountClient(Uri verification, bool deviceLink, HttpMessageHandler? handler, CookieContainer? cookies)
    {
        if (!verification.IsAbsoluteUri || verification.Scheme != "https" || verification.UserInfo.Length != 0 || verification.Query.Length != 0 ||
            verification.AbsolutePath is not ("/account.html" or "/account") || (deviceLink ? !Regex.IsMatch(verification.Fragment, "^#device=[a-f0-9]{32}$") : verification.Fragment.Length != 0))
            throw new NativeAccountException("ACCOUNT_LINK_INVALID");
        origin = new Uri(verification.GetLeftPart(UriPartial.Authority));
        link = deviceLink ? verification.Fragment[8..] : "";
        http = new HttpClient(handler ?? new HttpClientHandler { AllowAutoRedirect = false, UseCookies = true, CookieContainer = cookies ?? new CookieContainer() }) { Timeout = TimeSpan.FromSeconds(25) };
    }
    public static string NormalizeEmail(string value)
    {
        string email = value.Trim().ToLowerInvariant();
        if (email.Length > 254 || !MailAddress.TryCreate(email, out var address) || address.Address != email || address.DisplayName.Length != 0 || !address.Host.Contains('.'))
            throw new NativeAccountException("EMAIL_INVALID");
        return email;
    }
    static bool IsId(string? value) => value is not null && Regex.IsMatch(value, "^[a-f0-9]{32}$");
    async Task<JsonDocument> Request(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, new Uri(origin, "/api/v1/account" + path));
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.TryAddWithoutValidation("Origin", origin.GetLeftPart(UriPartial.Authority));
        if (method != HttpMethod.Get) request.Content = new StringContent(JsonSerializer.Serialize(body ?? new { }, Json), Encoding.UTF8, "application/json");
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        // No credential-bearing redirect, even to another path on the same host.
        if ((int)response.StatusCode is >= 300 and < 400) throw new NativeAccountException("ACCOUNT_ORIGIN_REJECTED");
        if (response.Content.Headers.ContentLength > MaxBody) throw new NativeAccountException("ACCOUNT_UNAVAILABLE");
        using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[8192];
        int count;
        while ((count = await stream.ReadAsync(chunk, ct)) != 0)
        {
            if (buffer.Length + count > MaxBody) throw new NativeAccountException("ACCOUNT_UNAVAILABLE");
            buffer.Write(chunk, 0, count);
        }
        JsonDocument data;
        try { data = JsonDocument.Parse(buffer.ToArray()); }
        catch (JsonException) { throw new NativeAccountException("ACCOUNT_UNAVAILABLE"); }
        if (data.RootElement.ValueKind != JsonValueKind.Object) { data.Dispose(); throw new NativeAccountException("ACCOUNT_UNAVAILABLE"); }
        if (!response.IsSuccessStatusCode)
        {
            string code = data.RootElement.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String ? error.GetString() ?? "" : "";
            data.Dispose();
            // Symbolic errors only; no response text or personal data reaches UI.
            if (!Regex.IsMatch(code, "^[A-Z_]{3,64}$")) code = "ACCOUNT_UNAVAILABLE";
            throw new NativeAccountException(code);
        }
        return data;
    }
    public async Task SendCodeAsync(string email, CancellationToken ct)
    {
        using var data = await Request(HttpMethod.Post, "/login/start", new { email = NormalizeEmail(email) }, ct);
        if (!data.RootElement.TryGetProperty("status", out var status) || status.GetString() != "sent") throw new NativeAccountException("MAIL_UNAVAILABLE");
    }
    public async Task<NativeAccountSnapshot> VerifyAsync(string email, string code, CancellationToken ct)
    {
        email = NormalizeEmail(email);
        if (!Regex.IsMatch(code, "^[0-9]{6}$")) throw new NativeAccountException("LOGIN_CODE_INVALID");
        using var data = await Request(HttpMethod.Post, "/login/verify", new { email, code }, ct);
        return await RefreshAsync(ct);
    }
    public async Task<NativeAccountSnapshot> RefreshAsync(CancellationToken ct)
    {
        using var data = await Request(HttpMethod.Get, "", null, ct);
        NativeAccountSnapshot result;
        try { result = data.Deserialize<NativeAccountSnapshot>(Json) ?? throw new NativeAccountException("ACCOUNT_UNAVAILABLE"); }
        catch (JsonException) { throw new NativeAccountException("ACCOUNT_UNAVAILABLE"); }
        if (result.Kind is not ("" or "player" or "club") || result.Email is null || result.Name is null || result.Subscriptions is null || result.Subscriptions.Count > 512 || result.Subscriptions.Any(s => s is null || !IsId(s.Id) || s.Kind is not ("player" or "club") || s.Devices is null || s.Devices.Count > 2048 || s.Devices.Any(d => d is null || d.Name is null || d.Machine is null || !Regex.IsMatch(d.Machine, "^[a-f0-9]{12,64}$"))) || result.Subscriptions.Sum(s => s.Devices.Count) > 4096 || result.Payments is null || result.Payments.Count > 512 || result.Payments.Any(p => p is null))
            throw new NativeAccountException("ACCOUNT_UNAVAILABLE");
        account = result;
        return result;
    }
    public async Task<NativeAccountSnapshot> CreatePersonalProfileAsync(string name, CancellationToken ct)
    {
        if (account is null || account.Kind != "") throw new NativeAccountException("ACCOUNT_PROFILE_CONFLICT");
        name = name.Trim();
        if (name.Length > 80 || name.Any(char.IsControl)) throw new NativeAccountException("ACCOUNT_PROFILE_INVALID");
        using var data = await Request(HttpMethod.Post, "/profile", new { kind = "player", name }, ct);
        return await RefreshAsync(ct);
    }
    public async Task<NativeDeviceLink> DeviceAsync(CancellationToken ct)
    {
        if (!IsId(link)) throw new NativeAccountException("ACCOUNT_LINK_INVALID");
        using var data = await Request(HttpMethod.Get, "/device-links/" + link, null, ct);
        return data.Deserialize<NativeDeviceLink>(Json) ?? throw new NativeAccountException("ACCOUNT_LINK_INVALID");
    }
    public async Task<NativeAccountSnapshot> CreateProfileAsync(string kind, string name, CancellationToken ct)
    {
        await RefreshAsync(ct);
        if (account!.Kind != "" || kind is not ("player" or "club")) throw new NativeAccountException("ACCOUNT_PROFILE_CONFLICT");
        name = name.Trim();
        if (name.Length > 80 || name.Any(char.IsControl) || kind == "club" && name.Length < 2) throw new NativeAccountException("ACCOUNT_PROFILE_INVALID");
        using var data = await Request(HttpMethod.Post, "/profile", new { kind, name }, ct);
        return await RefreshAsync(ct);
    }
    public async Task ReleaseDeviceAsync(string subscription, string machine, CancellationToken ct)
    {
        if (!IsId(subscription) || !Regex.IsMatch(machine, "^[a-f0-9]{12,64}$")) throw new NativeAccountException("ACCOUNT_DEVICE_INVALID");
        var fresh = await RefreshAsync(ct);
        if (!fresh.Subscriptions.Any(s => s.Id == subscription && s.Devices.Any(d => d.Machine == machine))) throw new NativeAccountException("ACCOUNT_DEVICE_INVALID");
        using var data = await Request(HttpMethod.Post, "/subscriptions/" + subscription + "/devices/" + machine + "/release", null, ct);
        if (!data.RootElement.TryGetProperty("status", out var status) || status.GetString() != "released") throw new NativeAccountException("ACCOUNT_UNAVAILABLE");
    }
    public async Task ApproveDeviceAsync(Uri verification, string subscription, CancellationToken ct)
    {
        if (!verification.IsAbsoluteUri || verification.GetLeftPart(UriPartial.Authority) != origin.GetLeftPart(UriPartial.Authority) || verification.UserInfo.Length != 0 || verification.Query.Length != 0 || verification.AbsolutePath is not ("/account" or "/account.html") || !Regex.IsMatch(verification.Fragment, "^#device=[a-f0-9]{32}$")) throw new NativeAccountException("ACCOUNT_LINK_INVALID");
        var fresh = await RefreshAsync(ct);
        if (!fresh.Subscriptions.Any(s => s.Id == subscription && s.Kind == fresh.Kind && s.CanConnect)) throw new NativeAccountException("ACCOUNT_SUBSCRIPTION_REQUIRED");
        link = verification.Fragment[8..];
        var device = await DeviceAsync(ct);
        if (device.Mode is not ("device" or "image") || device.Mode == "image" && fresh.Kind != "club") throw new NativeAccountException("ACCOUNT_LINK_INVALID");
        using var data = await Request(HttpMethod.Post, "/device-links/" + link + "/approve", new { subscription_id = subscription }, ct);
        if (!data.RootElement.TryGetProperty("state", out var state) || state.GetString() != "APPROVED") throw new NativeAccountException("ACCOUNT_LINK_INVALID");
    }
    public async Task ApproveAsync(string subscription, CancellationToken ct)
    {
        // Re-fetch permissions before confirmation. Server still checks ownership,
        // expiry, seat capacity and the signed service/device request atomically.
        await RefreshAsync(ct);
        if (account!.Kind != "player" || !account.Subscriptions.Any(s => s.Id == subscription && s.Kind == "player" && s.CanConnect))
            throw new NativeAccountException("ACCOUNT_SUBSCRIPTION_REQUIRED");
        if ((await DeviceAsync(ct)).Mode != "device") throw new NativeAccountException("ACCOUNT_LINK_INVALID");
        using var data = await Request(HttpMethod.Post, "/device-links/" + link + "/approve", new { subscription_id = subscription }, ct);
        if (!data.RootElement.TryGetProperty("state", out var state) || state.GetString() != "APPROVED") throw new NativeAccountException("ACCOUNT_LINK_INVALID");
    }
    public async Task LogoutAsync(CancellationToken ct) { using var data = await Request(HttpMethod.Post, "/logout", null, ct); account = null; }
    public void Dispose() { account = null; http.Dispose(); }
}
