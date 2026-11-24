using System.Text;
namespace Neexitlag.Desktop;
// «Диагностика» for people: one verdict, four plain rows and a report file for support.
// Everything technical stays in the hidden «Технические детали» view and in the report.
public sealed record HealthRow(string Name, string State, HealthLevel Level);
public enum HealthLevel { Ok, Neutral, Warning, Problem }
public sealed partial class DesktopViewModel
{
    bool showTechnical;
    public bool ShowTechnical { get => showTechnical; set { if (Set(ref showTechnical, value)) { Changed(nameof(ServiceApplications)); NotifyVisibleServices(); } } }
    string healthKey = "";
    // Polling repeats identical snapshots; notify only when the verdict really changes.
    void HealthChanged()
    {
        var key = string.Join("|", Health.Select(r => r.Name + ":" + r.State));
        if (key == healthKey) return;
        healthKey = key; Changed(nameof(Health)); Changed(nameof(HealthTitle)); Changed(nameof(HealthAdvice)); Changed(nameof(HealthLevel));
    }
    public HealthRow[] Health
    {
        get
        {
            if (!Available) return [new("Служба VELIQ", "не отвечает", HealthLevel.Problem)];
            var s = Snapshot;
            var network = !Optimizing ? new HealthRow("Работа на этом ПК", "VELIQ выключен", HealthLevel.Neutral)
                : s?.Backend.Ready == true ? new("Работа на этом ПК", "в порядке", HealthLevel.Ok) : new("Работа на этом ПК", "не запустилась", HealthLevel.Problem);
            var relays = s?.Routes.Where(r => r.Id != "DIRECT").ToArray() ?? [];
            var servers = relays.Any(Fresh) ? new HealthRow("Серверы VELIQ", "в порядке", HealthLevel.Ok)
                : relays.Length == 0 && !Optimizing ? new("Серверы VELIQ", "VELIQ выключен", HealthLevel.Neutral) : new("Серверы VELIQ", "недоступны", HealthLevel.Warning);
            HealthRow[] browsers = !Optimizing ? [new("Браузеры", "обычная сеть", HealthLevel.Neutral)]
                : browserHealth.Length == 0 ? [new("Браузеры", "автоматическая маршрутизация не настроена", HealthLevel.Neutral)] : browserHealth;
            return [new("Служба VELIQ", "в порядке", HealthLevel.Ok), network, servers, .. browsers];
        }
    }
    public HealthLevel HealthLevel => Health.Any(r => r.Level == HealthLevel.Problem) ? HealthLevel.Problem : Health.Any(r => r.Level == HealthLevel.Warning) ? HealthLevel.Warning : HealthLevel.Ok;
    public string HealthTitle => HealthLevel switch { HealthLevel.Problem => "Есть проблема", HealthLevel.Warning => "Работает, но не всё", _ => "Всё работает" };
    public string HealthAdvice => Health.FirstOrDefault(r => r.Level == HealthLevel.Problem || r.Level == HealthLevel.Warning) switch
    {
        { Name: "Служба VELIQ" } => "Перезапустите компьютер. Если не помогло, сохраните отчёт и отправьте его в поддержку.",
        { Name: "Работа на этом ПК" } => "Выключите и снова включите VELIQ на главной. Если не помогло, сохраните отчёт для поддержки.",
        { Name: "Серверы VELIQ" } => "Сайты, которым нужен сервер VELIQ, могут не открываться. Обычно это проходит само за пару минут.",
        _ => ""
    };
    // Plain text for support: the simple verdict first, then every technical detail the screens hide.
    public string SupportReport(string version)
    {
        var b = new StringBuilder();
        b.AppendLine($"VELIQ {version}, отчёт от {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        b.AppendLine($"Служба: {Connection}; состояние: {OptimizationStatus}");
        if (Error != "") b.AppendLine("Ошибка: " + Error);
        if (Notice != "") b.AppendLine("Сообщение: " + Notice);
        b.AppendLine().AppendLine(HealthTitle);
        foreach (var r in Health) b.AppendLine($"  {r.Name}: {r.State}");
        b.AppendLine().AppendLine("Проверки:");
        foreach (var r in Diagnostics) b.AppendLine($"  {r.Name} | {r.Status} | {r.Detail}");
        b.AppendLine().AppendLine("Маршруты:");
        foreach (var r in Routes) b.AppendLine($"  {r.Name} | {r.Status} | {r.Rtt} | {r.Jitter} | {r.Loss} | {r.Role}");
        b.AppendLine().AppendLine("Приложения:");
        foreach (var a in Applications) b.AppendLine($"  {a.Name} | {a.Mode} | {a.Path} | {a.ProcessStatus} | {a.UserStatus} | {a.LocalDetails}");
        b.AppendLine().AppendLine("Браузеры: " + BrowserReadinessText);
        return b.ToString();
    }
}
