using System.Collections.ObjectModel;

namespace Veliq.Desktop;

public sealed partial class DesktopViewModel
{
    public ObservableCollection<ApplicationRow> ActiveServices { get; } = [];
    public IEnumerable<ApplicationRow> ServiceApplications => ShowTechnical ? Applications : ActiveServices;
    public bool HasVisibleServices => ServiceApplications.Any();
    public bool NoActiveServices => !HasVisibleServices;

    void NotifyVisibleServices()
    {
        Changed(nameof(HasVisibleServices));
        Changed(nameof(NoActiveServices));
    }

    void UpdateServiceApplications(Snapshot status, ProcessIdentity[]? processes, CaptureEvidence? capture)
    {
        var visibleBefore = HasVisibleServices;
        var rows = new List<ApplicationRow>();
        if (status.Optimizing)
        {
            rows.AddRange(Applications.Where(row => row.HasAppliedStrategy));
            // Автообнаруженные приложения могут ещё не иметь сохранённого профиля.
            // Строка создаётся только из подтверждённого владельца реального потока.
            foreach (var group in (capture?.Flows ?? []).Where(f => f.IdentityCurrent && f.Pid != 0 &&
                         f.CreationTime != 0 && f.ProcessGroup.Length > 0 && f.Exe.Length > 0 &&
                         !status.Profiles.Any(p => p.Id == f.ProcessGroup)).GroupBy(f => f.ProcessGroup))
            {
                var row = ActiveServices.FirstOrDefault(a => a.Profile.Id == group.Key) ?? new ApplicationRow();
                var images = group.Select(f => f.Exe).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                var name = images[0].Replace('\\', '/').Split('/').Last();
                if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
                row.Update(new Profile { Id = group.Key, Name = name, Executables = images, Mode = "AUTO" }, processes, capture);
                if (row.HasAppliedStrategy) rows.Add(row);
            }
        }
        Replace(ActiveServices, rows.OrderBy(row => row.Name, StringComparer.CurrentCultureIgnoreCase));
        if (visibleBefore != HasVisibleServices) NotifyVisibleServices();
    }
}
