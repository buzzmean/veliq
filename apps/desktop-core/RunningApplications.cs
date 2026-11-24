using System.Collections.ObjectModel;
namespace Veliq.Desktop;

public sealed class RunningApplication
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public uint Pid { get; set; }
    public ulong CreationTime { get; set; }
    public uint[] Pids { get; set; } = [];
    public int ProcessCount { get; set; }
    public string DisplayName { get; set; } = "";
    public object? Icon { get; set; }
    public string Title => string.IsNullOrWhiteSpace(DisplayName) ? System.IO.Path.GetFileNameWithoutExtension(Name) : DisplayName;
    public string ProcessSummary => string.Format(Text.Russian, Text.Get("RunningProcessCount"), ProcessCount);
    public string PidSummary => string.Join(", ", Pids) + (ProcessCount > Pids.Length ? " …" : "");
}
public sealed class RunningApplicationList
{
    public RunningApplication[] Applications { get; set; } = [];
    public bool Truncated { get; set; }
}

// The desktop only consumes the service's bounded, grouped metadata view. There
// is no Process.GetProcesses, process handle, memory read or independent scan.
public sealed class RunningApplicationsViewModel(IServiceClient client) : Observable
{
    RunningApplication[] all = [];
    string search = "", error = "";
    bool busy, truncated;
    public ObservableCollection<RunningApplication> Applications { get; } = [];
    public string Search { get => search; set { if (Set(ref search, value)) Filter(); } }
    public string Error { get => error; private set => Set(ref error, value); }
    public bool Busy { get => busy; private set { if (Set(ref busy, value)) Changed(nameof(CanRefresh)); } }
    public bool CanRefresh => !Busy;
    public bool Truncated { get => truncated; private set => Set(ref truncated, value); }
    public string Status => Busy ? Text.Get("RunningLoading") : Error.Length > 0 ? Error : Truncated ? Text.Get("RunningTruncated") : Applications.Count == 0 ? Text.Get("RunningEmpty") : "";
    public async Task RefreshAsync(CancellationToken ct = default, Func<RunningApplication[], Task>? enrich = null)
    {
        if (Busy) return;
        Busy = true; Error = ""; Changed(nameof(Status));
        try
        {
            var list = await client.Call<RunningApplicationList>("processes", new { applications = true, limit = 128 }, ct);
            all = list.Applications.Take(128).ToArray();
            if (enrich is not null) await enrich(all);
            ct.ThrowIfCancellationRequested();
            Truncated = list.Truncated;
            Filter();
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception e) { all = []; Filter(); Error = Text.Failure(e); }
        finally { Busy = false; Changed(nameof(Status)); }
    }
    void Filter()
    {
        var term = Search.Trim();
        var rows = all.Where(a => term.Length == 0 || a.Title.Contains(term, StringComparison.OrdinalIgnoreCase) || a.Name.Contains(term, StringComparison.OrdinalIgnoreCase) || a.Path.Contains(term, StringComparison.OrdinalIgnoreCase) || a.PidSummary.Contains(term, StringComparison.OrdinalIgnoreCase))
            .OrderBy(a => a.Title, StringComparer.CurrentCultureIgnoreCase).ThenBy(a => a.Path, StringComparer.OrdinalIgnoreCase).ToArray();
        Applications.Clear();
        foreach (var row in rows) Applications.Add(row);
        Changed(nameof(Status));
    }
}
