namespace Neexitlag.Desktop;

public sealed record UpdateSnapshot
{
    public string State { get; set; } = "";
    public ulong AvailableBuild { get; set; }
    public string AvailableVersion { get; set; } = "";
    public long DownloadedBytes { get; set; }
    public long TotalBytes { get; set; }
}

public sealed partial class DesktopViewModel
{
    UpdateSnapshot update = new();
    bool updateAction;
    string updateMessage = "";
    public bool ShowUpdate => update.State is "DOWNLOADING" or "READY" or "INSTALLING" or "DOWNLOAD_FAILED" or "CHECK_FAILED" or "INSTALL_FAILED";
    public bool UpdateDownloading => update.State == "DOWNLOADING";
    public bool CanUpdate => Available && !updateAction && update.State is ("READY" or "DOWNLOAD_FAILED" or "CHECK_FAILED" or "INSTALL_FAILED");
    public double UpdatePercent => update.TotalBytes > 0 ? Math.Clamp(100d * update.DownloadedBytes / update.TotalBytes, 0, 100) : 0;
    public string UpdateTooltip => updateMessage.Length > 0 ? updateMessage : update.State switch
    {
        "DOWNLOADING" => string.Format(Text.Russian, Text.Get("UpdateDownloadingHint"), UpdatePercent),
        "READY" => string.Format(Text.Russian, Text.Get("UpdateReadyHint"), update.AvailableVersion),
        "INSTALLING" => Text.Get("UpdateInstallingHint"),
        "INSTALL_FAILED" => Text.Get("UpdateInstallFailedHint"),
        _ => Text.Get("UpdateDownloadFailedHint")
    };
    public string UpdateArc
    {
        get
        {
            var percent = Math.Clamp(UpdatePercent, 0.01, 99.99);
            var angle = percent / 100 * Math.PI * 2;
            return FormattableString.Invariant($"M 18,3 A 15,15 0 {(percent > 50 ? 1 : 0)} 1 {18 + 15 * Math.Sin(angle)},{18 - 15 * Math.Cos(angle)}");
        }
    }
    public void ApplyUpdate(UpdateSnapshot value)
    {
        if (update == value) return;
        if (update.State != value.State) updateMessage = "";
        update = value with { };
        UpdateChanged();
    }
    void UpdateChanged()
    {
        foreach (var name in new[] { nameof(ShowUpdate), nameof(UpdateDownloading), nameof(CanUpdate), nameof(UpdatePercent), nameof(UpdateTooltip), nameof(UpdateArc) }) Changed(name);
    }
    async Task RefreshUpdateAsync(CancellationToken ct)
    {
        try { ApplyUpdate(await client.Call<UpdateSnapshot>("update.status", cancellationToken: ct)); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { ApplyUpdate(new()); } // Older services must remain usable.
    }
    public async Task ApplyUpdateAsync(CancellationToken ct = default)
    {
        if (!CanUpdate) return;
        updateAction = true; updateMessage = ""; UpdateChanged();
        try
        {
            var method = update.State is "READY" or "INSTALL_FAILED" ? "update.install" : "update.retry";
            ApplyUpdate(await client.Call<UpdateSnapshot>(method, new { build = update.AvailableBuild }, ct));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch { updateMessage = Text.Get("UpdateActionFailedHint"); }
        finally { updateAction = false; UpdateChanged(); }
    }
}
