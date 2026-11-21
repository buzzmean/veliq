namespace Neexitlag.Desktop;

public sealed partial class DesktopViewModel
{
    // Keep the decision before the mutation: No must leave service/profile/UI
    // state untouched, including an application's existing DIRECT route.
    public async Task<bool> SetProfileWithRelayWarningAsync(Profile original, string mode, string? relay,
        Func<Task<bool>> confirmRelay, CancellationToken ct = default)
    {
        if (mode == "MANUAL" && !await confirmRelay()) return false;
        return await SetProfileAsync(original, mode, relay, ct);
    }
}
