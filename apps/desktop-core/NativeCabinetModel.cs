namespace Neexitlag.Desktop;

// Cabinet authentication is separate from machine activation. A club guest's
// service status never creates an owner session or administrator permission.
public sealed class NativeCabinetModel(Func<INativeCabinetClient> factory) : IDisposable
{
    INativeCabinetClient? api;
    CancellationTokenSource? session;
    int generation;
    bool disposed;
    public NativeAccountSnapshot? Account { get; private set; }
    public string Email { get; private set; } = "";
    public bool CodeSent { get; private set; }
    public Task ResumeAsync(CancellationToken ct)
    {
        Reset();
        ObjectDisposedException.ThrowIf(disposed, this);
        api = factory(); session = new();
        return RefreshAsync(ct);
    }
    public async Task SendCodeAsync(string email, CancellationToken ct = default)
    {
        string normalized = NativeAccountClient.NormalizeEmail(email);
        Reset();
        ObjectDisposedException.ThrowIf(disposed, this);
        api = factory(); session = new(); Email = normalized;
        int epoch = generation; var current = api;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, session.Token);
        await current.SendCodeAsync(normalized, linked.Token);
        if (epoch == generation) CodeSent = true;
    }
    public async Task VerifyAsync(string code, CancellationToken ct = default)
    {
        if (!CodeSent) throw new NativeAccountException("ACCOUNT_LOGIN_REQUIRED");
        await UpdateAsync((current, token) => current.VerifyAsync(Email, code, token), ct);
    }
    public Task RefreshAsync(CancellationToken ct = default) => UpdateAsync((current, token) => current.RefreshAsync(token), ct);
    public Task CreateProfileAsync(string kind, string name, CancellationToken ct = default) => UpdateAsync((current, token) => current.CreateProfileAsync(kind, name, token), ct);
    public Task ReleaseAsync(string subscription, string machine, CancellationToken ct = default) => UpdateAsync(async (current, token) => { await current.ReleaseDeviceAsync(subscription, machine, token); return await current.RefreshAsync(token); }, ct);
    public Task ApproveAsync(Uri verification, string subscription, CancellationToken ct = default) => UpdateAsync(async (current, token) => { await current.ApproveDeviceAsync(verification, subscription, token); return await current.RefreshAsync(token); }, ct);
    async Task UpdateAsync(Func<INativeCabinetClient, CancellationToken, Task<NativeAccountSnapshot>> action, CancellationToken ct)
    {
        if (disposed || api is null || session is null) throw new NativeAccountException("ACCOUNT_LOGIN_REQUIRED");
        int epoch = generation;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, session.Token);
        try
        {
            var result = await action(api, linked.Token);
            if (!disposed && epoch == generation) Account = result;
        }
        catch
        {
            if (epoch == generation) Account = null; // No stale access after failed revalidation.
            throw;
        }
    }
    public async Task LogoutAsync(CancellationToken ct = default)
    {
        var previous = api;
        Reset(false); // Clear the UI and cancel old reads before network logout.
        if (previous is null) return;
        try { await previous.LogoutAsync(ct); }
        finally { previous.Dispose(); }
    }
    public void Reset() => Reset(true);
    void Reset(bool dispose)
    {
        generation++;
        session?.Cancel(); session?.Dispose(); session = null;
        if (dispose) api?.Dispose();
        api = null; Account = null; Email = ""; CodeSent = false;
    }
    public void Dispose() { disposed = true; Reset(); }
}
