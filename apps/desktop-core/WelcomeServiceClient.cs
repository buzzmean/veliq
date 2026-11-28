namespace Veliq.Desktop;

// Onboarding reads must not keep the window busy for the sum of three IPC
// deadlines. A late reply belongs to the timed-out call, never to a new poll.
public sealed class WelcomeServiceClient(IServiceClient inner, TimeSpan? timeout = null) : IServiceClient
{
    readonly TimeSpan timeout = timeout ?? TimeSpan.FromSeconds(3);
    readonly object gate = new();
    readonly Dictionary<string, Task> pending = new();

    public async Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Personal sign-in starts a server-side approval session; retain its
        // existing deadline. Only activation submission and status reads use
        // the short onboarding deadline.
        if (method is not ("activation.set" or "activation.status" or "account.status" or "subscription.status" or "subscription.refresh"))
            return await inner.Call<T>(method, payload, cancellationToken);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        Task<T> request;
        lock (gate)
        {
            if (pending.TryGetValue(method, out var previous) && !previous.IsCompleted)
                throw new ServiceException(ServiceFailure.Unavailable);
            request = inner.Call<T>(method, payload, deadline.Token);
            pending[method] = request;
        }
        try { return await request.WaitAsync(deadline.Token); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new ServiceException(ServiceFailure.Unavailable); }
        finally
        {
            lock (gate)
                if (request.IsCompleted && pending.TryGetValue(method, out var current) && ReferenceEquals(current, request))
                    pending.Remove(method);
        }
    }
}
