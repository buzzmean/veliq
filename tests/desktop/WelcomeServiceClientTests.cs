using Veliq.Desktop;
using Xunit;
namespace Veliq.Tests;

public sealed class WelcomeServiceClientTests
{
    sealed class PersonalStart : IServiceClient
    {
        public async Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
        {
            await Task.Delay(50, cancellationToken);
            return (T)(object)new AccountConnectionView { State = "STARTING" };
        }
    }
    [Fact]
    public async Task PersonalApprovalCreationKeepsItsExistingDeadline()
    {
        var client = new WelcomeServiceClient(new PersonalStart(), TimeSpan.FromMilliseconds(1));
        var result = await client.Call<AccountConnectionView>("account.link.start").WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal("STARTING", result.State);
    }
    sealed class Delayed : IServiceClient
    {
        public readonly TaskCompletionSource<ActivationView> SetReply = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Sets, Reads;
        public bool Active;
        public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
        {
            if (method == "activation.set") { Interlocked.Increment(ref Sets); return (Task<T>)(object)SetReply.Task; }
            Interlocked.Increment(ref Reads);
            return Task.FromResult((T)(object)new ActivationView { State = Active ? "ACTIVATED" : "CODE_REQUIRED", HasIdentity = Active });
        }
    }
    [Fact]
    public async Task LostSetReplyDoesNotRequireCodeReplayOrOverwriteConfirmedActivation()
    {
        var service = new Delayed();
        var model = new ActivationModel(new WelcomeServiceClient(service, TimeSpan.FromMilliseconds(30)));
        await model.ActivateAsync("fixture-code");
        Assert.Equal("ACTIVATION_ERROR", model.Status.State);
        service.Active = true;
        await model.RefreshAsync();
        Assert.Equal("ACTIVATED", model.Status.State);
        service.SetReply.SetResult(new() { State = "ACTIVATING" });
        await service.SetReply.Task;
        Assert.Equal("ACTIVATED", model.Status.State);
        Assert.Equal(1, service.Sets);
        Assert.Equal(1, service.Reads);
    }
    [Fact]
    public async Task UnresponsiveCallIsBoundedAndCannotAccumulateSameMethodRequests()
    {
        var service = new Delayed();
        var client = new WelcomeServiceClient(service, TimeSpan.FromMilliseconds(30));
        var first = client.Call<ActivationView>("activation.set");
        var overlapping = await Assert.ThrowsAsync<ServiceException>(() => client.Call<ActivationView>("activation.set"));
        Assert.Equal(ServiceFailure.Unavailable, overlapping.Failure);
        await Assert.ThrowsAsync<ServiceException>(() => first.WaitAsync(TimeSpan.FromSeconds(2)));
        await Assert.ThrowsAsync<ServiceException>(() => client.Call<ActivationView>("activation.set"));
        Assert.Equal(1, service.Sets);
        service.SetReply.SetResult(new() { State = "ACTIVATING" });
        await service.SetReply.Task;
        await client.Call<ActivationView>("activation.set");
        Assert.Equal(2, service.Sets);
    }
    [Fact]
    public async Task ClosingWindowCancelsWaitWithoutInventingActivationError()
    {
        var service = new Delayed();
        var client = new WelcomeServiceClient(service, TimeSpan.FromSeconds(5));
        using var stop = new CancellationTokenSource();
        var call = client.Call<ActivationView>("activation.set", cancellationToken: stop.Token);
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);
        service.SetReply.SetResult(new() { State = "ACTIVATING" });
        using var alreadyClosed = new CancellationTokenSource(); alreadyClosed.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.Call<ActivationView>("activation.set", cancellationToken: alreadyClosed.Token));
        Assert.Equal(1, service.Sets);
    }
    sealed class ParallelService : IServiceClient
    {
        public int Started;
        public readonly TaskCompletionSource AllStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref Started) == 3) AllStarted.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken);
            return (T)(method switch {
                "activation.status" => (object)new ActivationView { State = "ACTIVATED", HasIdentity = true },
                "account.status" => new AccountConnectionView(),
                "subscription.status" => new SubscriptionView(),
                _ => throw new InvalidOperationException()
            });
        }
    }
    [Fact]
    public async Task IndependentStatusReadsCanFinishInOneDeadlineAndKeepAccessGate()
    {
        var service = new ParallelService(); var client = new WelcomeServiceClient(service);
        var activation = new ActivationModel(client); var account = new AccountConnectionModel(client); var subscription = new SubscriptionModel(client);
        var refresh = Task.WhenAll(activation.RefreshAsync(), account.RefreshAsync(), subscription.RefreshAsync());
        await service.AllStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(refresh.IsCompleted);
        service.Release.SetResult(); await refresh;
        Assert.True(WelcomeAccess.Evaluate(activation.Status, account.Status, subscription.Status).CanContinue);
        activation.Status.Error = "DEVICE_REVOKED";
        Assert.False(WelcomeAccess.Evaluate(activation.Status, account.Status, subscription.Status).CanContinue);
    }
}
