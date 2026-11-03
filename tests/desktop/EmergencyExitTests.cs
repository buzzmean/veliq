using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Neexitlag.Desktop;
using Xunit;

public class EmergencyExitTests
{
    sealed class Fixture(params string[] states) : IServiceClient
    {
        readonly Queue<string> states = new(states);
        public readonly List<string> Methods = [];
        public bool Reject;
        public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Methods.Add(method);
            if (Reject) throw new ServiceException(ServiceFailure.Rejected, "EMERGENCY_PASSWORD_INVALID");
            return Task.FromResult((T)(object)new EmergencyStatus { Configured = true, State = states.Dequeue() });
        }
    }
    [Fact] public async Task ClosesOnlyAfterCleanupAndFinishAcknowledgements()
    {
        var service = new Fixture("STOPPING","STOPPED","STOPPED");
        var password = Encoding.UTF8.GetBytes("fixture-password");
        await EmergencyExitFlow.StopAsync(service,password);
        Assert.Equal(new[]{"emergency.stop","emergency.status","emergency.finish"},service.Methods);
        Assert.All(password,b=>Assert.Equal(0,b));
    }
    [Fact] public async Task WrongPasswordNeverFallsBackToUnprotectedDisable()
    {
        var service = new Fixture { Reject = true };
        var password = Encoding.UTF8.GetBytes("fixture-password");
        await Assert.ThrowsAsync<ServiceException>(()=>EmergencyExitFlow.StopAsync(service,password));
        Assert.Equal(new[]{"emergency.stop"},service.Methods);
        Assert.All(password,b=>Assert.Equal(0,b));
    }
    [Fact] public async Task FailedCleanupDoesNotAskServiceToExit()
    {
        var service = new Fixture("CLEANUP_FAILED");
        await Assert.ThrowsAsync<ServiceException>(()=>EmergencyExitFlow.StopAsync(service,Encoding.UTF8.GetBytes("fixture-password")));
        Assert.Equal(new[]{"emergency.stop"},service.Methods);
    }
    [Fact] public async Task CancellationClearsPasswordAndDoesNotClaimSuccess()
    {
        var service = new Fixture("STOPPING");
        using var ct = new CancellationTokenSource();ct.Cancel();
        var password = Encoding.UTF8.GetBytes("fixture-password");
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>EmergencyExitFlow.StopAsync(service,password,ct.Token));
        Assert.Empty(service.Methods);Assert.All(password,b=>Assert.Equal(0,b));
    }
    [Fact] public void VerifierContainsOnlySaltAndKdfBoundToOwner()
    {
        var password = Encoding.UTF8.GetBytes("fixture-only-Δ-password");
        var bytes = EmergencyPasswordVerifier.Create(password,"owner-fixture");
        using var doc = JsonDocument.Parse(bytes);
        var r = doc.RootElement;
        Assert.Equal(1,r.GetProperty("version").GetInt32());
        Assert.Equal("pbkdf2-sha256",r.GetProperty("algorithm").GetString());
        Assert.Equal("owner-fixture",r.GetProperty("owner_sid").GetString());
        Assert.Equal(600000,r.GetProperty("iterations").GetInt32());
        var salt = r.GetProperty("salt").GetBytesFromBase64();
        var hash = r.GetProperty("hash").GetBytesFromBase64();
        Assert.Equal(32,salt.Length);
        Assert.Equal(Rfc2898DeriveBytes.Pbkdf2(password,salt,600000,HashAlgorithmName.SHA256,32),hash);
        Assert.False(r.TryGetProperty("password",out _));
    }
}
