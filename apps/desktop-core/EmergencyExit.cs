using System.Security.Cryptography;
using System.Text.Json;
namespace Neexitlag.Desktop;

public sealed class EmergencyStatus
{
    public bool Configured { get; set; }
    public string State { get; set; } = "";
    public string OwnerSid { get; set; } = "";
}

public static class EmergencyPasswordVerifier
{
    public const int Iterations = 600000;
    public const int MaxBytes = 1024;
    public static byte[] Create(byte[] password, string ownerSid)
    {
        if (password.Length is < 8 or > MaxBytes || string.IsNullOrWhiteSpace(ownerSid))
            throw new ArgumentException("EMERGENCY_PASSWORD_INVALID");
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        try
        {
            return JsonSerializer.SerializeToUtf8Bytes(new
            {
                version = 1, algorithm = "pbkdf2-sha256", owner_sid = ownerSid,
                iterations = Iterations, salt, hash
            });
        }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }
}

public static class EmergencyExitFlow
{
    // No generic optimize=false fallback: this path must be authorized by the
    // service and must receive explicit cleanup completion.
    public static async Task StopAsync(IServiceClient service, byte[] password, CancellationToken ct = default)
    {
        EmergencyStatus status;
        try { status = await service.Call<EmergencyStatus>("emergency.stop", new { password }, ct); }
        finally { CryptographicOperations.ZeroMemory(password); }
        while (status.State == "STOPPING")
        {
            await Task.Delay(250, ct);
            status = await service.Call<EmergencyStatus>("emergency.status", cancellationToken: ct);
        }
        if (status.State != "STOPPED")
            throw new ServiceException(ServiceFailure.Rejected, "EMERGENCY_CLEANUP_FAILED");
        status = await service.Call<EmergencyStatus>("emergency.finish", cancellationToken: ct);
        if (status.State != "STOPPED")
            throw new ServiceException(ServiceFailure.Rejected, "EMERGENCY_STOP_NOT_CONFIRMED");
    }
}
