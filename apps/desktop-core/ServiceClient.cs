using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
namespace Neexitlag.Desktop;
public enum ServiceFailure
{
    NotInstalled, Stopped, Unavailable, Incompatible, AccessDenied, Rejected
}
public sealed class ServiceException(ServiceFailure failure, string? detail = null) : Exception(detail ?? failure.ToString())
{
    public ServiceFailure Failure { get; } = failure;
}
public interface IServiceClient
{
    Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default);
}
public sealed class ServiceClient : IServiceClient
{
    readonly string tokenFile; readonly string pipeName; readonly TimeSpan timeout;
    public ServiceClient(string? tokenFile = null, string pipeName = "neexitlag-v1", TimeSpan? timeout = null)
    {
        this.tokenFile = tokenFile ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "VELIQ", "ipc.token");
        this.pipeName = pipeName;
        this.timeout = timeout ?? TimeSpan.FromSeconds(8);
    }
    public async Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
    {
        byte[]? request = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var ct = deadline.Token;
        try
        {
            if (!File.Exists(tokenFile))
                throw new ServiceException(ServiceFailure.NotInstalled);
            var token = (await File.ReadAllTextAsync(tokenFile, ct)).Trim();
            if (string.IsNullOrWhiteSpace(token))
                throw new ServiceException(ServiceFailure.Unavailable);
            var id = Guid.NewGuid().ToString("N");
            request = JsonSerializer.SerializeToUtf8Bytes(new
            {
                version = 1,
                id,
                sent_at = DateTimeOffset.UtcNow,
                token,
                method,
                payload
            }, WireJson.Options);
            if (request.Length > 65536)
                throw new ServiceException(ServiceFailure.Rejected);
            using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(ct);
            byte[] header = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(header, (uint)request.Length);
            await pipe.WriteAsync(header, ct);
            await pipe.WriteAsync(request, ct);
            await pipe.FlushAsync(ct);
            await pipe.ReadExactlyAsync(header, ct);
            uint length = BinaryPrimitives.ReadUInt32BigEndian(header);
            if (length is < 1 or > 65536)
                throw new ServiceException(ServiceFailure.Incompatible);
            byte[] reply = new byte[(int)length];
            await pipe.ReadExactlyAsync(reply, ct);
            using var doc = JsonDocument.Parse(reply);
            var root = doc.RootElement;
            if (!root.TryGetProperty("version", out var version) || version.GetInt32() != 1 || !root.TryGetProperty("id", out var responseId) || responseId.GetString() != id)
                throw new ServiceException(ServiceFailure.Incompatible);
            if (!root.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
                throw new ServiceException(ServiceFailure.Rejected, root.TryGetProperty("error", out var error) ? error.GetString() : null);
            return root.GetProperty("data").Deserialize<T>(WireJson.Options) ?? throw new ServiceException(ServiceFailure.Incompatible);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { throw new ServiceException(ServiceFailure.Unavailable); }
        catch (UnauthorizedAccessException) { throw new ServiceException(ServiceFailure.AccessDenied); }
        catch (IOException) { throw new ServiceException(ServiceFailure.Unavailable); }
        catch (JsonException) { throw new ServiceException(ServiceFailure.Incompatible); }
        catch (InvalidOperationException) { throw new ServiceException(ServiceFailure.Incompatible); }
        catch (FormatException) { throw new ServiceException(ServiceFailure.Incompatible); }
        catch (KeyNotFoundException) { throw new ServiceException(ServiceFailure.Incompatible); }
        finally { if (request is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(request); }
    }
}
