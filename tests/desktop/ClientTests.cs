using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class ClientTests
{
    static async Task WriteFrame(Stream pipe, byte[] payload)
    {
        byte[] header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)payload.Length);
        foreach (var b in header)
            await pipe.WriteAsync(new[] { b });
        foreach (var chunk in payload.Chunk(7))
            await pipe.WriteAsync(chunk);
        await pipe.FlushAsync();
    }
    static async Task<(string method, JsonElement payload)> Exchange(string response = "ok")
    {
        string folder = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string token = Path.Combine(folder, "ipc.token");
        await File.WriteAllTextAsync(token, "fixture-token");
        string pipeName = "neexitlag-test-" + Guid.NewGuid().ToString("N");
        using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var serving = Task.Run(async () =>
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await server.WaitForConnectionAsync(deadline.Token);
            byte[] header = new byte[4];
            await server.ReadExactlyAsync(header, deadline.Token);
            var bytes = new byte[BinaryPrimitives.ReadUInt32BigEndian(header)];
            await server.ReadExactlyAsync(bytes, deadline.Token);
            using var request = JsonDocument.Parse(bytes);
            var root = request.RootElement;
            Assert.Equal(1, root.GetProperty("version").GetInt32());
            Assert.Equal("fixture-token", root.GetProperty("token").GetString());
            Assert.NotEqual(default, root.GetProperty("sent_at").GetDateTimeOffset());
            string id = root.GetProperty("id").GetString()!;
            if (response == "oversized")
            {
                BinaryPrimitives.WriteUInt32BigEndian(header, 65537);
                await server.WriteAsync(header, deadline.Token);
            }
            else if (response == "missing-id")
                await WriteFrame(server, JsonSerializer.SerializeToUtf8Bytes(new
                {
                    version = 1,
                    ok = true,
                    data = new
                    {
                        ready = true
                    }
                }));
            else
                await WriteFrame(server, JsonSerializer.SerializeToUtf8Bytes(new
                {
                    version = response == "version" ? 2 : 1,
                    id = response == "id" ? "wrong" : id,
                    ok = response != "rejected",
                    error = "internal English error must not leak into UI",
                    data = new
                    {
                        ready = true
                    }
                }));
            return (root.GetProperty("method").GetString()!, root.GetProperty("payload").Clone());
        });
        try
        {
            var client = new ServiceClient(token, pipeName, TimeSpan.FromSeconds(5));
            if (response == "ok")
            {
                var result = await client.Call<JsonElement>("profile.set", new
                {
                    id = "custom",
                    mode = "MANUAL",
                    relay_id = "VPS-01"
                });
                Assert.True(result.GetProperty("ready").GetBoolean());
            }
            else
            {
                var error = await Assert.ThrowsAsync<ServiceException>(() => client.Call<JsonElement>("status"));
                Assert.Equal(response == "rejected" ? ServiceFailure.Rejected : ServiceFailure.Incompatible, error.Failure);
                Assert.DoesNotContain("English", Text.Failure(error));
            }
            return await serving;
        }
        finally { Directory.Delete(folder, true); }
    }
    [Fact]
    public async Task FramedAuthenticatedRequestHandlesPartialReads()
    {
        var call = await Exchange();
        Assert.Equal("profile.set", call.method);
        Assert.Equal("MANUAL", call.payload.GetProperty("mode").GetString());
    }
    [Theory][InlineData("id")][InlineData("missing-id")][InlineData("version")][InlineData("oversized")][InlineData("rejected")] public async Task InvalidServiceResponsesFailClosed(string response) => await Exchange(response);
    [Fact]
    public async Task MissingServiceDoesNotCrash()
    {
        var client = new ServiceClient(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".token"));
        var error = await Assert.ThrowsAsync<ServiceException>(() => client.Call<Snapshot>("status"));
        Assert.Equal(ServiceFailure.NotInstalled, error.Failure);
        Assert.Equal("Служба VELIQ не установлена", Text.Failure(error));
    }
    [Fact]
    public async Task UnavailablePipeHasBoundedDeadline()
    {
        string token = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(token, "fixture");
            var client = new ServiceClient(token, "absent-" + Guid.NewGuid(), TimeSpan.FromMilliseconds(150));
            var error = await Assert.ThrowsAsync<ServiceException>(() => client.Call<Snapshot>("status"));
            Assert.Equal(ServiceFailure.Unavailable, error.Failure);
        }
        finally { File.Delete(token); }
    }
    [Fact]
    public async Task ExplicitCancellationIsPreserved()
    {
        string token = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(token, "fixture");
            using var stop = new CancellationTokenSource();
            stop.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new ServiceClient(token).Call<Snapshot>("status", cancellationToken: stop.Token));
        }
        finally { File.Delete(token); }
    }
    [Fact]
    public void GoProcessCreationTimeAndSnakeCaseDtosDeserialize()
    {
        var p = JsonSerializer.Deserialize<ProcessIdentity>("{\"PID\":7,\"Path\":\"game.exe\",\"CreationTime\":123}", WireJson.Options)!;
        Assert.Equal(123UL, p.CreationTime);
        var s = JsonSerializer.Deserialize<Snapshot>("{\"rx_bytes\":42,\"backend\":{\"capabilities\":{\"tcp\":true}},\"routes\":[{\"id\":\"VPS-01\",\"rtt_ms\":12.5}]}", WireJson.Options)!;
        Assert.Equal(42UL, s.RxBytes);
        Assert.True(s.Backend.Capabilities.Tcp);
        Assert.Equal(12.5, s.Routes[0].RttMs);
    }
}
public sealed class StalledPipeTests
{
    [Fact]
    public async Task ConnectedButSilentServiceAlsoTimesOut()
    {
        string token = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(token, "fixture");
            string name = "silent-" + Guid.NewGuid();
            using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            var connection = server.WaitForConnectionAsync();
            var call = new ServiceClient(token, name, TimeSpan.FromSeconds(1)).Call<Snapshot>("status");
            await connection.WaitAsync(TimeSpan.FromSeconds(5));
            var error = await Assert.ThrowsAsync<ServiceException>(() => call);
            Assert.Equal(ServiceFailure.Unavailable, error.Failure);
        }
        finally { File.Delete(token); }
    }
}
