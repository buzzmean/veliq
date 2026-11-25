using System.Security.Cryptography;
using System.Text;
using Veliq.Desktop;
using Xunit;

namespace Veliq.Tests;

public sealed class GameCatalogIntegrityTests
{
    static byte[] BundledBytes()
    {
        using var stream = typeof(GameCatalog).Assembly.GetManifestResourceStream(
            "Veliq.Desktop.Resources.GameCatalog.json");
        Assert.NotNull(stream);
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    [Fact]
    public void EmbeddedCatalogHasLfAndExactPinnedHash()
    {
        var raw = BundledBytes();
        Assert.Contains((byte)'\n', raw);
        Assert.DoesNotContain((byte)'\r', raw);
        Assert.Equal(GameCatalog.BundledSha256, Convert.ToHexString(SHA256.HashData(raw)));
        Assert.NotEmpty(GameCatalog.Bundled().Games);
    }

    [Fact]
    public void CrLfConversionStillFailsIntegrityAndSignatureChecks()
    {
        var raw = BundledBytes();
        var crlf = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(raw).Replace("\n", "\r\n"));
        Assert.True(crlf.Length > raw.Length);
        var error = Assert.Throws<InvalidDataException>(() => GameCatalog.Parse(crlf, GameCatalog.BundledSha256));
        Assert.Equal("GAME_CATALOG_INTEGRITY_FAILED", error.Message);
        using var key = RSA.Create(2048);
        var signature = key.SignData(raw, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.NotEmpty(GameCatalog.VerifySigned(raw, signature, key).Games);
        error = Assert.Throws<InvalidDataException>(() => GameCatalog.VerifySigned(crlf, signature, key));
        Assert.Equal("GAME_CATALOG_SIGNATURE_INVALID", error.Message);
    }
}

public sealed class GameNetworkReferenceTests
{
    [Fact]
    public void PortsAreOnlyInformationalAndLeaveAllProfilesDirect()
    {
        var catalog=GameCatalog.Bundled();
        Assert.NotNull(catalog.NetworkInformation);
        var valve=Assert.Single(catalog.NetworkInformation,x=>x.Id=="steam-valve");
        Assert.Contains("27015-27050",valve.TcpPorts);
        Assert.Contains("27020",valve.TcpPorts);Assert.Contains("27021",valve.TcpPorts);Assert.Contains("27024",valve.TcpPorts);Assert.Contains("443",valve.TcpPorts);
        foreach(var port in new[]{"27000-27250","3478","4379","4380","27014-27030"})Assert.Contains(port,valve.UdpPorts);
        var bf=Assert.Single(catalog.NetworkInformation,x=>x.Id=="battlefield6");
        Assert.Equal(new[]{"80","443","2053","2083","2087","2096","8443"},bf.TcpPorts);
        Assert.Equal(new[]{"443","19294-19344","50000-50100"},bf.UdpPorts);
        Assert.Contains("unverified",bf.Evidence);
        Assert.DoesNotContain(catalog.Games,x=>x.Id=="battlefield6");
        Assert.Equal(13,catalog.Games.Length);Assert.All(catalog.Games,g=>Assert.Equal("DIRECT",g.DefaultMode));
        foreach(var g in catalog.Games)
            foreach(var id in g.NetworkReferences??[])Assert.Contains(catalog.NetworkInformation,x=>x.Id==id);
    }
}
