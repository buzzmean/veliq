using System.Net;
using System.Text;
using Neexitlag.Desktop;
using Xunit;

namespace NeExitLag.Tests;

public sealed class NativeCabinetTests
{
    const string Sub = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Machine = "abcdef123456", Link = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const string Account = "{\"email\":\"owner@example.test\",\"kind\":\"club\",\"name\":\"Клуб\",\"subscriptions\":[{\"id\":\"" + Sub + "\",\"kind\":\"club\",\"seats\":36,\"used_seats\":1,\"lifetime\":true,\"can_connect\":true,\"devices\":[{\"name\":\"ПК 7\",\"machine\":\"" + Machine + "\"}]}],\"payments\":[]}";
    static readonly Uri Cabinet = new("https://account.example.test/account");
    sealed class Transport : HttpMessageHandler
    {
        public readonly Queue<(string Path, string Body, HttpStatusCode Status)> Responses = new();
        public readonly List<string> Calls = [];
        public void Reply(string path, string body, HttpStatusCode status = HttpStatusCode.OK) => Responses.Enqueue((path, body, status));
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Assert.Equal("https://account.example.test", request.Headers.GetValues("Origin").Single());
            Assert.Equal("account.example.test", request.RequestUri!.Host);
            var expected = Responses.Dequeue();
            Assert.Equal("/api/v1/account" + expected.Path, request.RequestUri.AbsolutePath);
            Calls.Add(request.Method + " " + expected.Path);
            return Task.FromResult(new HttpResponseMessage(expected.Status) { Content = new StringContent(expected.Body, Encoding.UTF8, "application/json") });
        }
    }
    [Fact] public async Task CabinetReadsClubSeatsAndRevalidatesOwnedDeviceBeforeRelease()
    {
        var transport = new Transport(); transport.Reply("", Account); transport.Reply("", Account);
        transport.Reply("/subscriptions/" + Sub + "/devices/" + Machine + "/release", "{\"status\":\"released\"}");
        using var api = NativeAccountClient.ForCabinet(Cabinet, transport);
        var account = await api.RefreshAsync(default);
        Assert.Equal("Клуб", account.RoleLabel); Assert.Equal("Бессрочно", account.Subscriptions.Single().AccessLabel);
        Assert.Equal("Компьютеры: 1 из 36", account.Subscriptions.Single().SeatsLabel);
        await api.ReleaseDeviceAsync(Sub, Machine, default);
        Assert.Equal(3, transport.Calls.Count); Assert.Empty(transport.Responses);
    }
    [Fact] public async Task ForeignSubscriptionAndMalformedMachineCannotIssueRelease()
    {
        var transport = new Transport(); transport.Reply("", Account);
        using var api = NativeAccountClient.ForCabinet(Cabinet, transport);
        await Assert.ThrowsAsync<NativeAccountException>(() => api.ReleaseDeviceAsync(new string('c',32), Machine, default));
        await Assert.ThrowsAsync<NativeAccountException>(() => api.ReleaseDeviceAsync(Sub, "../logout?x=1", default));
        Assert.Single(transport.Calls); Assert.Equal("GET ", transport.Calls[0]);
    }
    [Theory]
    [InlineData("http://account.example.test/account")]
    [InlineData("https://user@account.example.test/account")]
    [InlineData("https://account.example.test/account?redirect=other")]
    [InlineData("https://account.example.test/account#device=" + Link)]
    [InlineData("https://account.example.test/other")]
    public void CabinetOriginRequiresCleanHttpsAccountUrl(string url) => Assert.Throws<NativeAccountException>(() => NativeAccountClient.ForCabinet(new Uri(url)));
    [Fact] public async Task DeviceLinkCannotMoveAuthenticatedSessionToAnotherOrigin()
    {
        var transport = new Transport(); using var api = NativeAccountClient.ForCabinet(Cabinet, transport);
        await Assert.ThrowsAsync<NativeAccountException>(() => api.ApproveDeviceAsync(new Uri("https://other.example.test/account#device="+Link), Sub, default));
        Assert.Empty(transport.Calls);
    }
    [Fact] public async Task ClubImageRequiresFreshClubSubscriptionAndServerApproval()
    {
        var transport = new Transport(); transport.Reply("", Account);
        transport.Reply("/device-links/"+Link, "{\"mode\":\"image\",\"name\":\"Образ\"}");
        transport.Reply("/device-links/"+Link+"/approve", "{\"state\":\"APPROVED\"}");
        using var api = NativeAccountClient.ForCabinet(Cabinet, transport);
        await api.ApproveDeviceAsync(new Uri(Cabinet+"#device="+Link), Sub, default);
        Assert.Equal("POST /device-links/"+Link+"/approve", transport.Calls.Last());
    }
    [Fact] public async Task ExpiredOrClosedAccessNeverUsesLifetimeLabelAsPermission()
    {
        var transport = new Transport(); transport.Reply("", Account.Replace("\"can_connect\":true", "\"can_connect\":false"));
        using var api = NativeAccountClient.ForCabinet(Cabinet, transport);
        await Assert.ThrowsAsync<NativeAccountException>(() => api.ApproveDeviceAsync(new Uri(Cabinet+"#device="+Link), Sub, default));
        Assert.Single(transport.Calls);
    }
    [Fact] public async Task ServerOwnershipRejectionIsNotOptimisticSuccess()
    {
        var transport = new Transport(); transport.Reply("", Account);
        transport.Reply("/subscriptions/"+Sub+"/devices/"+Machine+"/release", "{\"error\":\"SEAT_NOT_FOUND\"}", HttpStatusCode.NotFound);
        using var api=NativeAccountClient.ForCabinet(Cabinet,transport);
        Assert.Equal("SEAT_NOT_FOUND",(await Assert.ThrowsAsync<NativeAccountException>(()=>api.ReleaseDeviceAsync(Sub,Machine,default))).Code);
    }
    [Theory]
    [InlineData("{\"subscriptions\":[null]}")]
    [InlineData("{\"subscriptions\":[{\"id\":null}]}")]
    [InlineData("{\"subscriptions\":[],\"payments\":[null]}")]
    [InlineData("{\"subscriptions\":[{\"id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"kind\":\"club\",\"devices\":[null]}]}")]
    [InlineData("{\"subscriptions\":[{\"paid_until\":\"not-a-date\"}]}")]
    public async Task MalformedServerAccountNeverProducesPermissions(string body)
    {
        var transport=new Transport(); transport.Reply("",body);
        using var api=NativeAccountClient.ForCabinet(Cabinet,transport);
        Assert.Equal("ACCOUNT_UNAVAILABLE",(await Assert.ThrowsAsync<NativeAccountException>(()=>api.RefreshAsync(default))).Code);
    }
    sealed class Session : INativeCabinetClient
    {
        public NativeAccountSnapshot Snapshot = new() { Email="a@example.test", Kind="player" };
        public TaskCompletionSource<NativeAccountSnapshot>? Pending;
        public bool Disposed, FailRefresh;
        public Task SendCodeAsync(string email,CancellationToken ct)=>Task.CompletedTask;
        public Task<NativeAccountSnapshot> VerifyAsync(string email,string code,CancellationToken ct)=>Task.FromResult(Snapshot);
        public Task<NativeAccountSnapshot> RefreshAsync(CancellationToken ct)=>FailRefresh?Task.FromException<NativeAccountSnapshot>(new NativeAccountException("ACCOUNT_LOGIN_REQUIRED")):Pending?.Task??Task.FromResult(Snapshot);
        public Task<NativeAccountSnapshot> CreatePersonalProfileAsync(string name,CancellationToken ct)=>Task.FromResult(Snapshot);
        public Task<NativeAccountSnapshot> CreateProfileAsync(string kind,string name,CancellationToken ct)=>Task.FromResult(Snapshot);
        public Task<NativeDeviceLink> DeviceAsync(CancellationToken ct)=>Task.FromResult(new NativeDeviceLink());
        public Task ApproveAsync(string sub,CancellationToken ct)=>Task.CompletedTask;
        public Task ApproveDeviceAsync(Uri verification,string sub,CancellationToken ct)=>Task.CompletedTask;
        public Task ReleaseDeviceAsync(string sub,string machine,CancellationToken ct)=>Task.CompletedTask;
        public Task LogoutAsync(CancellationToken ct)=>Task.CompletedTask;
        public void Dispose()=>Disposed=true;
    }
    [Fact] public async Task LogoutClearsAccountBeforeDelayedRefreshCanReturn()
    {
        var session=new Session();using var model=new NativeCabinetModel(()=>session);
        await model.SendCodeAsync("a@example.test");await model.VerifyAsync("123456");
        session.Pending=new(TaskCreationOptions.RunContinuationsAsynchronously);
        var refresh=model.RefreshAsync();await model.LogoutAsync();
        Assert.Null(model.Account);Assert.Empty(model.Email);Assert.False(model.CodeSent);Assert.True(session.Disposed);
        session.Pending.SetResult(session.Snapshot);await refresh;Assert.Null(model.Account);
    }
    [Fact] public async Task AccountSwitchRejectsLatePreviousIdentity()
    {
        var a=new Session();var b=new Session{Snapshot=new(){Email="b@example.test",Kind="club"}};
        var clients=new Queue<Session>([a,b]);using var model=new NativeCabinetModel(()=>clients.Dequeue());
        await model.SendCodeAsync("a@example.test");await model.VerifyAsync("123456");
        a.Pending=new(TaskCreationOptions.RunContinuationsAsynchronously);var refresh=model.RefreshAsync();
        await model.SendCodeAsync("b@example.test");await model.VerifyAsync("654321");
        a.Pending.SetResult(a.Snapshot);await refresh;
        Assert.Equal("b@example.test",model.Account!.Email);Assert.Equal("club",model.Account.Kind);Assert.True(a.Disposed);
    }
    [Fact] public async Task SavedSessionDisplaysOnlyLiveServerDataAndCanSignOutWithoutEmailCode()
    {
        var client = new Session();
        using var model = new NativeCabinetModel(() => client);
        await model.ResumeAsync(CancellationToken.None);
        Assert.Same(client.Snapshot, model.Account);
        Assert.False(model.CodeSent);
        await model.LogoutAsync();
        Assert.Null(model.Account);
        Assert.True(client.Disposed);
    }

    [Fact] public async Task FailedRevalidationClearsPreviouslyGrantedView()
    {
        var session=new Session();using var model=new NativeCabinetModel(()=>session);
        await model.SendCodeAsync("a@example.test");await model.VerifyAsync("123456");session.FailRefresh=true;
        await Assert.ThrowsAsync<NativeAccountException>(()=>model.RefreshAsync());Assert.Null(model.Account);
    }
}
