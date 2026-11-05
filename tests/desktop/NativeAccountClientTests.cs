using System.Net;
using System.Text;
using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;

public sealed class NativeAccountClientTests
{
    const string Id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const string Sub = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    static readonly Uri Verification = new("https://account.example.test/account.html#device=" + Id);
    const string Personal = "{\"email\":\"fixture@example.test\",\"kind\":\"player\",\"subscriptions\":[{\"id\":\"" + Sub + "\",\"kind\":\"player\",\"seats\":1,\"used_seats\":0,\"can_connect\":true,\"lifetime\":true}]}";
    const string Device = "{\"name\":\"Тестовый ПК\",\"mode\":\"device\",\"approved\":false}";
    sealed class Transport : HttpMessageHandler
    {
        public readonly Queue<(string path, HttpStatusCode status, string body)> Replies = new();
        public readonly List<(string method, string url, string body)> Calls = [];
        public bool Disposed;
        public void Reply(string path, string body, HttpStatusCode status = HttpStatusCode.OK) => Replies.Enqueue((path, status, body));
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Assert.Equal("https://account.example.test", request.Headers.GetValues("Origin").Single());
            string body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            Calls.Add((request.Method.Method, request.RequestUri!.AbsoluteUri, body));
            var expected = Replies.Dequeue();
            Assert.Equal("/api/v1/account" + expected.path, request.RequestUri.AbsolutePath);
            Assert.Empty(request.RequestUri.Fragment); Assert.Empty(request.RequestUri.Query);
            if (request.Method != HttpMethod.Get) Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);
            var result = new HttpResponseMessage(expected.status) { Content = new StringContent(expected.body, Encoding.UTF8, "application/json") };
            if ((int)expected.status == 302) result.Headers.Location = new Uri("https://other.example.test/steal");
            return result;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
    [Fact] public async Task EmailRegistrationAndExplicitDeviceApprovalUseExistingApi()
    {
        var t = new Transport();
        t.Reply("/login/start", "{\"status\":\"sent\"}");
        t.Reply("/login/verify", "{\"email\":\"fixture@example.test\"}");
        t.Reply("", "{\"email\":\"fixture@example.test\",\"kind\":\"\",\"subscriptions\":[]}");
        t.Reply("/profile", "{\"kind\":\"player\"}"); t.Reply("", Personal);
        t.Reply("", Personal); t.Reply("/device-links/" + Id, Device);
        t.Reply("/device-links/" + Id + "/approve", "{\"state\":\"APPROVED\"}");
        t.Reply("/logout", "{\"status\":\"ok\"}");
        using (var api = new NativeAccountClient(Verification, t))
        {
            await api.SendCodeAsync(" Fixture@example.test ", default);
            var account = await api.VerifyAsync("fixture@example.test", "123456", default);
            Assert.Equal("", account.Kind);
            account = await api.CreatePersonalProfileAsync("Имя", default);
            Assert.True(account.Subscriptions.Single().Lifetime);
            Assert.DoesNotContain(t.Calls, c => c.url.EndsWith("/approve"));
            await api.ApproveAsync(Sub, default);
            await api.LogoutAsync(default);
        }
        Assert.Empty(t.Replies); Assert.True(t.Disposed);
        Assert.All(t.Calls, c => { Assert.DoesNotContain("123456", c.url); Assert.DoesNotContain("fixture@", c.url); });
        Assert.Contains("\"kind\":\"player\"", t.Calls.Single(c => c.url.EndsWith("/profile")).body);
    }
    [Theory]
    [InlineData("http://account.example.test/account.html#device=" + Id)]
    [InlineData("https://user@account.example.test/account.html#device=" + Id)]
    [InlineData("https://account.example.test/account.html?next=other#device=" + Id)]
    [InlineData("https://account.example.test/other#device=" + Id)]
    [InlineData("https://account.example.test/account.html#device=wrong")]
    public void UnsafeVerificationAddressIsRejected(string url)
    { Assert.Throws<NativeAccountException>(() => new NativeAccountClient(new Uri(url))); }
    [Fact] public async Task RedirectDoesNotForwardLogin()
    {
        var t = new Transport(); t.Reply("/login/start", "{}", HttpStatusCode.Found);
        using var api = new NativeAccountClient(Verification, t);
        Assert.Equal("ACCOUNT_ORIGIN_REJECTED", (await Assert.ThrowsAsync<NativeAccountException>(() => api.SendCodeAsync("fixture@example.test", default))).Code);
        Assert.Single(t.Calls);
    }
    [Fact] public async Task WrongCodeDoesNotReadAccountOrApprove()
    {
        var t = new Transport(); t.Reply("/login/verify", "{\"error\":\"LOGIN_CODE_INVALID\"}", HttpStatusCode.Unauthorized);
        using var api = new NativeAccountClient(Verification, t);
        Assert.Equal("LOGIN_CODE_INVALID", (await Assert.ThrowsAsync<NativeAccountException>(() => api.VerifyAsync("fixture@example.test", "123456", default))).Code);
        Assert.Single(t.Calls);
        await Assert.ThrowsAsync<NativeAccountException>(() => api.VerifyAsync("fixture@example.test", "abcdef", default));
        Assert.Single(t.Calls);
    }
    [Theory][InlineData("club", true)][InlineData("player", false)]
    public async Task WrongRoleOrExpiredAccessNeverApproves(string kind, bool connect)
    {
        var t = new Transport(); t.Reply("", Personal.Replace("\"player\"", "\"" + kind + "\"").Replace("\"can_connect\":true", "\"can_connect\":" + connect.ToString().ToLowerInvariant()));
        using var api = new NativeAccountClient(Verification, t);
        Assert.Equal("ACCOUNT_SUBSCRIPTION_REQUIRED", (await Assert.ThrowsAsync<NativeAccountException>(() => api.ApproveAsync(Sub, default))).Code);
        Assert.Single(t.Calls);
    }
    [Fact] public async Task ServiceImageIsNotApprovedAsPersonalComputer()
    {
        var t = new Transport(); t.Reply("", Personal); t.Reply("/device-links/" + Id, Device.Replace("device", "image"));
        using var api = new NativeAccountClient(Verification, t);
        await Assert.ThrowsAsync<NativeAccountException>(() => api.ApproveAsync(Sub, default));
        Assert.DoesNotContain(t.Calls, c => c.url.EndsWith("/approve"));
    }
    [Fact] public async Task AccountCapacityRejectionRemainsAnError()
    {
        var t = new Transport(); t.Reply("", Personal); t.Reply("/device-links/" + Id, Device);
        t.Reply("/device-links/" + Id + "/approve", "{\"error\":\"ACTIVATION_LIMIT\"}", HttpStatusCode.Conflict);
        using var api = new NativeAccountClient(Verification, t);
        Assert.Equal("ACTIVATION_LIMIT", (await Assert.ThrowsAsync<NativeAccountException>(() => api.ApproveAsync(Sub, default))).Code);
    }
    [Fact] public async Task ArbitraryServerBodyDoesNotReachUser()
    {
        var t = new Transport(); t.Reply("/login/start", "{\"error\":\"private response fixture@example.test\"}", HttpStatusCode.BadRequest);
        using var api = new NativeAccountClient(Verification, t);
        var error = await Assert.ThrowsAsync<NativeAccountException>(() => api.SendCodeAsync("fixture@example.test", default));
        Assert.Equal("ACCOUNT_UNAVAILABLE", error.Code); Assert.DoesNotContain("fixture", error.UserMessage);
    }
    [Fact] public async Task OversizedAccountResponseIsRejected()
    {
        var t = new Transport(); t.Reply("", new string(' ', 1024 * 1024 + 1));
        using var api = new NativeAccountClient(Verification, t);
        await Assert.ThrowsAsync<NativeAccountException>(() => api.RefreshAsync(default));
    }
}
