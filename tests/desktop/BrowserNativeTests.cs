using System.Text.Json;
using Neexitlag.Desktop;
using Xunit;

namespace NeExitLag.Tests;
public sealed class BrowserNativeTests
{
    sealed class NativeService : IServiceClient
    {
        public readonly PickerService Inner = new();
        public bool Reject;
        public int NativeCalls;
        public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
        {
            if (method == "browser.native.enable")
            {
                NativeCalls++;
                if (Reject) return Task.FromException<T>(new ServiceException(ServiceFailure.Rejected, "NATIVE_OWNED_PAC_GUARD_REQUIRED"));
                return Task.FromResult((T)(object)JsonSerializer.SerializeToElement(new { native = true }));
            }
            // PickerService models append-only application creation. Native disable
            // edits an existing profile: emulate the real upsert contract here.
            if(method=="profile.set" && payload is Profile p) Inner.State.Profiles=Inner.State.Profiles.Where(v=>v.Id!=p.Id).ToArray();
            return Inner.Call<T>(method, payload, cancellationToken);
        }
    }
    [Theory]
    [InlineData("chrome.exe")]
    [InlineData("msedge.exe")]
    public async Task NativeEnableIsOneIPCThenRefreshNoPrepareQuitOrProfileRewrite(string exe)
    {
        var service = new NativeService(); var p = new Profile { Id = "browser", Executables = [exe], Mode = "AUTO" };
        service.Inner.State.Profiles = [p];
        var vm = new DesktopViewModel(service); await vm.RefreshAsync();
        await vm.EnableNativeBrowserAsync(p);
        Assert.Single(vm.Applications); Assert.Equal(1, service.NativeCalls);
        Assert.DoesNotContain(service.Inner.Calls, c => c.Method is "browser.prepare" or "edge.prepare" or "profile.set" or "optimize");
    }
    [Fact]
    public async Task GuardRefusalKeepsApplicationsAndDoesNotInstallPolicy()
    {
        var service = new NativeService { Reject = true }; service.Inner.State.Profiles = [new() { Id = "edge", Executables = ["msedge.exe"], Mode = "DIRECT" }];
        var vm = new DesktopViewModel(service); await vm.RefreshAsync();
        await Assert.ThrowsAsync<ServiceException>(() => vm.EnableNativeBrowserAsync(service.Inner.State.Profiles[0]));
        Assert.True(vm.Available); Assert.Single(vm.Applications);
        Assert.DoesNotContain(service.Inner.Calls, c => c.Method.Contains("policy") || c.Method.Contains("prepare") || c.Method == "profile.set");
    }
    [Fact]
    public async Task ExplicitDisableClearsNativeFlagInsteadOfReenablingNative()
    {
        var service=new NativeService();var p=new Profile{Id="chrome",Executables=["chrome.exe"],Mode="AUTO",PolicyData=new(){["browser_transport"]=JsonSerializer.SerializeToElement("native")}};
        service.Inner.State.Profiles=[p];var vm=new DesktopViewModel(service);await vm.RefreshAsync();
        await vm.DisableNativeBrowserAsync(p);
        var saved=Assert.Single(service.Inner.State.Profiles);
        Assert.Equal("DIRECT",saved.Mode);Assert.False(DesktopViewModel.NativeBrowser(saved));Assert.Equal(0,service.NativeCalls);
        Assert.False(vm.NativeBrowserCandidate(saved));
    }
    [Fact]
    public void NativeErrorsShowOnlyKnownCodeWithoutPayloadOrSecrets()
    {
        Assert.Equal("NATIVE_OWNED_PAC_GUARD_REQUIRED", DesktopViewModel.NativeBrowserErrorCode(new Exception("NATIVE_OWNED_PAC_GUARD_REQUIRED token=private")));
        Assert.Equal("NATIVE_ACTIVATION_FAILED", DesktopViewModel.NativeBrowserErrorCode(new Exception("token=private")));
    }
    [Fact]
    public void NativeCandidatesPreserveExplicitModesAndPendingEdgeCanConverge()
    {
        var vm = new DesktopViewModel(new PickerService());
        foreach (var mode in new[] { "DIRECT", "MANUAL", "DIRECT_PLUS" })
            Assert.False(vm.NativeBrowserCandidate(new() { Executables = ["chrome.exe"], Mode = mode }));
        var edge = new Profile { Executables = ["msedge.exe"], Mode = "DIRECT", PolicyData = new() { ["app_preset"] = JsonSerializer.SerializeToElement("edge-sites-pending") } };
        Assert.True(vm.NativeBrowserCandidate(edge));
        edge.PolicyData["browser_transport"] = JsonSerializer.SerializeToElement("native");
        Assert.True(DesktopViewModel.NativeBrowser(edge)); Assert.True(DesktopViewModel.NativeBrowser(edge.Copy()));
        Assert.False(vm.NativeBrowserCandidate(new() { Executables = ["discord.exe"], Mode = "AUTO" }));
    }
}

public sealed class BrowserPathDisplayTests
{
 [Fact]
 public void EmptyNativeEvidenceCannotErasePACOrInventNativePass()
 {
  var pac=new BrowserTransportSnapshot{Listening=true,Records=[new(){Id=1,Domain="vk.com",EvidenceSource="PAC_CONNECT",Active=true,SentBytes=10,ReceivedBytes=20}]};
  var combined=DesktopViewModel.CombineBrowserPaths(pac,[],new(){CaptureReady=true});
  Assert.Single(combined.Records);Assert.Equal("PAC_CONNECT",combined.Records[0].EvidenceSource);
  Assert.DoesNotContain(combined.Records,r=>r.EvidenceSource=="NATIVE_TCP");
 }
 [Fact]
 public void MixedIngressAndNativeUpstreamAreLabeledAndRetainTruncation()
 {
  var pac=new BrowserTransportSnapshot{Listening=true,Records=[new(){Id=1,EvidenceSource="PAC_CONNECT"}]};
  var native=new NativeBrowserRecord{Id=1,Ingress="PAC_NATIVE_UPSTREAM"}.Connection();
  var combined=DesktopViewModel.CombineBrowserPaths(pac,[native],new(){CaptureReady=true,Truncated=true,Lost=2});
  Assert.Equal(2,combined.Records.Length);Assert.True(combined.Truncated);Assert.Equal(2UL,combined.Lost);
  Assert.Contains(combined.Records,r=>r.EvidenceSource=="PAC_NATIVE_UPSTREAM");
 }
 [Fact]
 public void NativeRecordsStayInTheirOwningBrowserLane()
 {
  var records=new BrowserConnection[]{new(){Domain="chrome.example",Owner=new(){ProfileId="chrome"}},new(){Domain="edge.example",Owner=new(){ProfileId="edge"}}};
  var chrome=DesktopViewModel.CombineBrowserPaths(new(),records,new(),new HashSet<string>{"chrome"});
  Assert.Equal("chrome.example",Assert.Single(chrome.Records).Domain);
  var edge=DesktopViewModel.CombineBrowserPaths(new(),records,new(),new HashSet<string>{"edge"});
  Assert.Equal("edge.example",Assert.Single(edge.Records).Domain);
 }
 [Fact]
 public void EdgeNativeReadinessDoesNotClaimPACNonceOrPages()
 {
  var vm=new DesktopViewModel(new PickerService());
  vm.Apply(new(){Optimizing=true});
  vm.ApplyEdgePolicyState(new(){TransportMode="NATIVE_ARMED_PAC_GUARD",ReadinessState="NATIVE_TUNNEL_OBSERVED",Listening=true,OwnedGuardInstalled=true,PacNonceReadiness="NOT_PREPARED"});
  Assert.Contains("native upstream",vm.EdgeState);Assert.Contains("проверка страницы и PAC отдельно",vm.EdgeState);
  Assert.DoesNotContain("не настроен",vm.EdgeState);
  Assert.Equal("BLOCK",new NativeBrowserRecord{Result="BLOCK",Policy=new(){Action="RELAY_REQUIRED"}}.Connection().Route);
  var r=new BrowserConnection{SentBytes=10,ReceivedBytes=20,Plan=new(){Probe="CONNECTION_FAILED"}};
  Assert.Contains("Origin probe",r.Outcome);Assert.Contains("результат страницы не измерен",r.Outcome);
 }
}
