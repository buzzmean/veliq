using System.Text.Json;
using Veliq.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public class FlowPolicyTests
{
 [Fact] public void NullStrategyArraysAndActionsAreSafe()
 {
  var p=JsonSerializer.Deserialize<LocalStrategyProfile>("""{"ports":null,"domains":null,"ips":null,"exclude_domains":null,"exclude_ips":null,"actions":null}""",WireJson.Options)!;
  Assert.Empty(p.Ports);Assert.Empty(p.Domains);Assert.Empty(p.Ips);Assert.Empty(p.ExcludeDomains);Assert.Empty(p.ExcludeIps);Assert.NotNull(p.Advanced);
  p.Actions=[new LocalStrategyAction{Positions=null!}];Assert.NotNull(p.Advanced);
 }
 [Fact] public void GuiRoundtripPreservesRulesFallbackAndIdentity()
 {
  var p=JsonSerializer.Deserialize<Profile>("""{"id":"openai","name":"ChatGPT","executables":["C:\\Apps\\ChatGPT.exe"],"mode":"AUTO","fallback":"RELAY_REQUIRED","app_preset":"openai","identity":{"root":"C:\\Apps","executable":"chatgpt.exe","helpers":["codex.exe"]},"rules":[{"id":"sensitive","action":"RELAY_REQUIRED","relay_id":"VPS-01"}]}""",WireJson.Options)!;
  var copy=p.Copy();copy.Name="Updated";var json=JsonSerializer.Serialize(copy,WireJson.Options);Assert.Contains("RELAY_REQUIRED",json);Assert.Contains("codex.exe",json);Assert.Contains("sensitive",json);Assert.NotSame(p.PolicyData,copy.PolicyData);Assert.Equal("RELAY_REQUIRED",copy.Fallback);
 }
}
public class AutoStatusTests
{
 [Fact] public void NormalStatusUsesActualCountersAndHidesInternalIds()
 {
  var row=new ApplicationRow();var p=new Profile{Id="chrome",Executables=["C:\\chrome.exe"],Mode="AUTO"};var process=new ProcessIdentity{PID=7,CreationTime=10,Path=p.Executables[0]};
  var flow=new CaptureFlow{Pid=7,CreationTime=10,Exe=process.Path,SelectedRoute="RELAY",RelayId="VPS-01",Strategy="fake5",Chain="TTL=5",LastSeen=DateTimeOffset.UtcNow};var capture=new CaptureEvidence{Flows=[flow]};
  row.Update(p,[process],capture);Assert.Equal(Text.Get("AutoChecking"),row.UserStatus);
  flow.Counters.RelayedBytes=1;row.Update(p,[process],capture);Assert.Equal(Text.Get("ProtectedRoute"),row.UserStatus);Assert.DoesNotContain("VPS-01",row.UserStatus);Assert.DoesNotContain("fake5",row.UserStatus);
  flow.SelectedRoute="BLOCK";flow.RelayRequiredBlocked=true;row.Update(p,[process],capture);Assert.Equal(Text.Get("ProtectedFlowBlocked"),row.UserStatus);
 }
}

public class AdaptiveUdpStatusTests
{
 [Theory]
 [InlineData(null)]
 [InlineData("DIRECT_PROBATION")]
 [InlineData("FLOW_RELAY_FALLBACK")]
 public void IsolatedRepliesNeverBecomeConfirmedDirectInGui(string? state)
 {
  var (row,p,process,flow)=Fixture();
  if(state!=null)flow.UdpHealth=new(){State=state,ProbationReplies=2,ProbationReplyBytes=580};
  row.Update(p,[process],new(){Flows=[flow]});
  Assert.Equal(Text.Get("AutoChecking"),row.UserStatus);
 }
 [Fact] public void ConfirmedDirectAndRealRelayCountersRemainDistinct()
 {
  var (row,p,process,flow)=Fixture();
  flow.UdpHealth=new(){State="DIRECT_CONFIRMED",ProbationReplies=10,ProbationReplyBytes=1000};
  row.Update(p,[process],new(){Flows=[flow]});Assert.Equal(Text.Get("DirectConnection"),row.UserStatus);
  flow.SelectedRoute="RELAY";flow.UdpHealth.State="FLOW_RELAY_FALLBACK";flow.UdpHealth.Reason="DIRECT_LIVENESS_LOST";
  row.Update(p,[process],new(){Flows=[flow]});Assert.Equal(Text.Get("AutoChecking"),row.UserStatus);
  flow.Counters.RelayedBytes=100;row.Update(p,[process],new(){Flows=[flow]});Assert.Equal(Text.Get("ProtectedRoute"),row.UserStatus);
  Assert.Contains("DIRECT_LIVENESS_LOST",row.LocalDetails);
 }
 [Fact] public void WireHealthEvidenceDeserializesWithoutChangingOldFlows()
 {
  var f=JsonSerializer.Deserialize<CaptureFlow>("""{"udp_health":{"state":"DIRECT_PROBATION","probation_replies":2,"probation_reply_bytes":580,"probation_duration_ms":3000,"reply_bins":1,"outbound_bins":8,"degraded_duration_ms":0}}""",WireJson.Options)!;
  Assert.Equal(580UL,f.UdpHealth!.ProbationReplyBytes);Assert.Equal(3000,f.UdpHealth.ProbationDurationMs);
  Assert.Null(JsonSerializer.Deserialize<CaptureFlow>("{}",WireJson.Options)!.UdpHealth);
 }
 static (ApplicationRow,Profile,ProcessIdentity,CaptureFlow) Fixture()
 {
  var p=new Profile{Id="media",Executables=["C:\\media.exe"],Mode="AUTO"};
  var process=new ProcessIdentity{PID=7,CreationTime=10,Path=p.Executables[0]};
  var f=new CaptureFlow{Pid=7,CreationTime=10,Exe=process.Path,SelectedRoute="DIRECT",LastSeen=DateTimeOffset.UtcNow,Policy=new(){Fallback="FLOW_RELAY_FALLBACK"},Counters=new(){DirectPackets=10,DirectReplyPackets=2,DirectReplyBytes=580}};
  return(new(),p,process,f);
 }
}
