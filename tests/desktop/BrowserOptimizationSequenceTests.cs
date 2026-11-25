using Veliq.Desktop;
using Xunit;
public class BrowserOptimizationSequenceTests {
 [Fact]public async Task BackendPrecedesEveryPolicyOrNativeAction(){
  var calls=new List<string>();bool enabled=false;
  await BrowserOptimizationSequence.RunAsync(()=>{calls.Add("optimize");enabled=true;return Task.CompletedTask;},()=>enabled,()=>true,()=>{Assert.True(enabled);calls.Add("policy");return Task.CompletedTask;},()=>{calls.Add("native");return Task.CompletedTask;});
  Assert.Equal(new[]{"optimize","policy","native"},calls);
 }
 [Theory][InlineData(false,true)][InlineData(true,false)]public async Task FailedOptimizeOrAutomaticOffDoesNotPreparePAC(bool enabled,bool automatic){
  int starts=0;
  await BrowserOptimizationSequence.RunAsync(()=>{starts++;return Task.CompletedTask;},()=>enabled,()=>automatic,()=>throw new Exception("PAC must not be prepared"),()=>throw new Exception("Native must not be armed"));
  Assert.Equal(1,starts);
 }
}
