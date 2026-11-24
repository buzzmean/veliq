namespace Veliq.Desktop;
// Backend-first orchestration shared with the actual Optimize button. Policy
// admission remains enforced by the service, not by these client-side checks.
public static class BrowserOptimizationSequence {
 public static async Task RunAsync(Func<Task> start,Func<bool> enabled,Func<bool> automatic,Func<Task> policy,Func<Task> native){
  await start();
  if(!enabled() || !automatic())return;
  await policy();
  await native();
 }
}
