namespace Neexitlag.Desktop;
public static class GuiRoutingLifetime {
 // Always try: a stale GUI Available=false does not prove service absence.
 // No browser/process control. Other IPC failures must keep the GUI open.
 public static async Task StopAsync(Func<Task> disable) {
  try { await disable(); }
  catch (ServiceException e) when (e.Failure is ServiceFailure.NotInstalled or ServiceFailure.Stopped) { }
 }
}
