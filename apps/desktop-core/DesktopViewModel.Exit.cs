namespace Veliq.Desktop;
public sealed partial class DesktopViewModel {
 // Unlike the ordinary button action, failure must propagate to Closing.
 public async Task DisableRoutingForExitAsync(CancellationToken ct = default) {
  SuppressAutomaticBrowserStartup();
  InvalidateBrowserPreparation();
  await gate.WaitAsync(ct);
  try {
   InvalidateBrowserPreparation();
   var status = await client.Call<Snapshot>("optimize", new { enabled = false }, ct);
   if (status.Optimizing)
    throw new ServiceException(ServiceFailure.Rejected, "Routing shutdown was not confirmed");
   Apply(status);
  } finally { gate.Release(); }
 }
}
