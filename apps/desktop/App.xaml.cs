using System.Globalization;
using System.IO.Pipes;
using System.Security.Principal;
using System.Windows;
namespace Neexitlag.Desktop;
public partial class App : System.Windows.Application
{
    Mutex? instance; bool ownsMutex; readonly CancellationTokenSource lifetime = new(); string activationPipe = "";
    protected override async void OnStartup(StartupEventArgs e)
    {
        CultureInfo.DefaultThreadCurrentCulture = Text.Russian;
        CultureInfo.DefaultThreadCurrentUICulture = Text.Russian;
        base.OnStartup(e);
        if (e.Args.Contains("--configure-emergency-password",StringComparer.OrdinalIgnoreCase))
        {
            MainWindow = new EmergencyPasswordWindow(true);
            MainWindow.Show();
            return;
        }
        var sid = (WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName) + "-" + System.Diagnostics.Process.GetCurrentProcess().SessionId;
        activationPipe = "NeExitLag-activate-" + sid;
        instance = new Mutex(true, "Local\\NeExitLag-" + sid, out ownsMutex);
        if (!ownsMutex)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", activationPipe, PipeDirection.Out, PipeOptions.Asynchronous);
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await pipe.ConnectAsync(deadline.Token);
                await pipe.WriteAsync(new byte[] { 1 }, deadline.Token);
            }
            catch { }
            Shutdown();
            return;
        }
        LocalPreferences.MigrateLegacyUserData();
        if (ClubWindow.IsClubInstallation() || e.Args.Any(arg => arg.Equals("--club", StringComparison.OrdinalIgnoreCase)))
        {
            MainWindow = new ClubWindow(); // Starts in tray, no end-user prompts.
            _ = ListenForActivation(lifetime.Token);
            return;
        }
        var freshReport = FreshPCSetupArguments(e.Args);
        var window = freshReport is null ? new MainWindow() : new MainWindow(LocalPreferences.Load(), false, true);
        MainWindow = window;
        window.Show();
        _ = ListenForActivation(lifetime.Token);
        if (freshReport is not null) await window.RunFreshPCSetupAsync(freshReport);
    }
    async Task ListenForActivation(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeServerStream(activationPipe, PipeDirection.In, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await pipe.WaitForConnectionAsync(ct);
                var signal = new byte[1];
                using var readDeadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                readDeadline.CancelAfter(TimeSpan.FromSeconds(2));
                if (await pipe.ReadAsync(signal, readDeadline.Token) == 1) {
                    if(signal[0]==1) await Dispatcher.InvokeAsync(() => ShowCurrentWindow());
                    else if(signal[0]==2) await Dispatcher.InvokeAsync(() => ExitCurrentWindow());
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException) { await Task.Delay(200, ct).ConfigureAwait(false); }
        }
    }
    void ShowCurrentWindow(){if(MainWindow is ClubWindow club)club.ShowFromTray();else if(MainWindow is MainWindow main)main.ShowFromTray();}
    void ExitCurrentWindow(){if(MainWindow is ClubWindow club)club.Exit();else if(MainWindow is MainWindow main)main.Exit();}
    protected override void OnExit(ExitEventArgs e)
    {
        lifetime.Cancel();
        if (ownsMutex)
            instance?.ReleaseMutex();
        instance?.Dispose();
        lifetime.Dispose();
        base.OnExit(e);
    }
}
