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
            try {
                await new ServiceClient().Call<EmergencyStatus>("emergency.status");
                MainWindow = new EmergencyPasswordWindow(true);
                MainWindow.Show();
            } catch {
                MessageBox.Show("Настройка аварийного отключения доступна только для клубной установки. На личном ПК используйте обычное отключение VELIQ.", "VELIQ");
                Shutdown();
            }
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
        if (ClubWindow.IsClubInstallation())
        {
            MainWindow = new ClubWindow(); // Starts in tray, no end-user prompts.
            _ = ListenForActivation(lifetime.Token);
            return;
        }
        var freshReport = FreshPCSetupArguments(e.Args);
        var welcome = new WelcomeWindow(() => {
            var window = freshReport is null ? new MainWindow() : new MainWindow(LocalPreferences.Load(), false, true);
            MainWindow = window;
            window.Show();
            if (freshReport is not null) _ = window.RunFreshPCSetupAsync(freshReport);
        });
        MainWindow = welcome;
        welcome.Show();
        _ = ListenForActivation(lifetime.Token);
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
    void ShowCurrentWindow(){if(MainWindow is ClubWindow club)club.ShowFromTray();else if(MainWindow is MainWindow main)main.ShowFromTray();else if(MainWindow is WelcomeWindow welcome)welcome.ShowFromTray();}
    void ExitCurrentWindow(){if(MainWindow is ClubWindow club)club.Exit();else if(MainWindow is MainWindow main)main.Exit();else if(MainWindow is WelcomeWindow welcome)welcome.Exit();}
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
