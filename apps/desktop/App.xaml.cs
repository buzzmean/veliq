using System.Globalization;
using System.IO.Pipes;
using System.Security.Principal;
using System.Windows;
using Forms = System.Windows.Forms;
namespace Neexitlag.Desktop;
public partial class App : System.Windows.Application
{
    Mutex? instance; bool ownsMutex; readonly CancellationTokenSource lifetime = new(); string activationPipe = "";
    Forms.NotifyIcon? startupTray;
    System.Drawing.Icon? startupIcon;
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
        var startInTray = StartsInTray(e.Args);
        var sid = (WindowsIdentity.GetCurrent().User?.Value ?? Environment.UserName) + "-" + System.Diagnostics.Process.GetCurrentProcess().SessionId;
        activationPipe = "NeExitLag-activate-" + sid;
        instance = new Mutex(true, "Local\\NeExitLag-" + sid, out ownsMutex);
        if (!ownsMutex)
        {
            if (!startInTray)
            {
                try
                {
                    using var pipe = new NamedPipeClientStream(".", activationPipe, PipeDirection.Out, PipeOptions.Asynchronous);
                    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    await pipe.ConnectAsync(deadline.Token);
                    await pipe.WriteAsync(new byte[] { 1 }, deadline.Token);
                }
                catch { }
            }
            Shutdown();
            return;
        }
        LocalPreferences.MigrateLegacyUserData();
        if (ClubWindow.IsClubInstallation())
            MainWindow = new ClubWindow(); // Starts in tray, no end-user prompts.
        else if (startInTray)
            ShowStartupTray();
        else
            ShowWelcome(FreshPCSetupArguments(e.Args));
        _ = ListenForActivation(lifetime.Token);
    }

    // Older club images already use --club in their Run value.
    internal static bool StartsInTray(string[] args) =>
        args.Contains(LocalPreferences.TrayArgument, StringComparer.OrdinalIgnoreCase) ||
        args.Contains("--club", StringComparer.OrdinalIgnoreCase);

    void ShowWelcome(string? freshReport, bool openedFromTray = false)
    {
        var welcome = new WelcomeWindow(() => {
            var window = new MainWindow(LocalPreferences.Load(), background: freshReport is null,
                shutdownOnClose: true, applyStartMinimized: !openedFromTray);
            MainWindow = window;
            window.Show();
            if (freshReport is not null) _ = window.RunFreshPCSetupAsync(freshReport);
        });
        MainWindow = welcome;
        welcome.Show();
    }

    internal bool StartupTrayVisible => startupTray?.Visible == true;

    internal void ShowStartupTray()
    {
        startupIcon = TrayIcons.LoadApplicationIcon();
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add(Text.Get("OpenApp"), null, (_, _) => Dispatcher.Invoke(ShowCurrentWindow));
        menu.Items.Add(Text.Get("Exit"), null, (_, _) => Dispatcher.Invoke(() => Shutdown()));
        TrayMenuRenderer.Apply(menu);
        startupTray = new Forms.NotifyIcon { Icon = startupIcon, Text = "VELIQ", ContextMenuStrip = menu };
        startupTray.MouseClick += (_, args) =>
        {
            if (args.Button == Forms.MouseButtons.Left) Dispatcher.Invoke(ShowCurrentWindow);
        };
        startupTray.Visible = true;
    }

    internal void DisposeStartupTray()
    {
        if (startupTray is null) return;
        startupTray.Visible = false;
        startupTray.ContextMenuStrip?.Dispose();
        startupTray.Dispose();
        startupTray = null;
        startupIcon?.Dispose();
        startupIcon = null;
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
    void ShowCurrentWindow()
    {
        if (startupTray is not null)
        {
            DisposeStartupTray();
            ShowWelcome(null, openedFromTray: true);
        }
        else if (MainWindow is ClubWindow club) club.ShowFromTray();
        else if (MainWindow is MainWindow main) main.ShowFromTray();
        else if (MainWindow is WelcomeWindow welcome) welcome.ShowFromTray();
    }

    void ExitCurrentWindow()
    {
        if (startupTray is not null) Shutdown();
        else if (MainWindow is ClubWindow club) club.Exit();
        else if (MainWindow is MainWindow main) main.Exit();
        else if (MainWindow is WelcomeWindow welcome) welcome.Exit();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        DisposeStartupTray();
        lifetime.Cancel();
        if (ownsMutex)
            instance?.ReleaseMutex();
        instance?.Dispose();
        lifetime.Dispose();
        base.OnExit(e);
    }
}
