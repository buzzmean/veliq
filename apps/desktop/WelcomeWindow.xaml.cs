using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
namespace Neexitlag.Desktop;

public partial class WelcomeWindow : Window
{
    readonly AccountConnectionModel account;
    readonly ActivationModel activation;
    readonly SubscriptionModel subscription;
    readonly Action connected;
    readonly bool shutdownOnClose;
    readonly CancellationTokenSource lifetime = new();
    readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(2) };
    bool refreshing, busy, codeSelected, transitioned, initial = true, choosing;
    WelcomeAccess access = new("CHECKING", "Проверяем подключение", "Подождите немного…", false);
    public WelcomeWindow(Action connected) : this(new WindowsServiceClient(), connected, true) { }
    internal WelcomeWindow(IServiceClient service, Action connected, bool shutdownOnClose)
    {
        this.connected = connected; this.shutdownOnClose = shutdownOnClose;
        account = new(service); activation = new(service); subscription = new(service);
        InitializeComponent(); WindowTheme.UseDarkCaption(this); Render();
        Loaded += async (_, _) => { await RefreshAsync(); if (!transitioned) timer.Start(); };
        timer.Tick += async (_, _) => await RefreshAsync();
        Closed += (_, _) => { timer.Stop(); lifetime.Cancel(); ConnectionCode.Clear(); if (!transitioned && shutdownOnClose) System.Windows.Application.Current.Shutdown(); };
    }
    internal WelcomeAccess Access => access;
    internal System.Windows.Controls.PasswordBox CodeInput => ConnectionCode;
    internal System.Windows.Controls.Button CodeSubmit => ActivateButton;
    internal async Task RefreshAsync(bool recheck = false)
    {
        if (refreshing || busy || lifetime.IsCancellationRequested) return;
        refreshing = true;
        try
        {
            await activation.RefreshAsync(lifetime.Token);
            await account.RefreshAsync(lifetime.Token);
            await subscription.RefreshAsync(recheck, lifetime.Token);
            access = WelcomeAccess.Evaluate(activation.Status, account.Status, subscription.Status);
            Render();
            // A confirmed saved account resumes without demanding another login.
            // Code-only legacy activation is shown explicitly instead of being
            // presented as a personal account session.
            if (initial && access.CanContinue && account.Status.Linked) Enter();
            initial = false;
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        finally { refreshing = false; if (!lifetime.IsCancellationRequested) Render(); }
    }
    void Render()
    {
        Heading.Text = access.Title; Lead.Text = access.Message;
        bool ready = access.CanContinue, waiting = access.State == "WAITING" && !choosing;
        if (ready) Feedback.Text = "";
        ReadyPanel.Visibility = ready ? Visibility.Visible : Visibility.Collapsed;
        WaitingPanel.Visibility = waiting ? Visibility.Visible : Visibility.Collapsed;
        ChoicePanel.Visibility = ready || waiting ? Visibility.Collapsed : Visibility.Visible;
        PersonalPanel.Visibility = !ready && !waiting && !codeSelected ? Visibility.Visible : Visibility.Collapsed;
        CodePanel.Visibility = !ready && !waiting && codeSelected ? Visibility.Visible : Visibility.Collapsed;
        AccountLabel.Text = account.Status.Linked ? account.Status.Summary : "Доступ по сохранённому коду подключения";
        SignInButton.IsEnabled = RegisterButton.IsEnabled = ActivateButton.IsEnabled = !busy && access.State != "CHECKING";
        PersonalTab.IsEnabled = CodeTab.IsEnabled = !busy;
        RetryButton.IsEnabled = !busy && !refreshing;
        ContinueButton.IsEnabled = ready && !busy;
        PersonalTab.BorderBrush = (System.Windows.Media.Brush)FindResource(codeSelected ? "LineStrong" : "Accent");
        CodeTab.BorderBrush = (System.Windows.Media.Brush)FindResource(codeSelected ? "Accent" : "LineStrong");
        ReopenButton.IsEnabled = account.Status.VerificationUri is not null && !busy;
        CabinetButton.Visibility = account.Status.CabinetUri is not null && access.State is "EXPIRED" or "BLOCKED" or "ERROR" ? Visibility.Visible : Visibility.Collapsed;
    }
    void SelectPersonal(object sender, RoutedEventArgs e) { codeSelected = false; choosing = true; Feedback.Text = ""; Render(); }
    void SelectCode(object sender, RoutedEventArgs e) { codeSelected = true; choosing = true; Feedback.Text = ""; Render(); ConnectionCode.Focus(); }
    void BackToChoice(object sender, RoutedEventArgs e) { choosing = true; Render(); }
    async void SignIn(object sender, RoutedEventArgs e) => await StartAccountAsync(false);
    async void Register(object sender, RoutedEventArgs e) => await StartAccountAsync(true);
    async Task StartAccountAsync(bool registration)
    {
        if (busy || refreshing) return;
        busy = true; choosing = false; Feedback.Text = registration ? "Открываем регистрацию в личном кабинете…" : "Открываем вход в личный кабинет…"; Render();
        try
        {
            await account.StartAsync(lifetime.Token);
            for (int i = 0; i < 20 && account.Status.State == "STARTING"; i++)
            { await Task.Delay(500, lifetime.Token); await account.RefreshAsync(lifetime.Token); }
            if (account.Status.VerificationUri is { } uri) { Open(uri); Feedback.Text = "Подтвердите компьютер в открывшемся личном кабинете."; }
            else Feedback.Text = account.Status.Message;
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch { Feedback.Text = "Не удалось открыть страницу входа. Повторите попытку."; }
        finally { busy = false; await RefreshAsync(); Render(); }
    }
    static void Open(Uri uri) => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
    void ReopenBrowser(object sender, RoutedEventArgs e)
    {
        try { if (account.Status.VerificationUri is { } uri) Open(uri); }
        catch { Feedback.Text = "Не удалось открыть браузер. Повторите попытку."; }
    }
    void OpenCabinet(object sender, RoutedEventArgs e)
    {
        try { if (account.Status.CabinetUri is { } uri) Open(uri); }
        catch { Feedback.Text = "Не удалось открыть личный кабинет. Повторите попытку."; }
    }
    async void ActivateCode(object sender, RoutedEventArgs e) => await ActivateAsync();
    async void CodeKeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) { e.Handled = true; await ActivateAsync(); } }
    async Task ActivateAsync()
    {
        if (busy || refreshing) return;
        string code = ConnectionCode.Password.Trim(); ConnectionCode.Clear();
        if (code.Length == 0) { Feedback.Text = "Введите код, выданный администратором."; ConnectionCode.Focus(); return; }
        busy = true; Feedback.Text = "Проверяем код подключения…"; Render();
        try { await activation.ActivateAsync(code, lifetime.Token); Feedback.Text = activation.Status.Message; }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        finally { code = ""; busy = false; await RefreshAsync(); Render(); }
    }
    async void Retry(object sender, RoutedEventArgs e) { await RefreshAsync(true); Render(); }
    async void Continue(object sender, RoutedEventArgs e)
    {
        await RefreshAsync();
        if (access.CanContinue && !busy && !refreshing) Enter();
    }
    void Enter()
    {
        if (transitioned || !access.CanContinue) return;
        transitioned = true; timer.Stop(); connected(); Close();
    }
    void ExitClick(object sender, RoutedEventArgs e) => Close();
    public void ShowFromTray() { Show(); WindowState = WindowState.Normal; Activate(); }
    public void Exit() => Close();
}
