using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
namespace Veliq.Desktop;

public partial class WelcomeWindow : Window
{
    enum SignInStage { Email, Code, Profile, Account, Connecting }
    readonly AccountConnectionModel account;
    readonly ActivationModel activation;
    readonly SubscriptionModel subscription;
    readonly Action connected;
    readonly bool shutdownOnClose;
    readonly Func<Uri, INativeAccountClient> nativeFactory;
    PersonalCabinetSession? personalSession;
    readonly CancellationTokenSource lifetime = new();
    readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(2) };
    INativeAccountClient? native;
    NativeAccountSnapshot? nativeAccount;
    SignInStage stage;
    string email = "";
    DateTime resendAfter;
    DateTime? activationWaitingSince;
    bool refreshing, busy, codeSelected, transitioned, started, registration, forceSignIn, nativeApproved;
    System.Windows.Forms.NotifyIcon? startupTray;
    System.Drawing.Icon? startupIcon;
    WelcomeAccess access = new("CHECKING", "Проверяем подключение", "Подождите немного…", false);
    public WelcomeWindow(Action connected) : this(new WindowsServiceClient(), connected, true) { }
    internal WelcomeWindow(IServiceClient service, Action connected, bool shutdownOnClose,
        Func<Uri, INativeAccountClient>? nativeFactory = null, bool forceSignIn = false, PersonalCabinetSession? session = null)
    {
        this.connected = connected; this.shutdownOnClose = shutdownOnClose; this.forceSignIn = forceSignIn;
        personalSession = session;
        this.nativeFactory = nativeFactory ?? (uri => {
            personalSession = new PersonalCabinetSession(uri);
            personalSession.Forget();
            return new NativeAccountClient(uri, cookies: personalSession.Cookies);
        });
        var welcomeService = new WelcomeServiceClient(service);
        account = new(welcomeService); activation = new(welcomeService); subscription = new(welcomeService);
        InitializeComponent(); WindowTheme.UseDarkCaption(this); Render();
        Loaded += async (_, _) => { if (!started) { started = true; await RefreshAsync(); if (!transitioned) timer.Start(); } };
        timer.Tick += async (_, _) => await RefreshAsync();
        Closed += (_, _) => {
            timer.Stop(); lifetime.Cancel(); native?.Dispose(); native = null; DisposeStartupTray();
            ConnectionCode.Clear(); LoginCode.Clear(); EmailField.Clear();
            if (!transitioned && shutdownOnClose) System.Windows.Application.Current.Shutdown();
        };
    }
    internal WelcomeAccess Access => access;
    internal System.Windows.Controls.PasswordBox CodeInput => ConnectionCode;
    internal System.Windows.Controls.Button CodeSubmit => ActivateButton;
    internal bool ForegroundRequested { get; private set; }
    internal bool StartupTrayVisible => startupTray?.Visible == true;
    // Check service authorization before showing onboarding. During Windows
    // startup keep a real tray icon even while the service is still warming up.
    internal async Task StartAsync(bool quiet)
    {
        if (started) return;
        started = true;
        if (quiet)
        {
            startupIcon = TrayIcons.Load("connecting");
            startupTray = new() { Icon = startupIcon, Text = "VELIQ: проверяем подключение", Visible = true };
            var menu = new System.Windows.Forms.ContextMenuStrip();
            menu.Items.Add(Text.Get("OpenApp"), null, (_, _) => Dispatcher.Invoke(ShowFromTray));
            menu.Items.Add(Text.Get("Exit"), null, (_, _) => Dispatcher.Invoke(Exit));
            TrayMenuRenderer.Apply(menu); startupTray.ContextMenuStrip = menu;
            startupTray.MouseClick += (_, args) => { if (args.Button == System.Windows.Forms.MouseButtons.Left) Dispatcher.Invoke(ShowFromTray); };
        }
        await RefreshAsync();
        if (transitioned || lifetime.IsCancellationRequested) return;
        timer.Start();
        if (!quiet) ShowFromTray();
    }
    void DisposeStartupTray()
    {
        if (startupTray is not null) { startupTray.Visible = false; startupTray.ContextMenuStrip?.Dispose(); startupTray.Dispose(); startupTray = null; }
        startupIcon?.Dispose(); startupIcon = null;
    }
    bool Ready => access.CanContinue && (!forceSignIn || nativeApproved);
    internal async Task RefreshAsync(bool recheck = false)
    {
        if (refreshing || busy || lifetime.IsCancellationRequested) return;
        refreshing = true;
        try
        {
            await Task.WhenAll(activation.RefreshAsync(lifetime.Token),
                account.RefreshAsync(lifetime.Token), subscription.RefreshAsync(recheck, lifetime.Token));
            access = WelcomeAccess.Evaluate(activation.Status, account.Status, subscription.Status);
            if (activation.Status.State is "ACTIVATED" or "ACTIVATION_ERROR" or "CODE_REQUIRED") activationWaitingSince = null;
            timer.Interval = TimeSpan.FromSeconds(activationWaitingSince is not null || activation.Status.State == "ACTIVATING" ? 1 : 2);
            if (Ready) Enter();
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        finally { refreshing = false; if (!lifetime.IsCancellationRequested) Render(); }
    }
    static Visibility Visible(bool value) => value ? Visibility.Visible : Visibility.Collapsed;
    void Render()
    {
        bool ready = Ready, personal = !ready && !codeSelected;
        bool available = !busy && !refreshing && access.State != "CHECKING";
        ChoicePanel.Visibility = Visible(!ready && (codeSelected || stage == SignInStage.Email));
        EmailPanel.Visibility = Visible(personal && stage == SignInStage.Email);
        RememberPersonal.Visibility = Visible(personal && PersonalCabinetSession.PersonalDevice(account.Status, duringPersonalSetup: true));
        OtpPanel.Visibility = Visible(personal && stage == SignInStage.Code);
        ProfilePanel.Visibility = Visible(personal && stage == SignInStage.Profile);
        AccountPanel.Visibility = Visible(personal && stage == SignInStage.Account);
        ConnectingPanel.Visibility = Visible(personal && stage == SignInStage.Connecting);
        CodePanel.Visibility = Visible(!ready && codeSelected);
        AuthBack.Visibility = Visible(personal && stage != SignInStage.Email);
        RetryButton.Visibility = Visible(access.State is "UNAVAILABLE" or "ERROR" or "EXPIRED" or "BLOCKED");
        EmailSubmit.IsEnabled = VerifySubmit.IsEnabled = ProfileSubmit.IsEnabled = ActivateButton.IsEnabled = available;
        PersonalTab.IsEnabled = CodeTab.IsEnabled = RegisterButton.IsEnabled = AuthBack.IsEnabled = !busy;
        ReloadAccountButton.IsEnabled = available && native is not null;
        ApproveButton.IsEnabled = available && nativeAccount?.Kind == "player" && SubscriptionChoices.Items.Count > 0;
        RetryButton.IsEnabled = available;
        PersonalTab.BorderBrush = (System.Windows.Media.Brush)FindResource(codeSelected ? "LineStrong" : "Accent");
        CodeTab.BorderBrush = (System.Windows.Media.Brush)FindResource(codeSelected ? "Accent" : "LineStrong");
        RegisterButton.Content = registration ? "Уже есть аккаунт? Войти" : "Создать аккаунт";
        int remaining = Math.Max(0, (int)Math.Ceiling((resendAfter - DateTime.UtcNow).TotalSeconds));
        ResendButton.Content = remaining > 0 ? $"Отправить ещё раз через {remaining} с" : "Отправить код ещё раз";
        ResendButton.IsEnabled = available && remaining == 0;
        if (ready)
        {
            Heading.Text = "Всё готово";
            Lead.Text = account.Status.Linked ? account.Status.Summary : "Этот компьютер уже подключён по коду.";
            Feedback.Text = "";
        }
        else if (codeSelected) { Heading.Text = "Подключение к клубу"; Lead.Text = "Введите код, который выдал администратор."; }
        else switch (stage)
        {
            case SignInStage.Email:
                Heading.Text = registration ? "Создать аккаунт" : "Войти в VELIQ";
                Lead.Text = "Получите код на свою электронную почту."; break;
            case SignInStage.Code:
                Heading.Text = "Проверьте почту"; Lead.Text = "Код отправлен на " + email; break;
            case SignInStage.Profile:
                Heading.Text = "Завершите регистрацию"; Lead.Text = "Личный аккаунт для вашего компьютера."; break;
            case SignInStage.Account:
                Heading.Text = "Подключить компьютер"; Lead.Text = nativeAccount?.Email ?? ""; break;
            default:
                Heading.Text = "Подключаем компьютер"; Lead.Text = "Проверяем доступ. Это займёт немного времени."; break;
        }
        if (access.State == "UNAVAILABLE" && Feedback.Text.Length == 0)
            Feedback.Text = "Служба VELIQ недоступна. Повторите проверку.";
        if (codeSelected && activationWaitingSince is {} waiting)
        {
            Feedback.Text = access.State is "ERROR" or "BLOCKED" or "EXPIRED" or "UNAVAILABLE" ? access.Message :
                DateTime.UtcNow - waiting >= TimeSpan.FromSeconds(30) ?
                "Активация занимает больше времени. Проверка продолжается автоматически — перезапускать VELIQ не нужно. Можно повторить попытку." :
                "Активируем VELIQ… Проверяем состояние каждую секунду.";
        }
        if (codeSelected && access.State is "ERROR" or "BLOCKED" or "EXPIRED" or "UNAVAILABLE")
            Feedback.Text = access.Message;
        if (stage == SignInStage.Connecting && access.State is "ERROR" or "EXPIRED" or "BLOCKED")
            Feedback.Text = access.Message;
        FooterNote.Text = codeSelected ? "Личный аккаунт игрока не требуется." : "Без пароля. Подключение сохранится на этом ПК.";
    }
    void ResetNative()
    {
        native?.Dispose(); native = null; nativeAccount = null; nativeApproved = false;
        LoginCode.Clear(); ProfileName.Clear(); stage = SignInStage.Email; Feedback.Text = "";
    }
    void SelectPersonal(object sender, RoutedEventArgs e) { if (busy) return; codeSelected = false; ResetNative(); Render(); EmailField.Focus(); }
    void SelectCode(object sender, RoutedEventArgs e) { if (busy) return; codeSelected = true; ResetNative(); Render(); ConnectionCode.Focus(); }
    void ToggleRegistration(object sender, RoutedEventArgs e) { registration = !registration; Feedback.Text = ""; Render(); EmailField.Focus(); }
    void RestartSignIn(object sender, RoutedEventArgs e) { if (busy) return; ResetNative(); Render(); EmailField.Focus(); }
    async Task RunAsync(Func<Task> operation)
    {
        // A delayed IPC reply must resume on this window's dispatcher even
        // when onboarding was invoked before an application message loop.
        if (!Dispatcher.CheckAccess() || SynchronizationContext.Current is not DispatcherSynchronizationContext)
        {
            await Dispatcher.InvokeAsync(() => RunAsync(operation)).Task.Unwrap();
            return;
        }
        if (busy || refreshing || lifetime.IsCancellationRequested) return;
        busy = true; Feedback.Text = ""; Render();
        try { await operation(); }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (NativeAccountException error) { Feedback.Text = error.UserMessage; }
        catch { Feedback.Text = "Не удалось подключиться. Проверьте интернет и повторите попытку."; }
        finally
        {
            busy = false;
            if (!lifetime.IsCancellationRequested) { await RefreshAsync(); if (!lifetime.IsCancellationRequested) Render(); }
        }
    }
    async Task EnsureNativeAsync()
    {
        if (native is not null) return;
        await account.StartAsync(lifetime.Token);
        for (int i = 0; i < 30 && account.Status.State == "STARTING"; i++)
        { await Task.Delay(500, lifetime.Token); await account.RefreshAsync(lifetime.Token); }
        if (account.Status.ImagePreparation) throw new NativeAccountException("ACCOUNT_PROFILE_CONFLICT");
        if (account.Status.VerificationUri is not { } uri)
            throw new NativeAccountException(account.Status.Error.Length > 0 ? account.Status.Error : "ACCOUNT_UNAVAILABLE");
        native = nativeFactory(uri);
    }
    async void SendEmailCode(object sender, RoutedEventArgs e) => await SendEmailAsync();
    async void EmailKeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) { e.Handled = true; await SendEmailAsync(); } }
    async Task SendEmailAsync() => await RunAsync(async () => {
        email = NativeAccountClient.NormalizeEmail(EmailField.Text);
        await EnsureNativeAsync();
        await native!.SendCodeAsync(email, lifetime.Token);
        stage = SignInStage.Code; resendAfter = DateTime.UtcNow.AddSeconds(60); Render(); LoginCode.Focus();
    });
    async void ResendEmailCode(object sender, RoutedEventArgs e)
    {
        if (DateTime.UtcNow < resendAfter || native is null) return;
        await RunAsync(async () => { await native.SendCodeAsync(email, lifetime.Token); resendAfter = DateTime.UtcNow.AddSeconds(60); LoginCode.Clear(); Feedback.Text = "Новый код отправлен."; });
    }
    async void VerifyEmailCode(object sender, RoutedEventArgs e) => await VerifyEmailAsync();
    async void OtpKeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) { e.Handled = true; await VerifyEmailAsync(); } }
    async Task VerifyEmailAsync()
    {
        if (busy || refreshing || native is null) return;
        string code = LoginCode.Password.Trim(); LoginCode.Clear();
        await RunAsync(async () => { try { await ShowAccountAsync(await native.VerifyAsync(email, code, lifetime.Token)); } finally { code = ""; } });
    }
    async Task ShowAccountAsync(NativeAccountSnapshot snapshot)
    {
        nativeAccount = snapshot;
        if (snapshot.Kind == "") { stage = SignInStage.Profile; return; }
        stage = SignInStage.Account;
        var choices = snapshot.Subscriptions.Where(s => snapshot.Kind == "player" && s.Kind == "player" && s.CanConnect).ToList();
        SubscriptionChoices.ItemsSource = choices; SubscriptionChoices.SelectedIndex = choices.Count > 0 ? 0 : -1;
        SubscriptionChoices.Visibility = Visible(choices.Count > 0);
        SubscriptionNotice.Text = snapshot.Kind == "club" ? "Это аккаунт клуба. Для клубного компьютера используйте код администратора." :
            choices.Count == 0 ? "Аккаунт подтверждён. Действующая личная подписка пока не найдена." : "";
        SubscriptionNotice.Visibility = Visible(SubscriptionNotice.Text.Length > 0);
        DeviceName.Text = "";
        if (snapshot.Kind == "player")
        {
            var device = await native!.DeviceAsync(lifetime.Token);
            if (device.Mode != "device") throw new NativeAccountException("ACCOUNT_LINK_INVALID");
            DeviceName.Text = "Компьютер: " + device.Name;
        }
    }
    async void CreateProfile(object sender, RoutedEventArgs e)
    {
        if (native is null) return;
        await RunAsync(async () => await ShowAccountAsync(await native.CreatePersonalProfileAsync(ProfileName.Text, lifetime.Token)));
    }
    async void ReloadAccount(object sender, RoutedEventArgs e)
    {
        if (native is null) return;
        await RunAsync(async () => await ShowAccountAsync(await native.RefreshAsync(lifetime.Token)));
    }
    async void ApproveAccount(object sender, RoutedEventArgs e)
    {
        if (native is null || SubscriptionChoices.SelectedItem is not NativeSubscription selected) return;
        await RunAsync(async () => {
            await native.ApproveAsync(selected.Id, lifetime.Token);
            nativeApproved = true; stage = SignInStage.Connecting;
            try
            {
                lifetime.Token.ThrowIfCancellationRequested();
                if (RememberPersonal.IsChecked == true && personalSession is not null &&
                    PersonalCabinetSession.PersonalDevice(account.Status, duringPersonalSetup: true))
                    personalSession.Save();
                else
                {
                    personalSession?.Forget();
                    using var logout = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                    logout.CancelAfter(TimeSpan.FromSeconds(3));
                    try { await native.LogoutAsync(logout.Token); } catch { }
                }
            }
            finally { native.Dispose(); native = null; }
        });
    }
    async void ActivateCode(object sender, RoutedEventArgs e) => await ActivateAsync();
    async void CodeKeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) { e.Handled = true; await ActivateAsync(); } }
    async Task ActivateAsync()
    {
        if (busy || refreshing) return;
        string code = ConnectionCode.Password.Trim(); ConnectionCode.Clear();
        if (code.Length == 0) { Feedback.Text = "Введите код администратора."; return; }
        activationWaitingSince = DateTime.UtcNow;
        timer.Interval = TimeSpan.FromSeconds(1);
        await RunAsync(async () => { try { await activation.ActivateAsync(code, lifetime.Token); Feedback.Text = activation.Status.Message; } finally { code = ""; } });
    }
    async void Retry(object sender, RoutedEventArgs e) { Feedback.Text = ""; await RefreshAsync(true); }
    void Enter()
    {
        if (transitioned || !Ready) return;
        transitioned = true; timer.Stop(); DisposeStartupTray(); connected(); Close();
    }
    public void ShowFromTray() { ForegroundRequested = true; Show(); WindowState = WindowState.Normal; Activate(); }
    public void Exit() => Close();
}
