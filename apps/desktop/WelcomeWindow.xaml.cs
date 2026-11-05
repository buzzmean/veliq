using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
namespace Neexitlag.Desktop;

public partial class WelcomeWindow : Window
{
    enum SignInStage { Email, Code, Profile, Account, Connecting }
    readonly AccountConnectionModel account;
    readonly ActivationModel activation;
    readonly SubscriptionModel subscription;
    readonly Action connected;
    readonly bool shutdownOnClose;
    readonly Func<Uri, INativeAccountClient> nativeFactory;
    readonly CancellationTokenSource lifetime = new();
    readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(2) };
    INativeAccountClient? native;
    NativeAccountSnapshot? nativeAccount;
    SignInStage stage;
    string email = "";
    DateTime resendAfter;
    bool refreshing, busy, codeSelected, transitioned, initial = true, registration, forceSignIn, nativeApproved;
    WelcomeAccess access = new("CHECKING", "Проверяем подключение", "Подождите немного…", false);
    public WelcomeWindow(Action connected) : this(new WindowsServiceClient(), connected, true) { }
    internal WelcomeWindow(IServiceClient service, Action connected, bool shutdownOnClose,
        Func<Uri, INativeAccountClient>? nativeFactory = null, bool forceSignIn = false)
    {
        this.connected = connected; this.shutdownOnClose = shutdownOnClose; this.forceSignIn = forceSignIn;
        this.nativeFactory = nativeFactory ?? (uri => new NativeAccountClient(uri));
        account = new(service); activation = new(service); subscription = new(service);
        InitializeComponent(); WindowTheme.UseDarkCaption(this); Render();
        Loaded += async (_, _) => { await RefreshAsync(); if (!transitioned) timer.Start(); };
        timer.Tick += async (_, _) => await RefreshAsync();
        Closed += (_, _) => {
            timer.Stop(); lifetime.Cancel(); native?.Dispose(); native = null;
            ConnectionCode.Clear(); LoginCode.Clear(); EmailField.Clear();
            if (!transitioned && shutdownOnClose) System.Windows.Application.Current.Shutdown();
        };
    }
    internal WelcomeAccess Access => access;
    internal System.Windows.Controls.PasswordBox CodeInput => ConnectionCode;
    internal System.Windows.Controls.Button CodeSubmit => ActivateButton;
    bool Ready => access.CanContinue && (!forceSignIn || nativeApproved);
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
            if (initial && Ready && account.Status.Linked) Enter();
            initial = false;
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
        OtpPanel.Visibility = Visible(personal && stage == SignInStage.Code);
        ProfilePanel.Visibility = Visible(personal && stage == SignInStage.Profile);
        AccountPanel.Visibility = Visible(personal && stage == SignInStage.Account);
        ConnectingPanel.Visibility = Visible(personal && stage == SignInStage.Connecting);
        CodePanel.Visibility = Visible(!ready && codeSelected);
        ReadyPanel.Visibility = Visible(ready);
        AuthBack.Visibility = Visible(personal && stage != SignInStage.Email);
        RetryButton.Visibility = Visible(access.State is "UNAVAILABLE" or "ERROR" or "EXPIRED" or "BLOCKED");
        PersonalInsteadButton.Visibility = Visible(ready && !account.Status.Linked);
        EmailSubmit.IsEnabled = VerifySubmit.IsEnabled = ProfileSubmit.IsEnabled = ActivateButton.IsEnabled = available;
        PersonalTab.IsEnabled = CodeTab.IsEnabled = RegisterButton.IsEnabled = AuthBack.IsEnabled = !busy;
        ReloadAccountButton.IsEnabled = available && native is not null;
        ApproveButton.IsEnabled = available && nativeAccount?.Kind == "player" && SubscriptionChoices.Items.Count > 0;
        ContinueButton.IsEnabled = ready && available;
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
    void PersonalInstead(object sender, RoutedEventArgs e) { forceSignIn = true; codeSelected = false; ResetNative(); Render(); EmailField.Focus(); }
    async Task RunAsync(Func<Task> operation)
    {
        if (busy || refreshing || lifetime.IsCancellationRequested) return;
        busy = true; Feedback.Text = ""; Render();
        try { await operation(); }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (NativeAccountException error) { Feedback.Text = error.UserMessage; }
        catch { Feedback.Text = "Не удалось подключиться. Проверьте интернет и повторите попытку."; }
        finally
        {
            busy = false;
            if (!lifetime.IsCancellationRequested) { await RefreshAsync(); Render(); }
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
            using var logout = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            logout.CancelAfter(TimeSpan.FromSeconds(3));
            try { await native.LogoutAsync(logout.Token); } catch { }
            native.Dispose(); native = null;
        });
    }
    async void ActivateCode(object sender, RoutedEventArgs e) => await ActivateAsync();
    async void CodeKeyDown(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) { e.Handled = true; await ActivateAsync(); } }
    async Task ActivateAsync()
    {
        if (busy || refreshing) return;
        string code = ConnectionCode.Password.Trim(); ConnectionCode.Clear();
        if (code.Length == 0) { Feedback.Text = "Введите код администратора."; return; }
        await RunAsync(async () => { try { await activation.ActivateAsync(code, lifetime.Token); Feedback.Text = activation.Status.Message; } finally { code = ""; } });
    }
    async void Retry(object sender, RoutedEventArgs e) { Feedback.Text = ""; await RefreshAsync(true); }
    async void Continue(object sender, RoutedEventArgs e) { await RefreshAsync(); if (Ready && !busy && !refreshing) Enter(); }
    void Enter()
    {
        if (transitioned || !Ready) return;
        transitioned = true; timer.Stop(); connected(); Close();
    }
    public void ShowFromTray() { Show(); WindowState = WindowState.Normal; Activate(); }
    public void Exit() => Close();
}