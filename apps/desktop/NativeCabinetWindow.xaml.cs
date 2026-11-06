using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace Neexitlag.Desktop;

public partial class NativeCabinetWindow : Window
{
    readonly Uri origin;
    readonly NativeCabinetModel cabinet;
    readonly AccountConnectionModel connection;
    readonly ActivationModel activation;
    readonly SubscriptionModel subscription;
    readonly CancellationTokenSource lifetime = new();
    bool busy;
    DateTime resendAfter;
    public NativeCabinetWindow(Uri uri) : this(uri, new WindowsServiceClient()) { }
    internal NativeCabinetWindow(Uri uri, IServiceClient service, Func<INativeCabinetClient>? factory = null)
    {
        origin = new Uri(uri.GetLeftPart(UriPartial.Authority));
        cabinet = new(factory ?? (() => NativeAccountClient.ForCabinet(uri)));
        connection = new(service); activation = new(service); subscription = new(service);
        InitializeComponent(); WindowTheme.UseDarkCaption(this); Render();
        Loaded += async (_, _) => await Run(RefreshDevice);
        Closed += (_, _) => { lifetime.Cancel(); cabinet.Dispose(); Code.Clear(); Email.Clear(); ProfileName.Clear(); Feedback.Text = ""; ClearPrivateView(); };
    }
    static Visibility Visible(bool value) => value ? Visibility.Visible : Visibility.Collapsed;
    void ClearPrivateView()
    {
        AccountName.Text = AccountRole.Text = Rights.Text = "";
        Subscriptions.ItemsSource = Devices.ItemsSource = Payments.ItemsSource = SubscriptionChoice.ItemsSource = null;
    }
    void Render()
    {
        ClearPrivateView();
        var account = cabinet.Account;
        SignInPanel.Visibility = Visible(account is null);
        ProfilePanel.Visibility = Visible(account?.Kind == "");
        AccountPanel.Visibility = Visible(account is not null && account.Kind != "");
        CodePanel.Visibility = Visible(cabinet.CodeSent);
        Email.IsReadOnly = cabinet.CodeSent;
        SendCode.Content = cabinet.CodeSent ? "Отправить код ещё раз" : "Получить код";
        ChangeEmail.Visibility = Visible(cabinet.CodeSent);
        Email.IsEnabled = SendCode.IsEnabled = VerifyCode.IsEnabled = SaveProfile.IsEnabled = ChangeEmail.IsEnabled = !busy;
        RefreshAccount.IsEnabled = SignOut.IsEnabled = ProfileSignOut.IsEnabled = !busy;
        if (account is null) return;
        AccountName.Text = account.Name.Length > 0 ? account.Name : account.Email;
        AccountRole.Text = account.RoleLabel + " · " + account.Email;
        Rights.Text = account.Kind == "club" ? "Вы управляете подписками и компьютерами своего клуба. Вход в кабинет не меняет права управления этим ПК." : "Вы управляете своим аккаунтом и его компьютерами. Подключение VELIQ на ПК сохраняется после выхода из кабинета.";
        Subscriptions.ItemsSource = account.Subscriptions;
        var devices = account.Subscriptions.SelectMany(s => s.Devices.Select(d => new CabinetDeviceRow(s.Id, s.SeatsLabel, d, !busy))).ToList();
        Devices.ItemsSource = devices; Payments.ItemsSource = account.Payments;
        NoSubscriptions.Visibility = Visible(account.Subscriptions.Count == 0);
        NoDevices.Visibility = Visible(devices.Count == 0); NoPayments.Visibility = Visible(account.Payments.Count == 0);
        var choices = account.Subscriptions.Where(s => s.Kind == account.Kind && s.CanConnect).ToList();
        SubscriptionChoice.ItemsSource = choices; SubscriptionChoice.SelectedIndex = choices.Count > 0 ? 0 : -1;
        bool canLink = connection.Status.State is "NOT_LINKED" or "WAITING_FOR_BROWSER" or "EXPIRED" || connection.Status.ImagePreparation && !connection.Status.ImageReady;
        ConnectPanel.Visibility = Visible(canLink && choices.Count > 0);
        ConnectDevice.IsEnabled = !busy && canLink;
    }
    async Task Run(Func<Task> action)
    {
        if (busy || lifetime.IsCancellationRequested) return;
        busy = true; Feedback.Text = ""; Render();
        try { await action(); }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (NativeAccountException error) { if (!lifetime.IsCancellationRequested) Feedback.Text = error.UserMessage; }
        catch { if (!lifetime.IsCancellationRequested) Feedback.Text = "Не удалось выполнить действие. Проверьте подключение и повторите попытку."; }
        finally { busy = false; if (!lifetime.IsCancellationRequested) Render(); }
    }
    async Task RefreshDevice()
    {
        await connection.RefreshAsync(lifetime.Token); await activation.RefreshAsync(lifetime.Token); await subscription.RefreshAsync(false, lifetime.Token);
        var access = WelcomeAccess.Evaluate(activation.Status, connection.Status, subscription.Status);
        DeviceAccess.Text = access.CanContinue ? "VELIQ подключён" : access.Title;
        DeviceHint.Text = access.CanContinue ? (connection.Status.Linked ? "Подключён: " + connection.Status.KindLabel + ". Для управления аккаунтом подтвердите свою почту ниже." : "Этот компьютер активирован по коду. Вход в кабинет выполняется отдельно.") : access.Message;
    }
    async void Send(object sender, RoutedEventArgs e) => await Run(async () => {
        if (DateTime.UtcNow < resendAfter) { Feedback.Text = "Повторно отправить код можно через минуту."; return; }
        Code.Clear(); await cabinet.SendCodeAsync(Email.Text, lifetime.Token); resendAfter = DateTime.UtcNow.AddMinutes(1);
        Feedback.Text = "Код отправлен на " + cabinet.Email;
    });
    async void Verify(object sender, RoutedEventArgs e) => await Run(async () => { string code = Code.Password; Code.Clear(); await cabinet.VerifyAsync(code, lifetime.Token); });
    async void CreateProfile(object sender, RoutedEventArgs e) => await Run(async () => {
        string kind = (ProfileKind.SelectedItem as ComboBoxItem)?.Tag as string ?? "";
        await cabinet.CreateProfileAsync(kind, ProfileName.Text, lifetime.Token); ProfileName.Clear();
    });
    async void Refresh(object sender, RoutedEventArgs e) => await Run(async () => { await cabinet.RefreshAsync(lifetime.Token); await RefreshDevice(); });
    async void Logout(object sender, RoutedEventArgs e) => await Run(async () => {
        var logout = cabinet.LogoutAsync(lifetime.Token); Email.Clear(); Code.Clear(); ProfileName.Clear(); Render(); await logout;
    });
    void ChangeAddress(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        cabinet.Reset(); Code.Clear(); Feedback.Text = ""; Render(); Email.Focus();
    }
    async void Release(object sender, RoutedEventArgs e)
    {
        if (busy || sender is not Button { Tag: CabinetDeviceRow row }) return;
        if (MessageBox.Show(this, "Отключить «" + row.Device.Name + "» от подписки? VELIQ на этом компьютере потеряет доступ. Для возврата потребуется новое подтверждение.", "Отключить компьютер", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await Run(async () => { await cabinet.ReleaseAsync(row.Subscription, row.Device.Machine, lifetime.Token); await RefreshDevice(); });
    }
    async void Connect(object sender, RoutedEventArgs e)
    {
        if (busy || SubscriptionChoice.SelectedItem is not NativeSubscription selected) return;
        await Run(async () => {
            await connection.RefreshAsync(lifetime.Token);
            if (connection.Status.Linked || connection.Status.ImageReady) { await RefreshDevice(); return; }
            await connection.StartAsync(lifetime.Token);
            var until = DateTime.UtcNow.AddSeconds(20);
            while (connection.Status.State == "STARTING" && DateTime.UtcNow < until) { await Task.Delay(500, lifetime.Token); await connection.RefreshAsync(lifetime.Token); }
            if (connection.Status.VerificationUri is not {} uri) throw new NativeAccountException(connection.Status.Error.Length > 0 ? connection.Status.Error : "ACCOUNT_LINK_INVALID");
            await cabinet.ApproveAsync(uri, selected.Id, lifetime.Token);
            Feedback.Text = "Подтверждение отправлено. Нажмите «Обновить», чтобы проверить подключение компьютера.";
            await RefreshDevice();
        });
    }
    void EmailKey(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) { e.Handled = true; Send(sender, new()); } }
    void CodeKey(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) { e.Handled = true; Verify(sender, new()); } }
    void Support(object sender, RoutedEventArgs e)
    {
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(new Uri(origin, "/support").AbsoluteUri) { UseShellExecute = true }); }
        catch { Feedback.Text = "Не удалось открыть страницу поддержки."; }
    }
    sealed record CabinetDeviceRow(string Subscription, string SubscriptionLabel, NativeAccountDevice Device, bool CanRelease);
}
