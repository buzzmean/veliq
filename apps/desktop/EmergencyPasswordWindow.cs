using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
namespace Neexitlag.Desktop;

internal sealed class EmergencyPasswordWindow : Window
{
    readonly bool setup;
    readonly IServiceClient service;
    readonly PasswordBox password = new() { MaxLength = 256, MinHeight = 42, FontSize = 18 };
    readonly PasswordBox confirm = new() { MaxLength = 256, MinHeight = 42, FontSize = 18 };
    readonly TextBlock status = new() { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,16,0,16) };
    readonly Button submit = new() { MinHeight = 42, IsDefault = true };
    bool busy;
    internal bool Succeeded { get; private set; }
    internal PasswordBox PasswordInput => password;
    internal Button SubmitButton => submit;

    internal EmergencyPasswordWindow(bool setup, IServiceClient? service = null)
    {
        this.setup = setup;
        this.service = service ?? new ServiceClient();
        Title = setup ? "VELIQ — пароль аварийного отключения" : "VELIQ — аварийное отключение";
        Width = 510; SizeToContent = SizeToContent.Height; ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = (Brush)FindResource("Bg"); Foreground = (Brush)FindResource("Text");
        FontFamily = (FontFamily)FindResource("VeliqFont"); FontSize = 15;
        WindowTheme.UseDarkCaption(this);
        var panel = new StackPanel { Margin = new Thickness(28) };
        panel.Children.Add(new TextBlock { Text = setup ? "Задайте отдельный пароль VELIQ" : "Аварийно отключить VELIQ",
            FontSize = 24, FontWeight = FontWeights.Bold, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,0,0,16) });
        panel.Children.Add(new TextBlock { Text = setup
            ? "Этот пароль работает без интернета. Не используйте пароль почты. Для сохранения нужны права администратора Windows и учётная запись владельца установки."
            : "VELIQ остановит маршрутизацию, восстановит изменённые им настройки сети и закроется. Перезагрузка ПК не нужна. Введите отдельный пароль VELIQ.",
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,0,0,18) });
        panel.Children.Add(new TextBlock { Text = "Пароль VELIQ", Margin = new Thickness(0,0,0,6) });
        panel.Children.Add(password);
        if (setup)
        {
            panel.Children.Add(new TextBlock { Text = "Повторите пароль (минимум 8 символов)", Margin = new Thickness(0,14,0,6) });
            panel.Children.Add(confirm);
        }
        panel.Children.Add(status);
        submit.Content = setup ? "Сохранить пароль" : "Отключить VELIQ";
        submit.Click += async (_,_) => await SubmitAsync();
        panel.Children.Add(submit);
        var cancel = new Button { Content = "Отмена", MinHeight = 36, Margin = new Thickness(0,10,0,0) };
        cancel.Click += (_,_) => { if (!busy) Close(); };
        panel.Children.Add(cancel);
        Content = panel;
        Loaded += (_,_) => password.Focus();
        Closing += (_,e) => { if (busy) e.Cancel = true; };
        Closed += (_,_) => { password.Clear(); confirm.Clear(); };
    }

    static byte[] Bytes(SecureString value)
    {
        IntPtr pointer = Marshal.SecureStringToGlobalAllocUnicode(value);
        char[] characters = new char[value.Length];
        try { Marshal.Copy(pointer,characters,0,characters.Length); return Encoding.UTF8.GetBytes(characters); }
        finally { Array.Clear(characters); Marshal.ZeroFreeGlobalAllocUnicode(pointer); }
    }

    async Task SubmitAsync()
    {
        if (busy) return;
        using var secure = password.SecurePassword;
        using var confirmation = confirm.SecurePassword;
        if (setup && secure.Length < 8) { status.Text = "Используйте не менее 8 символов."; return; }
        byte[] bytes = Bytes(secure), repeated = setup ? Bytes(confirmation) : Array.Empty<byte>();
        if (setup && !CryptographicOperations.FixedTimeEquals(bytes,repeated))
        {
            CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(repeated);
            status.Text = "Пароли не совпадают."; return;
        }
        CryptographicOperations.ZeroMemory(repeated);
        password.Clear(); confirm.Clear();
        busy = true; submit.IsEnabled = false; password.IsEnabled = confirm.IsEnabled = false;
        status.Text = setup ? "Сохраняем защищённую проверку пароля…" : "Останавливаем VELIQ и проверяем восстановление настроек…";
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            if (setup) await EmergencyPasswordStore.SaveAsync(bytes);
            else await EmergencyExitFlow.StopAsync(service,bytes,deadline.Token);
            Succeeded = true; busy = false; Close();
        }
        catch (Exception error)
        {
            status.Text = Message(error,setup);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            busy = false; submit.IsEnabled = true; password.IsEnabled = confirm.IsEnabled = true;
        }
    }
    internal static string Message(Exception error, bool setup) => error.Message switch
    {
        "EMERGENCY_CLUB_ONLY" => "Аварийное отключение доступно только администратору клубной установки. На личном ПК используйте обычное отключение VELIQ.",
        "EMERGENCY_PASSWORD_INVALID" => "Неверный пароль VELIQ. Настройки не изменены.",
        "EMERGENCY_PASSWORD_RATE_LIMIT" => "Слишком много неверных попыток. Подождите 5 минут.",
        "EMERGENCY_PASSWORD_NOT_CONFIGURED" => "Пароль ещё не настроен. В меню VELIQ выберите «Настроить пароль отключения…».",
        "EMERGENCY_PASSWORD_UNAVAILABLE" => "Защищённая проверка пароля недоступна. Обратитесь к владельцу установки.",
        "EMERGENCY_CLEANUP_FAILED" => "Не удалось подтвердить восстановление всех настроек. Окно остаётся открытым; обратитесь к администратору.",
        "EMERGENCY_STOP_NOT_CONFIRMED" => "Завершение VELIQ ещё не подтверждено.",
        _ => setup ? "Не удалось сохранить пароль. Нужны работающая служба новой версии, права администратора и учётная запись владельца установки."
                   : "Отключение не подтверждено. Проверьте состояние службы VELIQ; окно остаётся открытым."
    };
}
