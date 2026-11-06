using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Neexitlag.Desktop;
using Button = System.Windows.Controls.Button;
using TextBox = System.Windows.Controls.TextBox;
using PasswordBox = System.Windows.Controls.PasswordBox;
using ItemsControl = System.Windows.Controls.ItemsControl;
using TextBlock = System.Windows.Controls.TextBlock;

internal static class CabinetUiChecks
{
    sealed class Service : IServiceClient
    {
        internal string Kind = "club";
        internal List<string> Methods=[];
        public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default)
        {
            Methods.Add(method);
            object value=method switch {
                "activation.status" => new ActivationView{State="ACTIVATED",HasIdentity=true,CapturePermitted=true},
                "account.status" => new AccountConnectionView{State="LINKED",Kind=Kind,Name="Тестовый ПК"},
                "subscription.status" => new SubscriptionView(),
                _ => throw new InvalidOperationException("Cabinet must not escalate local permissions: "+method)
            };
            return Task.FromResult((T)value);
        }
    }
    sealed class Account : INativeCabinetClient
    {
        internal Action? Verified;
        internal Func<NativeAccountSnapshot>? Revalidate;
        internal bool Disposed;
        internal NativeAccountSnapshot Snapshot=new(){Email="owner@example.test",Kind="club",Name="Клуб владельца",
            Subscriptions=[new(){Id=new string('b',32),Kind="club",Seats=36,UsedSeats=1,Lifetime=true,CanConnect=true,
                Devices=[new(){Name="ПК аккаунта",Machine="abcdef123456"}]}]};
        public Task SendCodeAsync(string email,CancellationToken ct)=>Task.CompletedTask;
        public Task<NativeAccountSnapshot> VerifyAsync(string email,string code,CancellationToken ct)
        {
            if (code != "123456") throw new NativeAccountException("LOGIN_CODE_INVALID");
            Verified?.Invoke();
            return Task.FromResult(Snapshot);
        }
        public Task<NativeAccountSnapshot> RefreshAsync(CancellationToken ct)=>Task.FromResult(Revalidate is null ? Snapshot : Revalidate());
        public Task<NativeAccountSnapshot> CreatePersonalProfileAsync(string name,CancellationToken ct)=>throw new NotSupportedException();
        public Task<NativeAccountSnapshot> CreateProfileAsync(string kind,string name,CancellationToken ct)=>throw new NotSupportedException();
        public Task<NativeDeviceLink> DeviceAsync(CancellationToken ct)=>throw new NotSupportedException();
        public Task ApproveAsync(string sub,CancellationToken ct)=>throw new NotSupportedException();
        public Task ApproveDeviceAsync(Uri verification,string sub,CancellationToken ct)=>throw new NotSupportedException();
        public Task ReleaseDeviceAsync(string sub,string machine,CancellationToken ct)=>throw new NotSupportedException();
        public Task LogoutAsync(CancellationToken ct)=>Task.CompletedTask;
        public void Dispose()=>Disposed=true;
    }
    static void Pump(){var frame=new DispatcherFrame();Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle,new Action(()=>frame.Continue=false));Dispatcher.PushFrame(frame);}
    static void Click(Window w,string name){((Button)w.FindName(name)).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));Pump();}
    static void Require(bool value,string error){if(!value)throw new Exception(error);}
    static void Shot(Window w,string name)
    {
        w.UpdateLayout();var bmp=new RenderTargetBitmap((int)w.ActualWidth,(int)w.ActualHeight,96,96,PixelFormats.Pbgra32);bmp.Render(w);
        Directory.CreateDirectory("bin/native-ui-tests");using var file=File.Create("bin/native-ui-tests/"+name+".png");
        var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bmp));encoder.Save(file);
    }
    // Each phase can be launched in a fresh process. No production endpoint, token,
    // mouse input, real user preferences or live service is used by this fixture.
    internal static void PersonalSession(Guid fixture, string phase)
    {
        var uri = new Uri($"https://{fixture:N}.example.invalid/account");
        var store = new PersonalCabinetSession(uri);
        var endpoint = new Uri(uri, "/api/v1/account");
        var service = new Service { Kind = phase == "club" ? "club" : "player" };
        var api = new Account();
        api.Verified = () => store.Cookies.Add(endpoint, new System.Net.Cookie("veliq_session", new string('x',43), "/api/v1/account") { Secure=true, HttpOnly=true });
        api.Revalidate = () => {
            Require(store.Cookies.GetCookies(endpoint)["veliq_session"]?.Value == new string('x',43), "Credential missing from resumed client");
            if (phase == "expired") throw new NativeAccountException("ACCOUNT_LOGIN_REQUIRED");
            if (phase is "offline" or "offline-logout") throw new NativeAccountException("ACCOUNT_UNAVAILABLE");
            return api.Snapshot;
        };
        var window = new NativeCabinetWindow(uri, service, () => api, store) { ShowActivated=false, ShowInTaskbar=false, Opacity=0 };
        bool Visible(string name) => ((FrameworkElement)window.FindName(name)).Visibility == Visibility.Visible;
        try
        {
            window.Show(); Pump();
            switch (phase)
            {
                case "login":
                case "once":
                    Require(Visible("SignInPanel") && Visible("RememberCabinet"), "Personal login choice missing");
                    ((System.Windows.Controls.CheckBox)window.FindName("RememberCabinet")).IsChecked = phase == "login";
                    ((TextBox)window.FindName("Email")).Text="fixture@example.invalid";
                    Click(window,"SendCode"); ((PasswordBox)window.FindName("Code")).Password="123456"; Click(window,"VerifyCode");
                    Require(Visible("AccountPanel"), "Fixture sign-in failed: " + ((TextBlock)window.FindName("Feedback")).Text);
                    break;
                case "reopen":
                case "logout":
                    Require(Visible("AccountPanel") && !Visible("SignInPanel"), "Restored cabinet requested another code");
                    if (phase == "logout") { Click(window,"SignOut"); Require(Visible("SignInPanel"), "Logout failed"); }
                    break;
                case "offline":
                case "offline-logout":
                    Require(Visible("ResumePanel") && !Visible("AccountPanel"), "Offline restore revealed data or hid logout");
                    if (phase == "offline-logout")
                    {
                        var panel = (System.Windows.Controls.Panel)window.FindName("ResumePanel");
                        var actions = (System.Windows.Controls.Panel)panel.Children[1];
                        ((Button)actions.Children[1]).RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); Pump();
                        Require(Visible("SignInPanel"), "Offline logout kept the remembered session");
                    }
                    break;
                case "expired":
                case "signed-out":
                case "club":
                    Require(Visible("SignInPanel") && !Visible("AccountPanel") && !Visible("ResumePanel"), "Invalid or club credential restored");
                    if (phase == "club") Require(!Visible("RememberCabinet"), "Club persistence enabled");
                    break;
                default: throw new ArgumentException("Unknown fixture phase");
            }
        }
        finally { window.Close(); }
        Console.WriteLine("PASS personal-cabinet " + phase);
    }
    internal static void Run()
    {
        var service=new Service();var api=new Account();
        var window=new NativeCabinetWindow(new Uri("https://account.example.test/account"),service,()=>api);
        window.Show();Pump();Shot(window,"cabinet-sign-in");
        Require(((FrameworkElement)window.FindName("AccountPanel")).Visibility==Visibility.Collapsed,"Machine activation exposed owner cabinet");
        Require(((TextBlock)window.FindName("DeviceAccess")).Text=="VELIQ подключён","Device status impersonates account sign-in");
        var email=(TextBox)window.FindName("Email");email.Text="owner@example.test";Click(window,"SendCode");
        Require(email.IsReadOnly,"OTP destination could drift from visible email");
        var code=(PasswordBox)window.FindName("Code");code.Password="000000";Click(window,"VerifyCode");
        Require(code.SecurePassword.Length==0&&((ItemsControl)window.FindName("Devices")).Items.Count==0,"Bad OTP exposed account");
        code.Password="123456";Click(window,"VerifyCode");
        Require(((FrameworkElement)window.FindName("AccountPanel")).Visibility==Visibility.Visible,"Account not shown after OTP");
        Require(((ItemsControl)window.FindName("Devices")).Items.Count==1,"Owned devices missing");
        Require(((FrameworkElement)window.FindName("ConnectPanel")).Visibility==Visibility.Collapsed,"Already linked club PC offers rebinding");
        Shot(window,"cabinet-club");window.Width=window.MinWidth;window.Height=window.MinHeight;Pump();Shot(window,"cabinet-minimum");
        var scroll=(System.Windows.Controls.ScrollViewer)window.FindName("CabinetContent");scroll.ScrollToEnd();Pump();
        Require(scroll.ScrollableHeight>0&&scroll.VerticalOffset>0,"Small cabinet cannot reach devices and payments");Shot(window,"cabinet-minimum-bottom");
        Click(window,"SignOut");
        Require(api.Disposed&&((ItemsControl)window.FindName("Devices")).Items.Count==0&&((ItemsControl)window.FindName("Subscriptions")).Items.Count==0,"Logout retained account data");
        Require(((TextBlock)window.FindName("AccountRole")).Text.Length==0&&email.Text.Length==0,"Logout retained identity");
        Require(service.Methods.All(m=>m is "account.status" or "activation.status" or "subscription.status"),"Cabinet changed machine access without service consent");
        window.Close();
        api=new(){Snapshot=new(){Email="new@example.test"}};
        window=new NativeCabinetWindow(new Uri("https://account.example.test/account"),service,()=>api);window.Show();Pump();
        ((TextBox)window.FindName("Email")).Text="new@example.test";Click(window,"SendCode");((PasswordBox)window.FindName("Code")).Password="123456";Click(window,"VerifyCode");
        Require(((FrameworkElement)window.FindName("ProfilePanel")).Visibility==Visibility.Visible,"New profile step missing");Shot(window,"cabinet-profile");
        Click(window,"ProfileSignOut");Require(api.Disposed,"Incomplete profile could not sign out");window.Close();
        Console.WriteLine("PASS native cabinet: OTP/club/devices/minimum layout/logout/profile; no live account or permission changes");
    }
}
