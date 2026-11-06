using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Neexitlag.Desktop;
using Button = System.Windows.Controls.Button;
using TextBox = System.Windows.Controls.TextBox;
using PasswordBox = System.Windows.Controls.PasswordBox;

internal static class WelcomeUiChecks
{
    sealed class Fixture : IServiceClient
    {
        internal string State="CODE_REQUIRED";
        internal bool Started, Linked;
        internal List<string> Methods=[];
        public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default)
        {
            Methods.Add(method);
            if(method=="account.link.start")Started=true;
            object value=method switch {
                "activation.status" => new ActivationView{State=State,HasIdentity=State=="ACTIVATED",CapturePermitted=true},
                "activation.set" => new ActivationView{State="ACTIVATION_ERROR",Error="ACTIVATION_INVALID"},
                "account.status" or "account.link.start" => new AccountConnectionView{
                    State=Linked?"LINKED":Started?"WAITING_FOR_BROWSER":"NOT_LINKED", Kind=Linked?"player":"",
                    VerificationUrl=Started?"https://account.example.test/account.html#device=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":""},
                "subscription.status" or "subscription.refresh" => new SubscriptionView(),
                _ => throw new InvalidOperationException("Unexpected IPC: "+method)
            };
            return Task.FromResult((T)value);
        }
    }
    sealed class Account : INativeAccountClient
    {
        internal bool Approved, Disposed, LoggedOut;
        NativeAccountSnapshot snapshot=new(){Email="fixture@example.test"};
        public Task SendCodeAsync(string email,CancellationToken ct)=>Task.CompletedTask;
        public Task<NativeAccountSnapshot> VerifyAsync(string email,string code,CancellationToken ct)
        {
            if(code!="123456")throw new NativeAccountException("LOGIN_CODE_INVALID");
            return Task.FromResult(snapshot);
        }
        public Task<NativeAccountSnapshot> CreatePersonalProfileAsync(string name,CancellationToken ct)
        {
            snapshot=new(){Email="fixture@example.test",Kind="player",Subscriptions=[new(){Id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",Kind="player",Seats=1,CanConnect=true,Lifetime=true}]};
            return Task.FromResult(snapshot);
        }
        public Task<NativeAccountSnapshot> RefreshAsync(CancellationToken ct)=>Task.FromResult(snapshot);
        public Task<NativeDeviceLink> DeviceAsync(CancellationToken ct)=>Task.FromResult(new NativeDeviceLink{Name="Тестовый компьютер",Mode="device"});
        public Task ApproveAsync(string subscription,CancellationToken ct){Approved=true;return Task.CompletedTask;}
        public Task LogoutAsync(CancellationToken ct){LoggedOut=true;return Task.CompletedTask;}
        public void Dispose()=>Disposed=true;
    }
    static void Pump()
    {
        var frame=new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle,new Action(()=>frame.Continue=false));
        Dispatcher.PushFrame(frame);
    }
    static void Click(Window w,string name){((Button)w.FindName(name)).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));Pump();}
    static void Panel(Window w,string name){if(((FrameworkElement)w.FindName(name)).Visibility!=Visibility.Visible)throw new Exception("Missing step: "+name);}
    static void Screenshot(Window window,string name)
    {
        window.UpdateLayout();
        var bitmap=new RenderTargetBitmap((int)window.ActualWidth,(int)window.ActualHeight,96,96,PixelFormats.Pbgra32);
        bitmap.Render(window);
        Directory.CreateDirectory("bin/native-ui-tests");
        using var file=File.Create("bin/native-ui-tests/"+name+".png");
        var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));encoder.Save(file);
    }
    internal static void PersonalSession(Guid fixtureId, bool remember)
    {
        var address = new Uri($"https://{fixtureId:N}.example.invalid/account");
        var store = new PersonalCabinetSession(address);
        var api = new Account();
        // Seed only the fixture's own cookie jar. Real cookies arrive from the
        // HTTPS handler during VerifyAsync; both flows call the production Save.
        store.Cookies.Add(new Uri(address, "/api/v1/account"), new System.Net.Cookie("veliq_session",new string('x',43),"/api/v1/account"){Secure=true,HttpOnly=true});
        var window = new WelcomeWindow(new Fixture(), () => {}, false, _ => api, session:store){ShowActivated=false,ShowInTaskbar=false,Opacity=0};
        try
        {
            window.Show();Pump();Panel(window,"RememberPersonal");
            ((System.Windows.Controls.CheckBox)window.FindName("RememberPersonal")).IsChecked=remember;
            ((TextBox)window.FindName("EmailField")).Text="fixture@example.test";Click(window,"EmailSubmit");
            ((PasswordBox)window.FindName("LoginCode")).Password="123456";Click(window,"VerifySubmit");
            Click(window,"ProfileSubmit");Click(window,"ApproveButton");Panel(window,"ConnectingPanel");
            if(!api.Approved || !api.Disposed || api.LoggedOut == remember)throw new Exception("Welcome consent did not control retention");
        }
        finally {window.Close();}
        Console.WriteLine("PASS personal welcome remember=" + remember);
    }
    internal static void Run()
    {
        var fixture=new Fixture();var api=new Account();bool entered=false;
        var window=new WelcomeWindow(fixture,()=>entered=true,false,_=>api);
        window.Show();Pump();
        if(window.Access.CanContinue||entered)throw new Exception("Unactivated install entered desktop");
        Panel(window,"EmailPanel");Screenshot(window,"welcome-personal");
        window.Width=window.MinWidth;window.Height=window.MinHeight;Pump();
        Screenshot(window,"welcome-minimum");
        ((TextBox)window.FindName("EmailField")).Text="fixture@example.test";
        Click(window,"EmailSubmit");Panel(window,"OtpPanel");Screenshot(window,"welcome-email-code");
        var otp=(PasswordBox)window.FindName("LoginCode");
        otp.Password="000000";Click(window,"VerifySubmit");
        if(otp.SecurePassword.Length!=0||entered||api.Approved)throw new Exception("Bad OTP leaked or granted access");
        Panel(window,"OtpPanel");
        otp.Password="123456";Click(window,"VerifySubmit");Panel(window,"ProfilePanel");
        Screenshot(window,"welcome-profile");
        Click(window,"ProfileSubmit");Panel(window,"AccountPanel");Screenshot(window,"welcome-account");
        Click(window,"ApproveButton");Panel(window,"ConnectingPanel");
        if(!api.Approved||!api.Disposed||entered)throw new Exception("Approval bypassed service or retained account client");
        fixture.Linked=true;fixture.State="ACTIVATED";
        window.RefreshAsync().GetAwaiter().GetResult();Pump();
        Panel(window,"ReadyPanel");Screenshot(window,"welcome-connected");
        Click(window,"ContinueButton");
        if(!entered||window.IsVisible)throw new Exception("Confirmed connection did not enter desktop");

        fixture=new();entered=false;
        window=new WelcomeWindow(fixture,()=>entered=true,false);
        window.Show();Pump();Click(window,"CodeTab");Panel(window,"CodePanel");
        if(window.CodeInput.ActualHeight<42||window.CodeInput.ActualWidth<280||window.CodeInput.PasswordChar=='\0')throw new Exception("Connection code clipped or unmasked");
        Screenshot(window,"welcome-code");
        window.CodeInput.Password="fixture-invalid-code";Click(window,"ActivateButton");
        if(window.CodeInput.SecurePassword.Length!=0||entered||!fixture.Methods.Contains("activation.set"))throw new Exception("Code failure leaked input or granted access");
        fixture.State="ACTIVATED";window.RefreshAsync().GetAwaiter().GetResult();Pump();
        Panel(window,"ReadyPanel");Click(window,"ContinueButton");
        if(!entered||window.IsVisible)throw new Exception("Legacy code connection not recognized");
        Console.WriteLine("PASS native welcome: email/OTP/profile/approval/service gate/club code; fixture only, no live credentials");
    }
}
