using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Veliq.Desktop;
using Button = System.Windows.Controls.Button;
using TextBox = System.Windows.Controls.TextBox;
using PasswordBox = System.Windows.Controls.PasswordBox;

internal static class WelcomeUiChecks
{
    sealed class Fixture : IServiceClient
    {
        internal string State="CODE_REQUIRED";
        internal bool Started, Linked, AcceptCode;
        internal List<string> Methods=[];
        public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default)
        {
            Methods.Add(method);
            if(method=="account.link.start")Started=true;
            if(method=="activation.set" && AcceptCode)State="ACTIVATED";
            object value=method switch {
                "activation.status" => new ActivationView{State=State,HasIdentity=State=="ACTIVATED",CapturePermitted=true},
                "activation.set" => AcceptCode ? new ActivationView{State=State,HasIdentity=true,CapturePermitted=true} : new ActivationView{State="ACTIVATION_ERROR",Error="ACTIVATION_INVALID"},
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
        if(!entered||window.IsVisible)throw new Exception("Confirmed connection did not enter desktop");

        fixture=new();entered=false;
        window=new WelcomeWindow(fixture,()=>entered=true,false);
        window.Show();Pump();Click(window,"CodeTab");Panel(window,"CodePanel");
        if(window.CodeInput.ActualHeight<42||window.CodeInput.ActualWidth<280||window.CodeInput.PasswordChar=='\0')throw new Exception("Connection code clipped or unmasked");
        Screenshot(window,"welcome-code");
        window.CodeInput.Password="fixture-invalid-code";Click(window,"ActivateButton");
        if(window.CodeInput.SecurePassword.Length!=0||entered||!fixture.Methods.Contains("activation.set"))throw new Exception("Code failure leaked input or granted access");
        fixture.AcceptCode=true;window.CodeInput.Password="fixture-valid-code";Click(window,"ActivateButton");
        if(!entered||window.IsVisible)throw new Exception("Legacy code connection not recognized");
        Startup();
        ActivationCompletion();
        Console.WriteLine("PASS native welcome: email/OTP/profile/approval/service gate/club code; fixture only, no live credentials");
    }
    sealed class CodeCompletion : IServiceClient
    {
        internal string State = "CODE_REQUIRED";
        internal bool LoseSetReply;
        internal int Sets;
        internal TaskCompletionSource<ActivationView> Reply = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default)
        {
            if(method=="activation.set")
            {
                Sets++; State=LoseSetReply?"ACTIVATED":"ACTIVATING";
                if(LoseSetReply)return (Task<T>)(object)Reply.Task;
            }
            object value=method switch{
                "activation.status" or "activation.set"=>new ActivationView{State=State,HasIdentity=State=="ACTIVATED"},
                "account.status"=>new AccountConnectionView(),
                "subscription.status" or "subscription.refresh"=>new SubscriptionView(),
                _=>throw new InvalidOperationException(method)
            };
            return Task.FromResult((T)value);
        }
    }
    static void PumpUntil(Func<bool> ready)
    {
        var until=DateTime.UtcNow.AddSeconds(6);
        while(!ready()&&DateTime.UtcNow<until){Pump();Thread.Sleep(10);}
        Pump();if(!ready())throw new Exception("Activation did not complete without a manual refresh/restart");
    }
    static void ActivationCompletion()
    {
        foreach(bool lostReply in new[]{false,true})
        {
            var fixture=new CodeCompletion{LoseSetReply=lostReply};int entries=0;
            var window=new WelcomeWindow(fixture,()=>entries++,false);
            try
            {
                window.Show();Pump();Click(window,"CodeTab");
                window.CodeInput.Password="fixture-private-code";Click(window,"ActivateButton");
                if(window.CodeInput.SecurePassword.Length!=0)throw new Exception("Activation input retained");
                if(!lostReply)fixture.State="ACTIVATED";
                PumpUntil(()=>entries==1);
                if(window.IsVisible||fixture.Sets!=1)throw new Exception("Activation required resubmission/restart");
                fixture.Reply.TrySetResult(new(){State="ACTIVATING"});Pump();
                if(entries!=1||!window.Access.CanContinue)throw new Exception("Late activation reply regressed ready state");
            }
            finally{fixture.Reply.TrySetCanceled();window.Close();Pump();}
        }
        Console.WriteLine("PASS activation: automatic poll after pending, lost set reply, late reply, one submission/entry, no restart");
    }
    static void Startup()
    {
        foreach(bool quiet in new[]{false,true})
        {
            var fixture=new Fixture{State="ACTIVATED"};int entries=0,shows=0;
            var window=new WelcomeWindow(fixture,()=>entries++,false);
            window.IsVisibleChanged+=(_,_)=>{if(window.IsVisible)shows++;};
            window.StartAsync(quiet).GetAwaiter().GetResult();Pump();
            window.RefreshAsync().GetAwaiter().GetResult();Pump();
            if(entries!=1||shows!=0||window.StartupTrayVisible)throw new Exception("Activated startup flashed onboarding or duplicated entry/tray");
        }
        var waiting=new Fixture();int completed=0;
        var pending=new WelcomeWindow(waiting,()=>completed++,false);
        pending.StartAsync(true).GetAwaiter().GetResult();Pump();
        if(pending.IsVisible||!pending.StartupTrayVisible||completed!=0)throw new Exception("Quiet startup must wait behind a visible tray icon");
        pending.ShowFromTray();Pump();
        if(!pending.IsVisible||!pending.ForegroundRequested)throw new Exception("Waiting tray must allow opening onboarding");
        waiting.State="ACTIVATED";pending.RefreshAsync().GetAwaiter().GetResult();Pump();
        if(completed!=1||pending.StartupTrayVisible||pending.IsVisible)throw new Exception("Delayed activation did not finish quiet startup");
        var protectedSignIn=new WelcomeWindow(new Fixture{State="ACTIVATED"},()=>throw new Exception("Explicit account sign-in bypassed"),false,forceSignIn:true);
        protectedSignIn.StartAsync(false).GetAwaiter().GetResult();Pump();
        if(!protectedSignIn.IsVisible)throw new Exception("Explicit account sign-in must remain visible");
        protectedSignIn.Close();Pump();
        Console.WriteLine("PASS confirmed code auto-entry once, no welcome flash, delayed quiet startup/tray, explicit sign-in gate");
    }
}
