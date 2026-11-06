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
        internal List<string> Methods=[];
        public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default)
        {
            Methods.Add(method);
            object value=method switch {
                "activation.status" => new ActivationView{State="ACTIVATED",HasIdentity=true,CapturePermitted=true},
                "account.status" => new AccountConnectionView{State="LINKED",Kind="club",Name="Клуб на этом ПК"},
                "subscription.status" => new SubscriptionView(),
                _ => throw new InvalidOperationException("Cabinet must not escalate local permissions: "+method)
            };
            return Task.FromResult((T)value);
        }
    }
    sealed class Account : INativeCabinetClient
    {
        internal bool Disposed;
        internal NativeAccountSnapshot Snapshot=new(){Email="owner@example.test",Kind="club",Name="Клуб владельца",
            Subscriptions=[new(){Id=new string('b',32),Kind="club",Seats=36,UsedSeats=1,Lifetime=true,CanConnect=true,
                Devices=[new(){Name="ПК аккаунта",Machine="abcdef123456"}]}]};
        public Task SendCodeAsync(string email,CancellationToken ct)=>Task.CompletedTask;
        public Task<NativeAccountSnapshot> VerifyAsync(string email,string code,CancellationToken ct)=>code=="123456"?Task.FromResult(Snapshot):Task.FromException<NativeAccountSnapshot>(new NativeAccountException("LOGIN_CODE_INVALID"));
        public Task<NativeAccountSnapshot> RefreshAsync(CancellationToken ct)=>Task.FromResult(Snapshot);
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
    internal static void Run()
    {
        var service=new Service();var api=new Account();
        var window=new NativeCabinetWindow(new Uri("https://account.example.test/account"),service,()=>api);
        window.Show();Pump();Shot(window,"cabinet-sign-in");
        Require(((FrameworkElement)window.FindName("AccountPanel")).Visibility==Visibility.Collapsed,"Machine activation exposed owner cabinet");
        var email=(TextBox)window.FindName("Email");email.Text="owner@example.test";Click(window,"SendCode");
        Require(email.IsReadOnly,"OTP destination could drift from visible email");
        var code=(PasswordBox)window.FindName("Code");code.Password="000000";Click(window,"VerifyCode");
        Require(code.SecurePassword.Length==0&&((ItemsControl)window.FindName("Devices")).Items.Count==0,"Bad OTP exposed account");
        code.Password="123456";Click(window,"VerifyCode");
        Require(((FrameworkElement)window.FindName("AccountPanel")).Visibility==Visibility.Visible,"Account not shown after OTP");
        Require(((ItemsControl)window.FindName("Devices")).Items.Count==1,"Owned devices missing");
        Require(((FrameworkElement)window.FindName("ConnectPanel")).Visibility==Visibility.Collapsed,"Already linked club PC offers rebinding");
        Shot(window,"cabinet-club");window.Width=window.MinWidth;window.Height=window.MinHeight;Pump();Shot(window,"cabinet-minimum");
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
