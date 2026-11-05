using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Neexitlag.Desktop;
using Button = System.Windows.Controls.Button;

internal static class WelcomeUiChecks
{
    sealed class Fixture : IServiceClient
    {
        internal string State="CODE_REQUIRED";
        internal List<string> Methods=[];
        public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default)
        {
            Methods.Add(method);
            object value=method switch {
                "activation.status" => new ActivationView{State=State,HasIdentity=State=="ACTIVATED",CapturePermitted=true},
                "activation.set" => new ActivationView{State="ACTIVATION_ERROR",Error="ACTIVATION_INVALID"},
                "account.status" => new AccountConnectionView(),
                "subscription.status" or "subscription.refresh" => new SubscriptionView(),
                _ => throw new InvalidOperationException("Unexpected IPC: "+method)
            };
            return Task.FromResult((T)value);
        }
    }
    static void Pump()
    {
        var frame=new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle,new Action(()=>frame.Continue=false));
        Dispatcher.PushFrame(frame);
    }
    static void Screenshot(Window window,string name)
    {
        window.UpdateLayout();
        var bitmap=new RenderTargetBitmap((int)window.ActualWidth,(int)window.ActualHeight,96,96,PixelFormats.Pbgra32);
        bitmap.Render(window);
        Directory.CreateDirectory("bin/native-ui-tests");
        using var file=File.Create("bin/native-ui-tests/"+name+".png");
        var encoder=new PngBitmapEncoder();encoder.Frames.Add(BitmapFrame.Create(bitmap));encoder.Save(file);
    }
    internal static void Run()
    {
        var fixture=new Fixture();bool entered=false;
        var window=new WelcomeWindow(fixture,()=>entered=true,false);
        window.Show();Pump();
        if(window.Access.CanContinue||entered)throw new Exception("Unactivated install entered desktop");
        Screenshot(window,"welcome-personal");
        ((Button)window.FindName("CodeTab")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));Pump();
        if(window.CodeInput.ActualHeight<42||window.CodeInput.ActualWidth<280||window.CodeInput.PasswordChar=='\0')throw new Exception("Connection code field clipped or unmasked");
        Screenshot(window,"welcome-code");
        fixture.Methods.Clear();
        window.CodeInput.Password="fixture-invalid-code";
        window.CodeSubmit.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));Pump();
        if(window.CodeInput.SecurePassword.Length!=0||entered||!fixture.Methods.Contains("activation.set"))throw new Exception("Code failure leaked input or granted access");
        fixture.State="ACTIVATED";
        window.RefreshAsync().GetAwaiter().GetResult();Pump();
        if(!window.Access.CanContinue)throw new Exception("Valid code activation not recognized");
        Screenshot(window,"welcome-connected");
        ((Button)window.FindName("ContinueButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));Pump();
        if(!entered||window.IsVisible)throw new Exception("Confirmed connection did not enter desktop");
        Console.WriteLine("PASS native welcome: personal/code/connected layout, masked code, failed activation gate, confirmed transition; no live credentials");
    }
}
