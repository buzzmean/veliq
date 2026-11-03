using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Neexitlag.Desktop;

internal static class EmergencyUiChecks
{
    sealed class Fixture : IServiceClient
    {
        internal bool Reject=true;
        internal List<string> Methods=[];
        public Task<T> Call<T>(string method,object? payload=null,CancellationToken cancellationToken=default)
        {
            Methods.Add(method);
            if(Reject)throw new ServiceException(ServiceFailure.Rejected,"EMERGENCY_PASSWORD_INVALID");
            return Task.FromResult((T)(object)new EmergencyStatus{Configured=true,State="STOPPED"});
        }
    }
    static void Pump()
    {
        var frame=new DispatcherFrame();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle,new Action(()=>frame.Continue=false));
        Dispatcher.PushFrame(frame);
    }
    internal static void Run()
    {
        var service=new Fixture();
        var window=new EmergencyPasswordWindow(false,service);
        window.Show();Pump();
        if(window.PasswordInput.ActualWidth<350||window.PasswordInput.ActualHeight<40||window.PasswordInput.PasswordChar=='\0')
            throw new Exception("Emergency password field is not usable/masked");
        window.PasswordInput.Password="fixture-password";
        window.SubmitButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));Pump();
        if(!window.IsVisible||window.Succeeded||window.PasswordInput.SecurePassword.Length!=0||service.Methods.Count!=1)
            throw new Exception("Wrong emergency password did not leave a cleared, open dialog");
        service.Reject=false;service.Methods.Clear();
        window.PasswordInput.Password="fixture-password";
        window.SubmitButton.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));Pump();
        if(window.IsVisible||!window.Succeeded||!service.Methods.SequenceEqual(new[]{"emergency.stop","emergency.finish"}))
            throw new Exception("Emergency GUI closed without both acknowledgements");
        var setup=new EmergencyPasswordWindow(true);
        setup.Show();Pump();
        if(setup.PasswordInput.ActualWidth<350)throw new Exception("Setup field clipped");
        setup.Close();
        Console.WriteLine("PASS native emergency dialog: masked input, wrong-password failure, acknowledged close; no live service/registry writes");
    }
}
