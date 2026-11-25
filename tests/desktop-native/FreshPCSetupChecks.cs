using System.IO;
using Veliq.Desktop;
internal static class FreshPCSetupChecks
{
    internal static void Run()
    {
        static void Require(bool ok) { if (!ok) throw new Exception("Fresh-PC argument contract failed"); }
        static void Reject(Action action) { bool failed=false;try{action();}catch(ArgumentException){failed=true;}Require(failed); }
        var folder=Path.Combine(Path.GetTempPath(),"veliq-fresh-arguments-"+Guid.NewGuid());
        Directory.CreateDirectory(folder);
        try
        {
            var report=Path.Combine(folder,"report.json");
            Require(App.FreshPCSetupArguments([]) is null);
            Require(App.FreshPCSetupArguments(["--existing-normal-argument"]) is null);
            Require(App.FreshPCSetupArguments(["--fresh-pc-setup",report])==report);
            Reject(()=>App.FreshPCSetupArguments(["--fresh-pc-setup"]));
            Reject(()=>App.FreshPCSetupArguments(["--fresh-pc-setup","relative.json"]));
            File.WriteAllText(report,"owner file");
            Reject(()=>App.FreshPCSetupArguments(["--fresh-pc-setup",report]));
            Require(File.ReadAllText(report)=="owner file");
        }
        finally { Directory.Delete(folder,true); }
        Console.WriteLine("PASS fresh-PC explicit GUI entry and refusal of unsafe/foreign report path; ordinary GUI args unchanged");
        ActivationIsExclusive();
    }
    sealed class UnexpectedService : IServiceClient
    {
        public int Calls;
        public Task<T> Call<T>(string method, object? payload=null, CancellationToken cancellationToken=default)
        { Calls++; return Task.FromException<T>(new IOException("Unexpected IPC during legacy activation")); }
    }
    static void ActivationIsExclusive()
    {
        const System.Reflection.BindingFlags flags=System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic;
        var window=new MainWindow(new LocalPreferences(),false,false);
        try {
            var service=new UnexpectedService();var vm=new DesktopViewModel(service);
            vm.Apply(new Snapshot { Optimizing=true, Settings=new(){Automatic=true}, Profiles=[new Profile { Id="chrome",Mode="AUTO",Executables=[@"C:\Apps\chrome.exe"] }] });
            typeof(MainWindow).GetField("model",flags)!.SetValue(window,vm);
            var prepare=typeof(MainWindow).GetMethod("PrepareNativeBrowsersAsync",flags)!;
            foreach(var name in new[]{"chromeActivating","edgeActivating"}) {
                var field=typeof(MainWindow).GetField(name,flags)!;field.SetValue(window,true);
                try { ((Task)prepare.Invoke(window,[true])!).GetAwaiter().GetResult(); }
                finally { field.SetValue(window,false); }
                if(service.Calls!=0)throw new Exception("Native timer raced legacy PAC activation: "+name);
            }
        } finally { window.Exit(); }
        Console.WriteLine("PASS native adoption cannot race either real WPF legacy PAC activation transaction");
    }

}
