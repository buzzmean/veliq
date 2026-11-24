namespace Veliq.Desktop;
public sealed partial class DesktopViewModel {
 bool browserAutomaticStartDecided;
 int browserAutomaticStartInFlight;
 void SuppressAutomaticBrowserStartup()=>browserAutomaticStartDecided=true;
 // One automatic start per GUI lifetime. Explicit OFF wins over polling forever
 // in this window; a later GUI launch with Automatic enabled can start again.
 public async Task EnsureBrowserOptimizationOnStartupAsync(CancellationToken ct=default){
  if(browserAutomaticStartDecided||!Available||Busy||Snapshot?.Settings.Automatic!=true||Activation?.Status.CapturePermitted==false||!Applications.Any(a=>a.Profile.Mode=="AUTO"&&NativeBrowser(a.Profile)))return;
  if(Interlocked.CompareExchange(ref browserAutomaticStartInFlight,1,0)!=0)return;
  try{
   if(!Optimizing){
    await gate.WaitAsync(ct);Busy=true;
    try {
     var status=await client.Call<Snapshot>("optimize",new{enabled=true},ct);
     if(!status.Optimizing)throw new ServiceException(ServiceFailure.Rejected,"CAPTURE_START_FAILED");
     Apply(status);Error="";
    }finally{Busy=false;gate.Release();}
   }
   if(Optimizing)browserAutomaticStartDecided=true;
  }catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
  catch(Exception error){if(!browserAutomaticStartDecided){ReportBrowserPreparationFailure(error,"browser.startup.optimize");browserIssueNotice="Браузер пока не готов. VELIQ повторит подготовку автоматически.";Notice=browserIssueNotice;}}
  finally{Interlocked.Exchange(ref browserAutomaticStartInFlight,0);}
 }
}
