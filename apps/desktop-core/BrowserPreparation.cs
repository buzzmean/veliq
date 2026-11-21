namespace Neexitlag.Desktop;
public sealed class BrowserPreparationDeferredException() : Exception("BROWSER_PREPARATION_DEFERRED");
public sealed partial class DesktopViewModel {
 long browserPreparationGeneration;
 string? browserIssueNotice;
 (bool Optimizing,bool Connected,bool Automatic)? browserControlState;
 public bool BrowserPreparationAllowed=>Available&&!Busy&&Optimizing&&Snapshot is {Connected:true,Settings:{Automatic:true}};
 public long CaptureBrowserPreparation(){var ticket=Interlocked.Read(ref browserPreparationGeneration);CheckBrowserPreparation(ticket);return ticket;}
 public void CheckBrowserPreparation(long ticket){if(ticket!=Interlocked.Read(ref browserPreparationGeneration)||!BrowserPreparationAllowed)throw new BrowserPreparationDeferredException();}
 void InvalidateBrowserPreparation()=>Interlocked.Increment(ref browserPreparationGeneration);
 void ObserveBrowserControlState(Snapshot next){
  var state=(next.Optimizing,next.Connected,next.Settings.Automatic);
  if(browserControlState is {} previous && previous!=state)InvalidateBrowserPreparation();
  browserControlState=state;
 }
 public void ReportBrowserPreparationFailure(Exception error,string phase){
  RecordGuiFailure(error,phase);
  browserIssueNotice=Optimizing?"Браузер пока не готов. VELIQ повторит подготовку автоматически.":"Оптимизация выключена. Браузеры используют прямую сеть.";
  Notice=browserIssueNotice;
 }
 public void ClearBrowserPreparationIssue(){if(browserIssueNotice is not null&&Notice==browserIssueNotice)Notice="";browserIssueNotice=null;}
 void ApplyDisabledBrowserDisplay(){
  if(Optimizing){if(Snapshot?.Connected!=true||Snapshot?.Backend.Ready!=true)ApplyNativeBrowserReadiness(new());return;}
  ApplyNativeBrowserReadiness(new());
  if(Applications.Any(a=>BrowserCatalog.IsChrome(a.Profile))){const string direct="Chrome: прямая сеть (оптимизация выключена)";if(ChromePolicyState!=direct){ChromePolicyState=direct;Changed(nameof(ChromePolicyState));}}
  if(Applications.Any(a=>BrowserCatalog.IsEdge(a.Profile))){const string direct="Edge: прямая сеть (оптимизация выключена)";if(EdgeState!=direct){EdgeState=direct;Changed(nameof(EdgeState));}}
 }
 static bool BrowserPhase(string phase)=>phase.Contains("browser",StringComparison.OrdinalIgnoreCase)||phase.StartsWith("edge",StringComparison.OrdinalIgnoreCase)||phase.StartsWith("chrome",StringComparison.OrdinalIgnoreCase);
}
