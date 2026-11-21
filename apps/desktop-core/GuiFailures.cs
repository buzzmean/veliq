namespace Neexitlag.Desktop;

// Only acquisition/validation of the core status decides service availability.
// Optional browser/recovery diagnostics and rejected UI actions cannot revoke an
// already authenticated status or erase its profiles. Never persist exception
// messages here: helper state/IPC exceptions may contain private runtime data.
public sealed record GuiFailure(string Phase,string ExceptionType,DateTimeOffset At,string Code="");
public sealed partial class DesktopViewModel {
 public GuiFailure? LastGuiFailure {get;private set;}
 public event Action<GuiFailure>? GuiFailureReported;
 public void RecordGuiFailure(Exception error,string phase){
  LastGuiFailure=new(phase,error.GetType().Name,DateTimeOffset.UtcNow,error is EdgeActivationException edge?edge.Code:error is ChromeActivationException chrome?chrome.Code:error is BrowserPreparationDeferredException?"BROWSER_PREPARATION_DEFERRED":error is ServiceException ipc?(BrowserPhase(phase)&&NativeBrowserErrorCode(error) is var nativeCode&&nativeCode!="NATIVE_ACTIVATION_FAILED"?nativeCode:"IPC_"+ipc.Failure.ToString().ToUpperInvariant()):"");
  GuiFailureReported?.Invoke(LastGuiFailure);Changed(nameof(LastGuiFailure));
 }
 public void ReportAuxiliaryFailure(Exception error,string phase){
  if(BrowserPhase(phase)){ReportBrowserPreparationFailure(error,phase);return;}
  RecordGuiFailure(error,phase);
  Notice="Некоторые сведения временно недоступны. Повторная проверка выполняется автоматически.";
  Changed(nameof(LastGuiFailure));
 }
 public void ReportActionFailure(Exception error){
  if(error is EdgeActivationException edgeFailure){ReportBrowserPreparationFailure(error,edgeFailure.Phase);return;}
  if(error is ChromeActivationException chromeFailure){ReportBrowserPreparationFailure(error,chromeFailure.Phase);return;}
  if(error is BrowserPreparationDeferredException){ReportBrowserPreparationFailure(error,"browser.prepare");return;}
  if(error is ServiceException ipc&&ipc.Failure!=ServiceFailure.Rejected){SetUnavailable(error);return;}
  ReportAuxiliaryFailure(error,error is EdgeActivationException edge?edge.Phase:"ui.action");Error=error is EdgeActivationException?error.Message:Text.Failure(error);
  if(error is EdgeActivationException)ApplyEdgePolicyState(new(){LastError=error.Message});
 }
 public async Task ObserveAuxiliaryAsync(Func<Task> action,string phase,CancellationToken ct=default){
  try{await action();if(BrowserPhase(phase))ClearBrowserPreparationIssue();}
  catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
  catch(Exception error){ReportAuxiliaryFailure(error,phase);}
 }
}
