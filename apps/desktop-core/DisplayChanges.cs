namespace Neexitlag.Desktop;
public sealed partial class DesktopViewModel {
 Dictionary<string,object?> HomeValues()=>new(){
  [nameof(Optimizing)]=Optimizing,[nameof(OptimizeLabel)]=OptimizeLabel,[nameof(OptimizationStatus)]=OptimizationStatus,
  [nameof(Primary)]=Primary,[nameof(ActiveApps)]=ActiveApps,[nameof(Rx)]=Rx,[nameof(Tx)]=Tx,
  [nameof(CurrentLatency)]=CurrentLatency,[nameof(DirectLatency)]=DirectLatency,[nameof(RelayLatency)]=RelayLatency,
  [nameof(Jitter)]=Jitter,[nameof(Loss)]=Loss,[nameof(CurrentBurst)]=CurrentBurst,
  [nameof(CurrentStability)]=CurrentStability,[nameof(CurrentSamples)]=CurrentSamples,
  [nameof(HomeLead)]=HomeLead,[nameof(Server)]=Server,[nameof(ServerHint)]=ServerHint,[nameof(GoSub)]=GoSub};
 void NotifyHomeChanges(Dictionary<string,object?> old){foreach(var pair in HomeValues())if(!Equals(old[pair.Key],pair.Value))Changed(pair.Key);}
}
public sealed partial class ApplicationRow {
 Dictionary<string,object?> DisplayValues()=>new(){[nameof(Name)]=Name,[nameof(Path)]=Path,[nameof(Mode)]=Mode,
 [nameof(ProcessStatus)]=ProcessStatus,[nameof(Route)]=Route,[nameof(UserStatus)]=UserStatus,[nameof(LocalDetails)]=LocalDetails,
 [nameof(Udp)]=Udp,[nameof(Tcp)]=Tcp,[nameof(Ipv4)]=Ipv4,[nameof(Ipv6)]=Ipv6};
 void NotifyDisplayChanges(Dictionary<string,object?> old){foreach(var pair in DisplayValues())if(!Equals(old[pair.Key],pair.Value))Changed(pair.Key);}
}
