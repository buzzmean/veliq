# Test-only SCM access for the opt-in, disposable beta Setup fixture.
if($env:GITHUB_ACTIONS -cne 'true' -or $env:VELIQ_BETA_INSTALL_SMOKE -cne '1' -or [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'DISPOSABLE_WINDOWS_RECOVERY_FIXTURE_REQUIRED'}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public sealed class VeliqRecoverySnapshot {
    public uint ResetSeconds;
    public uint[] ActionTypes;
    public uint[] ActionDelays;
    public bool NonCrashFailures;
}

public static class VeliqRecoveryFixture {
    [StructLayout(LayoutKind.Sequential)]
    private struct FailureActions {
        public uint Reset;
        public IntPtr Reboot;
        public IntPtr Command;
        public uint Count;
        public IntPtr List;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FailureAction { public uint Type; public uint Delay; }

    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool QueryServiceConfig2W(IntPtr service, uint level, IntPtr buffer, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool ChangeServiceConfig2W(IntPtr service, uint level, IntPtr buffer);
    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);

    private static IntPtr Open(uint access) {
        IntPtr manager=OpenSCManagerW(null, null, 1);
        if(manager==IntPtr.Zero) throw new InvalidOperationException("SCM_MANAGER_OPEN_FAILED");
        try {
            IntPtr service=OpenServiceW(manager, "VELIQ", access);
            if(service==IntPtr.Zero) throw new InvalidOperationException("SCM_FIXTURE_SERVICE_OPEN_FAILED");
            return service;
        } finally { CloseServiceHandle(manager); }
    }
    private static IntPtr Query(IntPtr service, uint level) {
        uint needed;
        bool unexpected=QueryServiceConfig2W(service, level, IntPtr.Zero, 0, out needed);
        if(unexpected || Marshal.GetLastWin32Error()!=122 || needed<4 || needed>65536)
            throw new InvalidOperationException("SCM_RECOVERY_QUERY_SIZE_FAILED");
        IntPtr buffer=Marshal.AllocHGlobal((int)needed);
        try {
            if(!QueryServiceConfig2W(service, level, buffer, needed, out needed))
                throw new InvalidOperationException("SCM_RECOVERY_QUERY_FAILED");
            return buffer;
        } catch { Marshal.FreeHGlobal(buffer); throw; }
    }
    public static VeliqRecoverySnapshot Read() {
        IntPtr service=Open(1);
        try {
            VeliqRecoverySnapshot result=new VeliqRecoverySnapshot();
            IntPtr buffer=Query(service, 2);
            try {
                FailureActions actions=(FailureActions)Marshal.PtrToStructure(buffer, typeof(FailureActions));
                if(actions.Count>128 || (actions.Count>0 && actions.List==IntPtr.Zero))
                    throw new InvalidOperationException("SCM_RECOVERY_ACTIONS_INVALID");
                result.ResetSeconds=actions.Reset;
                result.ActionTypes=new uint[actions.Count];
                result.ActionDelays=new uint[actions.Count];
                int size=Marshal.SizeOf(typeof(FailureAction));
                for(int i=0; i<(int)actions.Count; i++) {
                    FailureAction action=(FailureAction)Marshal.PtrToStructure(IntPtr.Add(actions.List, i*size), typeof(FailureAction));
                    result.ActionTypes[i]=action.Type; result.ActionDelays[i]=action.Delay;
                }
            } finally { Marshal.FreeHGlobal(buffer); }
            buffer=Query(service, 4);
            try { result.NonCrashFailures=Marshal.ReadInt32(buffer)!=0; }
            finally { Marshal.FreeHGlobal(buffer); }
            return result;
        } finally { CloseServiceHandle(service); }
    }
    public static void Clear() {
        IntPtr service=Open(3);
        IntPtr list=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FailureAction)));
        IntPtr buffer=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(FailureActions)));
        try {
            // A non-null list with Count=0 deletes the policy; null would leave it unchanged.
            FailureActions actions=new FailureActions(); actions.List=list;
            Marshal.StructureToPtr(actions, buffer, false);
            if(!ChangeServiceConfig2W(service, 2, buffer)) throw new InvalidOperationException("SCM_RECOVERY_CLEAR_FAILED");
            Marshal.WriteInt32(buffer, 0);
            if(!ChangeServiceConfig2W(service, 4, buffer)) throw new InvalidOperationException("SCM_RECOVERY_FLAG_CLEAR_FAILED");
        } finally { Marshal.FreeHGlobal(buffer); Marshal.FreeHGlobal(list); CloseServiceHandle(service); }
    }
}
'@

function Assert-OwnedRecoveryFixture([string]$InstallDirectory){
 $expected='"'+(Join-Path $InstallDirectory 'veliq-service.exe')+'" -config "'+(Join-Path $InstallDirectory 'service.json')+'"'
 $service=Get-CimInstance Win32_Service -Filter "Name='VELIQ'" -OperationTimeoutSec 5
 if(!$service -or $service.PathName -cne $expected){throw 'RECOVERY_FIXTURE_OWNED_SERVICE_REQUIRED'}
 return $service
}
function Clear-OwnedRecoveryFixture([string]$InstallDirectory){
 $null=Assert-OwnedRecoveryFixture $InstallDirectory
 [VeliqRecoveryFixture]::Clear()
 $state=[VeliqRecoveryFixture]::Read()
 if($state.ActionTypes.Length -ne 0 -or $state.NonCrashFailures){throw 'RECOVERY_FIXTURE_DID_NOT_CLEAR_POLICY'}
}
function Assert-OwnedRecoveryPolicy([string]$InstallDirectory){
 $service=Assert-OwnedRecoveryFixture $InstallDirectory
 $state=[VeliqRecoveryFixture]::Read()
 if($state.ResetSeconds -ne 86400 -or $state.ActionTypes.Length -ne 3 -or !$state.NonCrashFailures){throw 'RECOVERY_POLICY_NOT_RESTORED'}
 for($i=0;$i -lt 3;$i++){
  if($state.ActionTypes[$i] -ne 1 -or $state.ActionDelays[$i] -ne 5000){throw 'RECOVERY_POLICY_RESTART_ACTION_INVALID'}
 }
 if($service.StartMode -cne 'Auto' -or $service.State -cne 'Running'){throw 'RECOVERY_SERVICE_NOT_AUTOMATIC_AND_RUNNING'}
 $status=Invoke-ServiceIPC 'status' $null (Join-Path $InstallDirectory 'ipc.token')
 if($null -eq $status.PSObject.Properties['backend']){throw 'RECOVERY_SERVICE_IPC_NOT_READY'}
}
function Assert-OwnedCrashRecovery([string]$InstallDirectory,[string]$ExpectedCommit,[string]$ExpectedBinaryHash,[hashtable]$PreservedHashes,[ValidateRange(1,60)][int]$TimeoutSeconds=45){
 if($env:GITHUB_ACTIONS -cne 'true' -or $env:VELIQ_BETA_INSTALL_SMOKE -cne '1' -or [IO.Path]::GetFullPath($InstallDirectory) -cne [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'VELIQ'))){throw 'DISPOSABLE_RECOVERY_CRASH_TARGET_REQUIRED'}
 if($ExpectedCommit -cnotmatch '^[a-f0-9]{40}$' -or $ExpectedBinaryHash -notmatch '^[a-fA-F0-9]{64}$'){throw 'RECOVERY_CRASH_SOURCE_REQUIRED'}
 $target=Join-Path $InstallDirectory 'veliq-service.exe'
 $service=Assert-OwnedRecoveryFixture $InstallDirectory
 $oldId=[int]$service.ProcessId
 if($service.State -cne 'Running' -or $service.StartMode -cne 'Auto' -or $oldId -le 4){throw 'RECOVERY_CRASH_RUNNING_SERVICE_REQUIRED'}
 $process=Get-Process -Id $oldId -ErrorAction Stop
 try{
  # Retain the process handle through the test so an exit cannot recycle this PID before the guarded kill.
  $null=$process.Handle
  $oldBirth=$process.StartTime.ToUniversalTime()
  if($process.Path -cne $target -or (Get-FileHash -LiteralPath $target).Hash -cne $ExpectedBinaryHash){throw 'RECOVERY_CRASH_IMAGE_MISMATCH'}
  $status=Invoke-ServiceIPCOnce 'status' $null (Join-Path $InstallDirectory 'ipc.token')
  if([int]$status.service_pid -ne $oldId -or $status.build -cne $ExpectedCommit.Substring(0,12)){throw 'RECOVERY_CRASH_IPC_IDENTITY_MISMATCH'}
  foreach($name in @('service.json','ipc.token')){
   if(!$PreservedHashes.ContainsKey($name) -or (Get-FileHash -LiteralPath (Join-Path $InstallDirectory $name)).Hash -cne $PreservedHashes[$name]){throw 'RECOVERY_CRASH_STATE_MISMATCH'}
  }
  # Recheck exact SCM command line/PID and the retained process immediately before this one scoped stop.
  $service=Assert-OwnedRecoveryFixture $InstallDirectory
  $process.Refresh()
  if($service.State -cne 'Running' -or $service.StartMode -cne 'Auto' -or [int]$service.ProcessId -ne $oldId -or $process.HasExited -or $process.Path -cne $target -or $process.StartTime.ToUniversalTime() -ne $oldBirth){throw 'RECOVERY_CRASH_TARGET_CHANGED'}
  $elapsed=[Diagnostics.Stopwatch]::StartNew()
  Stop-Process -Id $oldId -Force -ErrorAction Stop
  # No manual start: only SCM's configured crash recovery may restore the fixture service.
  while($elapsed.Elapsed.TotalSeconds -lt $TimeoutSeconds){
   $service=Assert-OwnedRecoveryFixture $InstallDirectory
   if($service.State -ceq 'Running' -and $service.StartMode -ceq 'Auto' -and [int]$service.ProcessId -gt 4 -and [int]$service.ProcessId -ne $oldId){
    $next=Get-Process -Id ([int]$service.ProcessId) -ErrorAction Stop
    try{
     $null=$next.Handle
     if($next.Path -cne $target -or $next.StartTime.ToUniversalTime() -le $oldBirth -or (Get-FileHash -LiteralPath $target).Hash -cne $ExpectedBinaryHash){throw 'RECOVERY_RESTART_IMAGE_MISMATCH'}
     $status=$null
     try{$status=Invoke-ServiceIPCOnce 'status' $null (Join-Path $InstallDirectory 'ipc.token')}catch{}
     if($null -ne $status -and $null -ne $status.PSObject.Properties['backend']){
      if([int]$status.service_pid -ne [int]$service.ProcessId -or $status.build -cne $ExpectedCommit.Substring(0,12)){throw 'RECOVERY_RESTART_IPC_IDENTITY_MISMATCH'}
      foreach($name in @('service.json','ipc.token')){if((Get-FileHash -LiteralPath (Join-Path $InstallDirectory $name)).Hash -cne $PreservedHashes[$name]){throw 'RECOVERY_RESTART_STATE_CHANGED'}}
      $current=Assert-OwnedRecoveryFixture $InstallDirectory
      $next.Refresh()
      if($current.State -cne 'Running' -or $current.StartMode -cne 'Auto' -or [int]$current.ProcessId -ne [int]$service.ProcessId -or $next.HasExited){throw 'RECOVERY_RESTART_NOT_STABLE'}
      return [pscustomobject]@{old_pid=$oldId;new_pid=[int]$current.ProcessId;new_birth_utc=$next.StartTime.ToUniversalTime().ToString('o');source=$ExpectedCommit;elapsed_ms=[int]$elapsed.Elapsed.TotalMilliseconds}
     }
    }finally{$next.Dispose()}
   }
   Start-Sleep -Milliseconds 200
  }
  throw 'RECOVERY_AUTOMATIC_RESTART_TIMEOUT'
 }finally{$process.Dispose()}
}
