[CmdletBinding()]
param([ValidateSet('Prepare','Apply','Restore')][string]$Action='Prepare')
$ErrorActionPreference='Stop'

function Initialize-Cs2PilotNative {
 if ('VeliqPilotFile' -as [type]) { return }
 Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

public static class VeliqPilotFile {
    [DllImport("ktmw32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateTransaction(IntPtr a,IntPtr id,uint options,uint level,uint flags,uint timeout,string description);
    [DllImport("ktmw32.dll",SetLastError=true)] static extern bool CommitTransaction(SafeFileHandle transaction);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern SafeFileHandle CreateFileTransactedW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template,SafeFileHandle transaction,IntPtr mini,IntPtr extended);
    [StructLayout(LayoutKind.Sequential)] struct FileInfo {
        public uint attributes; public System.Runtime.InteropServices.ComTypes.FILETIME creation,access,write;
        public uint volume,sizeHigh,sizeLow,links,idHigh,idLow;
    }
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out FileInfo info);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint rights);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr scm,string service,uint rights);
    [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
    static Exception LastError() { return new Win32Exception(Marshal.GetLastWin32Error()); }

    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
        public int length; public IntPtr descriptor; public int inherit;
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern bool CreateDirectoryW(string name,ref SecurityAttributes attributes);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string name,uint access,uint share,ref SecurityAttributes sa,uint create,uint flags,IntPtr template);

    // Set security only when creating new diagnostic staging objects.
    // No privilege adjustment or change to any existing ACL.
    public static void NewPrivateObject(string name,bool directory) {
        var sd=new RawSecurityDescriptor("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        var bytes=new byte[sd.BinaryLength]; sd.GetBinaryForm(bytes,0);
        var pin=GCHandle.Alloc(bytes,GCHandleType.Pinned);
        try {
            var sa=new SecurityAttributes();
            sa.length=Marshal.SizeOf(typeof(SecurityAttributes)); sa.descriptor=pin.AddrOfPinnedObject();
            if(directory) {
                if(!CreateDirectoryW(name,ref sa)) throw LastError();
            } else {
                using(var h=CreateFileW(name,0x40000000,0,ref sa,1,0x80,IntPtr.Zero))
                    if(h.IsInvalid) throw LastError();
            }
        } finally { pin.Free(); }
    }

    public static void CheckServiceRights() {
        IntPtr scm=OpenSCManager(null,null,1); if (scm==IntPtr.Zero) throw LastError();
        try {
            IntPtr service=OpenService(scm,"VELIQ",0x35); // QUERY_CONFIG, QUERY_STATUS, START, STOP
            if(service==IntPtr.Zero) throw LastError();
            CloseServiceHandle(service);
        } finally { CloseServiceHandle(scm); }
    }
    static string Identity(SafeFileHandle h) {
        FileInfo info;
        if(!GetFileInformationByHandle(h,out info)) throw LastError();
        if(info.links!=1 || (info.attributes & 0x410)!=0) throw new IOException("Expected one link and a regular file");
        return string.Format("{0:X8}-{1:X8}{2:X8}",info.volume,info.idHigh,info.idLow);
    }
    public static string Identity(string path) {
        using(var f=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete)) return Identity(f.SafeFileHandle);
    }
    static string Digest(Stream f) {
        f.Position=0;
        using(var hash=SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(f)).Replace("-","").ToLowerInvariant();
    }

    // Writes data only, through OPEN_EXISTING in a local NTFS transaction.
    // Closing an uncommitted transaction aborts it; no replacement file inherits a different ACL.
    public static void Write(string target,string source,string identity,string oldHash,string newHash,bool commit) {
        using(var input=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read)) {
            if(Digest(input)!=newHash) throw new IOException("Source digest mismatch");
            input.Position=0;
            using(var txn=CreateTransaction(IntPtr.Zero,IntPtr.Zero,0,0,0,30000,"VELIQ pilot service payload")) {
                if(txn.IsInvalid) throw LastError();
                using(var h=CreateFileTransactedW(target,0xC0000000,0,IntPtr.Zero,3,0,IntPtr.Zero,txn,IntPtr.Zero,IntPtr.Zero)) {
                    if(h.IsInvalid) throw LastError();
                    if(Identity(h)!=identity) throw new IOException("Destination identity mismatch");
                    using(var output=new FileStream(h,FileAccess.ReadWrite)) {
                        if(Digest(output)!=oldHash) throw new IOException("Destination digest mismatch");
                        output.Position=0; input.CopyTo(output); output.SetLength(input.Length); output.Flush();
                        if(Digest(output)!=newHash) throw new IOException("Transactional readback mismatch");
                    }
                }
                if(commit && !CommitTransaction(txn)) throw LastError();
            }
        }
    }
}
'@
}

function Get-Cs2PilotHash([string]$Path) {
 (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-Cs2PilotTransaction([string]$Directory) {
 $stem=Join-Path $Directory ([Guid]::NewGuid().ToString('N'))
 $target=$stem+'.test'; $old=$stem+'.old'; $new=$stem+'.new'
 try {
  [IO.File]::WriteAllBytes($target,[byte[]](1,2,3))
  [IO.File]::WriteAllBytes($old,[byte[]](1,2,3))
  [IO.File]::WriteAllBytes($new,[byte[]](4,5,6,7))
  $id=[VeliqPilotFile]::Identity($target)
  $a=Get-Cs2PilotHash $old; $b=Get-Cs2PilotHash $new
  $before=(Get-Acl -LiteralPath $target).Sddl
  [VeliqPilotFile]::Write($target,$new,$id,$a,$b,$false)
  if((Get-Cs2PilotHash $target) -ne $a){throw 'PILOT_NTFS_ABORT_FAILED'}
  [VeliqPilotFile]::Write($target,$new,$id,$a,$b,$true)
  if((Get-Cs2PilotHash $target) -ne $b){throw 'PILOT_NTFS_COMMIT_FAILED'}
  [VeliqPilotFile]::Write($target,$old,$id,$b,$a,$true)
  if((Get-Cs2PilotHash $target) -ne $a -or [VeliqPilotFile]::Identity($target) -ne $id -or (Get-Acl -LiteralPath $target).Sddl -cne $before){throw 'PILOT_NTFS_RESTORE_FAILED'}
 } finally {
  foreach($file in @($target,$new,$old)){if([IO.File]::Exists($file)){[IO.File]::Delete($file)}}
 }
}

function Assert-Cs2PilotAccess([string]$Path,[int64]$UntrustedMask) {
 $item=Get-Item -LiteralPath $Path -Force
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'PILOT_REPARSE_POINT'}
 $acl=Get-Acl -LiteralPath $Path
 $trusted=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){throw 'PILOT_UNTRUSTED_OWNER'}
 $sd=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
 if($null -eq $sd.DiscretionaryAcl){throw 'PILOT_NO_DACL'}
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if(($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0){continue}
  if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and
     (([int64]$rule.FileSystemRights -band $UntrustedMask) -ne 0)){throw 'PILOT_UNTRUSTED_WRITE'}
 }
}

function Get-Cs2PilotService([string]$Target) {
 $s=Get-CimInstance Win32_Service -Filter "Name='VELIQ'" -OperationTimeoutSec 5
 $expected='"'+$Target+'" -config "'+(Join-Path (Split-Path $Target) 'service.json')+'"'
 if(!$s -or $s.PathName -ine $expected -or $s.StartMode -ne 'Auto'){throw 'PILOT_SCM_CONFIG_CHANGED'}
 if($s.State -eq 'Running'){
  if((Get-Process -Id $s.ProcessId -ErrorAction Stop).Path -ine $Target){throw 'PILOT_RUNTIME_MISMATCH'}
 }
 return $s
}

function Wait-Cs2PilotActive([string]$Target,[string]$Hash) {
 $until=[DateTime]::UtcNow.AddSeconds(60)
 do {
  try{
   $scm=Get-Cs2PilotService $Target
   $s=Invoke-ServiceIPCOnce 'status' $null
   if($scm.State -eq 'Running' -and $s.capture_active -eq $true -and $s.optimizing -eq $true -and
      (Get-Cs2PilotHash $Target) -eq $Hash -and (Get-Service LanGameService).Status -eq 'Running'){return}
  }catch{}
  Start-Sleep -Milliseconds 500
 }while([DateTime]::UtcNow -lt $until)
 throw 'PILOT_SERVICE_NOT_ACTIVE'
}

function Stop-Cs2PilotHost([string]$Target) {
 $s=Get-Cs2PilotService $Target
 if($s.State -eq 'Stopped'){return}
 if($s.State -ne 'Running'){throw 'PILOT_SERVICE_TRANSITION'}
 $process=Get-Process -Id $s.ProcessId -ErrorAction Stop
 try{
  $other=@(Get-CimInstance Win32_Process -Filter "Name='veliq-service.exe'" -OperationTimeoutSec 5 | Where-Object {$_.ProcessId -ne $s.ProcessId -and $_.ExecutablePath -ieq $Target})
  if($other.Count){throw 'PILOT_OTHER_IMAGE_IN_USE'}
  Stop-Service -Name VELIQ -ErrorAction Stop
  (Get-Service VELIQ).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
  if(!$process.WaitForExit(30000)){throw 'PILOT_SERVICE_PROCESS_STILL_RUNNING'}
 } finally {$process.Dispose()}
}

function Invoke-Cs2Pilot {
 if([Environment]::MachineName -ine 'PC14' -or [Environment]::OSVersion.Platform -ne 'Win32NT'){throw 'PILOT_REQUIRES_PC14'}
 if([Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0 -or $null -ne (Get-Variable PSSenderInfo -ErrorAction SilentlyContinue)){throw 'PILOT_LOCAL_INTERACTIVE_SESSION_REQUIRED'}
 . (Join-Path $PSScriptRoot 'common.ps1')
 Assert-Administrator
 Initialize-Cs2PilotNative
 [VeliqPilotFile]::CheckServiceRights()
 $expectedStock='e543b9e8d673ff64f530ab5c48e252f7fe9b98f3ab39df45f3629d817d5ccc7d'
 $expectedPilot='@@CS2_PILOT_SHA256@@'
 if($expectedPilot -cnotmatch '^[a-f0-9]{64}$' -or $expectedPilot -eq $expectedStock){throw 'PILOT_REQUIRES_PINNED_KIT'}
 $root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'VELIQ'
 $target=Join-Path $root 'veliq-service.exe'
 $stage=Join-Path $root ('cs2-pilot-'+$expectedPilot.Substring(0,12))
 $stock=Join-Path $stage 'stock.exe';$candidate=Join-Path $stage 'candidate.exe';$record=Join-Path $stage 'original-id.txt'
 $writeMask=0x500D0156 # generic write/all, write, append, EA, delete-child, attributes, DELETE, WRITE_DAC, WRITE_OWNER
 for($ancestor=(Get-Item $root).Parent;$null -ne $ancestor;$ancestor=$ancestor.Parent){
  Assert-Cs2PilotAccess $ancestor.FullName 0x100D0040
 }
 foreach($item in @($root,$target)){Assert-Cs2PilotAccess $item $writeMask}
 $scm=Get-Cs2PilotService $target
 if($Action -eq 'Prepare'){
  if($scm.State -ne 'Running' -or (Get-Cs2PilotHash $target) -ne $expectedStock){throw 'PILOT_STOCK_MISMATCH'}
  Wait-Cs2PilotActive $target $expectedStock
  if(!(Test-Path -LiteralPath $stage)){[VeliqPilotFile]::NewPrivateObject($stage,$true)}
 }
 Assert-Cs2PilotAccess $stage $writeMask
 $lockPath=Join-Path $stage 'operation.lock'
 if(!(Test-Path -LiteralPath $lockPath)){[VeliqPilotFile]::NewPrivateObject($lockPath,$false)}
 Assert-Cs2PilotAccess $lockPath $writeMask
 $lock=[IO.File]::Open($lockPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
 try {
  $id=[VeliqPilotFile]::Identity($target)
  if($Action -eq 'Prepare'){
   $source=Join-Path $PSScriptRoot 'veliq-service.exe'
   foreach($copy in @(@($target,$stock,$expectedStock),@($source,$candidate,$expectedPilot))){
    if(!(Test-Path -LiteralPath $copy[1])){
     $temp=Join-Path $stage ([Guid]::NewGuid().ToString('N')+'.copy')
     try{
      $inputStream=[IO.File]::OpenRead($copy[0])
      try{
       [VeliqPilotFile]::NewPrivateObject($temp,$false)
       $output=[IO.File]::Open($temp,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::None)
       try{$inputStream.CopyTo($output);$output.Flush($true)}finally{$output.Dispose()}
      }finally{$inputStream.Dispose()}
      if((Get-Cs2PilotHash $temp) -ne $copy[2]){throw 'PILOT_SUPPLIED_HASH_MISMATCH'}
      [IO.File]::Move($temp,$copy[1])
     }finally{if([IO.File]::Exists($temp)){[IO.File]::Delete($temp)}}
    }
    Assert-Cs2PilotAccess $copy[1] $writeMask
    if((Get-Cs2PilotHash $copy[1]) -ne $copy[2]){throw 'PILOT_STAGED_HASH_MISMATCH'}
   }
   Test-Cs2PilotTransaction $stage
   if(!(Test-Path -LiteralPath $record)){[VeliqPilotFile]::NewPrivateObject($record,$false);[IO.File]::WriteAllText($record,$id)}
  }
  foreach($file in @($record,$stock)){Assert-Cs2PilotAccess $file $writeMask}
  if($Action -ne 'Restore'){Assert-Cs2PilotAccess $candidate $writeMask}
  if([IO.File]::ReadAllText($record) -cne $id -or (Get-Cs2PilotHash $stock) -ne $expectedStock -or
     ($Action -ne 'Restore' -and (Get-Cs2PilotHash $candidate) -ne $expectedPilot)){throw 'PILOT_RESTORE_MATERIAL_INVALID'}
  if($Action -eq 'Prepare'){Write-Output 'PC14_STOCK_AND_NTFS_ROUNDTRIP_READY';return}
  if($Action -eq 'Apply'){
   Wait-Cs2PilotActive $target $expectedStock
   Test-Cs2PilotTransaction $stage
  }
  $current=Get-Cs2PilotHash $target
  if($Action -eq 'Restore' -and $current -eq $expectedStock){
   Start-Service VELIQ; Wait-Cs2PilotActive $target $expectedStock; Write-Output 'PC14_STOCK_RESTORED';return
  }
  if(($Action -eq 'Apply' -and $current -ne $expectedStock) -or ($Action -eq 'Restore' -and $current -ne $expectedPilot)){throw 'PILOT_UNEXPECTED_CURRENT_IMAGE'}
  try{
   Stop-Cs2PilotHost $target
   if($Action -eq 'Apply'){[VeliqPilotFile]::Write($target,$candidate,$id,$expectedStock,$expectedPilot,$true);$wanted=$expectedPilot}
   else{[VeliqPilotFile]::Write($target,$stock,$id,$expectedPilot,$expectedStock,$true);$wanted=$expectedStock}
   if([VeliqPilotFile]::Identity($target) -cne $id -or (Get-Cs2PilotHash $target) -ne $wanted){throw 'PILOT_COMMIT_UNCONFIRMED'}
   Start-Service VELIQ -ErrorAction Stop
   Wait-Cs2PilotActive $target $wanted
  }catch{
   $originalError=$_.Exception
   if((Get-Cs2PilotHash $target) -eq $expectedPilot){
    Stop-Cs2PilotHost $target
    [VeliqPilotFile]::Write($target,$stock,$id,$expectedPilot,$expectedStock,$true)
   }
   if((Get-Cs2PilotHash $target) -ne $expectedStock -or [VeliqPilotFile]::Identity($target) -cne $id){throw 'PILOT_MANUAL_RESTORE_REQUIRED'}
   if((Get-Service VELIQ).Status -eq 'Stopped'){Start-Service VELIQ -ErrorAction Stop}
   Wait-Cs2PilotActive $target $expectedStock
   throw ('PILOT_FAILED_STOCK_ACTIVE: '+$originalError.Message)
  }
  if($Action -eq 'Restore'){Write-Output 'PC14_STOCK_RESTORED'}else{Write-Output 'PC14_CANDIDATE_ACTIVE'}
 } finally {$lock.Dispose()}
}

if($MyInvocation.InvocationName -ne '.') {Invoke-Cs2Pilot}
