# Read-only Windows policy/token inspection. No elevation or registry writes.
function New-FreshExecutionEvidence {
 return [pscustomobject]@{
  PolicyView='Registry64';EnableLUA=$null;EnableLUAKind='Unknown';ConsentPromptBehaviorAdmin=$null;ConsentKind='Unknown';PolicyReadError=$null
  IsAdministrator=$null;OwnerQueryError=$null;ElevationType=$null;Elevated=$null;Restricted=$null
  NativeReadError=$null;OpenTokenError=$null;ElevationTypeError=$null;ElevationError=$null;RestrictedError=$null
  ElevationTypeBufferLength=$null;ElevationBufferLength=$null;RestrictedBufferLength=$null;LinkedTokenBufferLength=$null
  HasLinkedToken=$null;LinkedTokenQuery='NOT_RUN';LinkedTokenError=$null
 }
}

function Resolve-FreshExecutionMode($Evidence) {
 if($Evidence.PolicyReadError -ne 0){throw 'UAC_POLICY_READ_FAILED'}
 if($Evidence.EnableLUAKind -cne 'DWord'){throw 'ENABLE_LUA_NOT_DWORD'}
 if($Evidence.ConsentKind -cne 'DWord'){throw 'CONSENT_POLICY_NOT_DWORD'}
 if($Evidence.EnableLUA -notin @(0,1) -or $Evidence.ConsentPromptBehaviorAdmin -notin @(0,1,2,3,4,5)){throw 'UAC_POLICY_VALUE_INVALID'}
 if($Evidence.NativeReadError -ne 0 -or $Evidence.OpenTokenError -ne 0){throw 'TOKEN_READ_FAILED'}
 if($Evidence.ElevationTypeError -ne 0 -or $Evidence.ElevationType -notin @(1,2,3)){throw 'TOKEN_ELEVATION_TYPE_UNAVAILABLE'}
 if($Evidence.ElevationError -ne 0 -or $Evidence.Elevated -isnot [bool]){throw 'TOKEN_ELEVATION_UNAVAILABLE'}
 if($Evidence.RestrictedError -ne 0 -or $Evidence.Restricted -isnot [bool]){throw 'TOKEN_RESTRICTION_UNAVAILABLE'}
 if($Evidence.Restricted){throw 'RESTRICTED_TOKEN_REFUSED'}
 if($Evidence.OwnerQueryError -ne 0 -or $Evidence.IsAdministrator -isnot [bool]){throw 'ADMINISTRATOR_MEMBERSHIP_UNAVAILABLE'}
 $absent=$Evidence.LinkedTokenQuery -ceq 'ABSENT' -and $Evidence.HasLinkedToken -ceq $false -and $Evidence.LinkedTokenError -eq 0
 $present=$Evidence.LinkedTokenQuery -ceq 'PRESENT' -and $Evidence.HasLinkedToken -ceq $true -and $Evidence.LinkedTokenError -eq 0
 # Default is independent Windows evidence of a non-split token. Any failed
 # linked query is normal for that type, not a failed elevation/restriction
 # query. Never make this exception for Full/Limited or a query not attempted.
 $defaultUnavailable=$Evidence.ElevationType -eq 1 -and $Evidence.LinkedTokenQuery -ceq 'ERROR' -and $Evidence.HasLinkedToken -cne $true -and $null -ne $Evidence.LinkedTokenError -and $Evidence.LinkedTokenError -ne 0
 if(!$absent -and !$present -and !$defaultUnavailable){throw 'LINKED_TOKEN_QUERY_UNAVAILABLE'}
 if($Evidence.ElevationType -eq 1 -and $present){throw 'DEFAULT_TOKEN_HAS_LINKED_TOKEN'}
 if($Evidence.EnableLUA -eq 0){
  if($Evidence.ElevationType -ne 1){throw 'UAC_OFF_REQUIRES_DEFAULT_TOKEN'}
  if(!$Evidence.IsAdministrator -or !$Evidence.Elevated){throw 'UAC_OFF_REQUIRES_FULL_ADMIN'}
  return 'UAC_DISABLED_FULL_ADMIN'
 }
 if($Evidence.IsAdministrator -or $Evidence.Elevated){throw 'UAC_ENABLED_ELEVATED_REFUSED'}
 if(($Evidence.ElevationType -eq 3 -and $present) -or ($Evidence.ElevationType -eq 1 -and ($absent -or $defaultUnavailable))){return 'UAC_ENABLED_OWNER'}
 throw 'OWNER_TOKEN_INCONSISTENT'
}

function Format-FreshExecutionEvidence($Evidence,[string]$Reason) {
 # Explicit allowlist, not ConvertTo-Json of errors/environment/IPC objects.
 if($Reason -cnotmatch '^[A-Z][A-Z0-9_]{1,95}$'){$Reason='EXECUTION_EVIDENCE_QUERY_FAILED'}
 $parts=[Collections.Generic.List[string]]::new();$parts.Add('reason='+$Reason)
 foreach($name in @('PolicyView','EnableLUA','EnableLUAKind','ConsentPromptBehaviorAdmin','ConsentKind','PolicyReadError','IsAdministrator','OwnerQueryError','ElevationType','Elevated','Restricted','NativeReadError','OpenTokenError','ElevationTypeError','ElevationError','RestrictedError','HasLinkedToken','LinkedTokenQuery','LinkedTokenError')){
  $p=if($null -ne $Evidence){$Evidence.PSObject.Properties[$name]}else{$null}
  $value=if($null -eq $p -or $null -eq $p.Value){'unknown'}elseif($p.Value -is [bool] -or $p.Value -is [int] -or $p.Value -is [long]){[string]$p.Value}elseif($p.Value -is [string] -and $p.Value -cmatch '^-?[0-9]{1,10}$'){[string]$p.Value}elseif($p.Value -in @('Registry64','Unknown','DWord','String','QWord','Binary','MultiString','ExpandString','None','NOT_RUN','ERROR','PRESENT','ABSENT')){[string]$p.Value}else{'unsupported'}
  $parts.Add($name+'='+$value)
 }
 foreach($query in @(@('TokenElevationType',18,'ElevationTypeError','ElevationTypeBufferLength'),@('TokenElevation',20,'ElevationError','ElevationBufferLength'),@('TokenIsRestricted',40,'RestrictedError','RestrictedBufferLength'),@('TokenLinkedToken',19,'LinkedTokenError','LinkedTokenBufferLength'))){
  $errorProperty=if($null -ne $Evidence){$Evidence.PSObject.Properties[$query[2]]}else{$null}
  if($null -ne $errorProperty -and $errorProperty.Value -is [int] -and $errorProperty.Value -ne 0){
   $lengthProperty=$Evidence.PSObject.Properties[$query[3]]
   $length=if($null -ne $lengthProperty -and $lengthProperty.Value -is [int]){[string]$lengthProperty.Value}else{'unknown'}
   $parts.Add('call=GetTokenInformation; class='+$query[0]+'('+[string]$query[1]+'); error='+[string]$errorProperty.Value+'; buffer_length='+$length)
  }
 }
 return $parts -join '; '
}

function Get-FreshExecutionEvidence {
 if($env:OS -ne 'Windows_NT'){throw 'WINDOWS_TOKEN_QUERY_REQUIRED'}
 $e=New-FreshExecutionEvidence
 # Collect independent evidence even if another query fails. Null/error is
 # never silently converted to false/zero; reject with partial diagnostics.
 try{
  $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
  try{
   $key=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',$false)
   if($null -eq $key){throw 'UAC_POLICY_MISSING'}
   try{
    $e.EnableLUA=$key.GetValue('EnableLUA');$e.ConsentPromptBehaviorAdmin=$key.GetValue('ConsentPromptBehaviorAdmin')
    $e.EnableLUAKind=$key.GetValueKind('EnableLUA').ToString();$e.ConsentKind=$key.GetValueKind('ConsentPromptBehaviorAdmin').ToString()
    $e.PolicyReadError=0
   }finally{$key.Dispose()}
  }finally{$base.Dispose()}
 }catch{$e.PolicyReadError=$_.Exception.HResult}
 try{
  # V3 prevents reusing the incorrect DWORD ABI after retry in the same PS.
  if($null -eq ('Veliq.FreshPCTokenV3' -as [type])){
   Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace Veliq {
 public sealed class FreshPCTokenV3 {
  public int? ElevationType { get; private set; }
  public bool? Elevated { get; private set; }
  public bool? HasLinkedToken { get; private set; }
  public bool? Restricted { get; private set; }
  public int OpenTokenError, ElevationTypeError, ElevationError, RestrictedError, LinkedTokenError;
  public readonly int ElevationTypeBufferLength=sizeof(int), ElevationBufferLength=sizeof(int), RestrictedBufferLength=sizeof(int);
  public readonly int LinkedTokenBufferLength=Marshal.SizeOf(typeof(TokenLinkedToken));
  [StructLayout(LayoutKind.Sequential)]
  struct TokenLinkedToken { public IntPtr LinkedToken; }
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", EntryPoint="GetTokenInformation", ExactSpelling=true, SetLastError=true)]
  static extern bool GetTokenInformationDword(IntPtr token, int info, out int value, int size, out int needed);
  [DllImport("advapi32.dll", EntryPoint="GetTokenInformation", ExactSpelling=true, SetLastError=true)]
  static extern bool GetTokenInformationLinked(IntPtr token, int info, out TokenLinkedToken value, int size, out int needed);
  // Shared result validation is exercised without native calls in isolated tests.
  internal static int? CheckedDwordResult(bool success, int value, int needed, int nativeError, out int error) {
   if(!success) { error=nativeError!=0 ? nativeError : 13; return null; }
   if(needed!=sizeof(int)) { error=24; return null; }
   error=0; return value;
  }
  static int? Dword(IntPtr token, int kind, out int error) {
   int needed, value;
   bool success=GetTokenInformationDword(token,kind,out value,sizeof(int),out needed);
   int nativeError=success ? 0 : Marshal.GetLastWin32Error();
   return CheckedDwordResult(success,value,needed,nativeError,out error);
  }
  public static FreshPCTokenV3 Read() {
   var result=new FreshPCTokenV3();
   IntPtr token;
   // TOKEN_QUERY only: no privileges, token lowering or impersonation.
   if(!OpenProcessToken(GetCurrentProcess(), 8, out token)) { result.OpenTokenError=Marshal.GetLastWin32Error(); return result; }
   try {
    result.ElevationType=Dword(token,18,out result.ElevationTypeError);
    int? elevated=Dword(token,20,out result.ElevationError);
    result.Elevated=elevated.HasValue ? (bool?)(elevated.Value!=0) : null;
    // TokenIsRestricted=40, matching the owner's actual token fact.
    int? restricted=Dword(token,40,out result.RestrictedError);
    result.Restricted=restricted.HasValue ? (bool?)(restricted.Value!=0) : null;
    int needed;
    TokenLinkedToken linked;
    if(GetTokenInformationLinked(token,19,out linked,result.LinkedTokenBufferLength,out needed)) {
     IntPtr other=linked.LinkedToken;
     result.HasLinkedToken=other!=IntPtr.Zero;
     if(other!=IntPtr.Zero) CloseHandle(other);
    } else {
     result.LinkedTokenError=Marshal.GetLastWin32Error();
     if(result.ElevationType==1 && result.LinkedTokenError!=0) result.HasLinkedToken=false;
    }
    return result;
   } finally { CloseHandle(token); }
  }
 }
}
'@
  }
  $token=[Veliq.FreshPCTokenV3]::Read()
  foreach($name in @('ElevationType','Elevated','Restricted','HasLinkedToken','OpenTokenError','ElevationTypeError','ElevationError','RestrictedError','LinkedTokenError','ElevationTypeBufferLength','ElevationBufferLength','RestrictedBufferLength','LinkedTokenBufferLength')){$e.$name=$token.$name}
  $e.LinkedTokenQuery=if($e.LinkedTokenError -ne 0){'ERROR'}elseif($e.HasLinkedToken -is [bool]){if($e.HasLinkedToken){'PRESENT'}else{'ABSENT'}}else{'NOT_RUN'}
  $e.NativeReadError=0
 }catch{$e.NativeReadError=$_.Exception.HResult}
 try{
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{$e.IsAdministrator=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);$e.OwnerQueryError=0}finally{$identity.Dispose()}
 }catch{$e.OwnerQueryError=$_.Exception.HResult}
 return $e
}

function Invoke-FreshServicePhase([string]$Mode,[string]$Sid,[scriptblock]$InProcess,[scriptblock]$Elevate) {
 switch -Exact ($Mode) {
  'UAC_DISABLED_FULL_ADMIN' { & $InProcess $Sid; return }
  'UAC_ENABLED_OWNER' { & $Elevate $Sid; return }
  default { throw 'UNVERIFIED_SERVICE_EXECUTION_MODE' }
 }
}
