# Private code handling only. Never print the returned value or pass it on argv.
function Read-ClubCodeFile([string]$Path){
 $item=Get-Item -LiteralPath $Path
 if($item.PSIsContainer -or $item.Length -gt 256 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'CLUB_CODE_FILE_INVALID'}
 $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 foreach($rule in (Get-Acl -LiteralPath $item.FullName).Access){$sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;if($rule.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18','S-1-5-32-544',$owner)){throw 'CLUB_CODE_FILE_ACL_UNSAFE'}}
 $code=[IO.File]::ReadAllText($item.FullName).Trim()
 if($code -cnotmatch '^VQ(-[A-Z2-7]{4}){6}$'){throw 'CLUB_CODE_FORMAT_INVALID'}
 return $code
}
function New-ClubPendingRecord([string]$Code){
 if($Code -cnotmatch '^VQ(-[A-Z2-7]{4}){6}$'){throw 'CLUB_CODE_FORMAT_INVALID'}
 return @{code=$Code;request_id=[Guid]::NewGuid().ToString('N');pending=$true}
}
function Invoke-ClubCodeReplacement([string]$Directory,$Record,[switch]$Image){
 # Offline image edits must NEVER touch the admin PC SCM.
 if($Image){Write-ClubJson (Join-Path $Directory 'activation-code.json.pending') $Record;return}
 $service=Get-Service VELIQ -ErrorAction SilentlyContinue
 if(!$Image -and !$service){throw 'CLUB_SERVICE_NOT_FOUND'}
 $wasRunning=$service -and $service.Status -ne 'Stopped'
 try{
  if($wasRunning){Stop-Service VELIQ;(Get-Service VELIQ).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
  Write-ClubJson (Join-Path $Directory 'activation-code.json.pending') $Record
  if(!$Image){Start-Service VELIQ;(Get-Service VELIQ).WaitForStatus('Running',[TimeSpan]::FromSeconds(45))}
 }catch{
  if(!$Image -and $wasRunning){try{Start-Service VELIQ}catch{throw 'CLUB_CODE_REPLACEMENT_FAILED_SERVICE_RESTORE_FAILED'}}
  throw 'CLUB_CODE_REPLACEMENT_FAILED; private records preserved; check service and activation.status'
 }
}
