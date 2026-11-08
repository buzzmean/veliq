# Read-only relationship of pending Windows operations to this package.
function Write-VeliqInstallDiagnostic([string]$Stage,$Evidence) {
 if(!$script:DiagnosticFile){return}
 [ordered]@{utc=[DateTime]::UtcNow.ToString('o');stage=$Stage;evidence=$Evidence} |
  ConvertTo-Json -Depth 6 -Compress | Add-Content -LiteralPath $script:DiagnosticFile -Encoding UTF8
}
function Convert-VeliqPendingPath([string]$Path) {
 if($Path.StartsWith('!')){$Path=$Path.Substring(1)}
 if($Path.StartsWith('*1\??\') -or $Path.StartsWith('*2\??\')){$Path=$Path.Substring(2)}
 if($Path.StartsWith('\??\')){$Path=$Path.Substring(4)}
 if($Path -notmatch '^[a-zA-Z]:\\' -or $Path.Substring(2) -match '[:/*?]' -or $Path.Split('\') -contains '..'){throw 'INSTALL_PENDING_PATH_UNRESOLVED'}
 $Path=[IO.Path]::GetFullPath($Path).TrimEnd('\')
 $tail=@();$ancestor=$Path
 while(!(Test-Path -LiteralPath $ancestor)){
  $tail=@([IO.Path]::GetFileName($ancestor))+$tail
  $ancestor=[IO.Path]::GetDirectoryName($ancestor)
  if(!$ancestor){throw 'INSTALL_PENDING_PATH_UNRESOLVED'}
 }
 $item=Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
 if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'INSTALL_PENDING_PATH_UNRESOLVED'}
 $resolved=$item.FullName.TrimEnd('\')
 foreach($part in $tail){$resolved=Join-Path $resolved $part}
 return $resolved
}
function Get-VeliqInstallRebootState([string]$Directory) {
 $blocking=@();$operations=@();$windowsReasons=@()
 try{
  foreach($pair in @(
   @('SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','CBS_REBOOT_PENDING'),
   @('SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired','WINDOWS_UPDATE_REBOOT_REQUIRED')
  )){if(Read-VeliqRebootRegistry $pair[0]){$windowsReasons+=,$pair[1]}}
  $volatile=Read-VeliqRebootRegistry 'SOFTWARE\Microsoft\Updates' 'UpdateExeVolatile'
  if($null -ne $volatile -and [int]$volatile -ne 0){$windowsReasons+='UPDATE_EXE_VOLATILE'}
  $active=Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' 'ComputerName'
  $pending=Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' 'ComputerName'
  if($active -and $pending -and $active -ine $pending){$windowsReasons+='COMPUTER_RENAME_PENDING'}
  $roots=@($Directory,(Join-Path $env:ProgramData 'VELIQ'),(Join-Path $env:ProgramData 'neexitlag'))
  foreach($name in @('PendingFileRenameOperations','PendingFileRenameOperations2')){
   $value=Read-VeliqRebootRegistry 'SYSTEM\CurrentControlSet\Control\Session Manager' $name
   if($null -eq $value){continue}
   $items=@($value)
   if($items.Count){$windowsReasons+=$name.ToUpperInvariant()}
   if($items.Count % 2){throw 'INSTALL_PENDING_QUEUE_MALFORMED'}
   for($i=0;$i -lt $items.Count;$i+=2){
    if($items[$i] -isnot [string] -or !$items[$i] -or $items[$i+1] -isnot [string]){throw 'INSTALL_PENDING_QUEUE_MALFORMED'}
    $paths=@((Convert-VeliqPendingPath $items[$i]))
    if($items[$i+1]){$paths+=Convert-VeliqPendingPath $items[$i+1]}
    $related=$false
    foreach($path in $paths){
     foreach($root in $roots){
      $root=[IO.Path]::GetFullPath($root).TrimEnd('\')
      if($path -ieq $root -or $path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or $root.StartsWith($path+'\',[StringComparison]::OrdinalIgnoreCase)){$related=$true}
     }
     if($path -match '\\(?:System32|SysWOW64)\\(?:drivers\\)?WinDivert[^\\]*\.(sys|dll)$'){$related=$true}
    }
    $destination='';if($paths.Count -gt 1){$destination=$paths[1]}
    $operations+=@{source=$paths[0];destination=$destination;related=$related}
    if($related){$blocking+=($name.ToUpperInvariant()+'_VELIQ')}
   }
  }
  foreach($service in @('VELIQ','neexitlag')){
   if(Read-VeliqRebootRegistry ('SYSTEM\CurrentControlSet\Services\'+$service) 'DeleteFlag'){$blocking+='SERVICE_DELETE_PENDING'}
  }
  $state=[pscustomobject]@{known=$true;required=($blocking.Count -gt 0);reasons=@($blocking|Select-Object -Unique);deferred_cleanup_count=0;windows_reboot_pending=($windowsReasons.Count -gt 0);windows_reboot_reasons=$windowsReasons;pending_operations=$operations}
  Write-VeliqInstallDiagnostic 'REBOOT_SCOPE' $state
  return $state
 }catch{
  Write-VeliqInstallDiagnostic 'REBOOT_SCOPE_UNKNOWN' @{code='INSTALL_PENDING_QUEUE_UNRESOLVED'}
  return [pscustomobject]@{known=$false;required=$null;reasons=@('INSTALL_PENDING_QUEUE_UNRESOLVED');deferred_cleanup_count=$null}
 }
}
