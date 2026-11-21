# Pure metadata conversion. No process handles, memory, injection or network I/O.
Set-StrictMode -Version Latest
function Get-ObservationValue($Object,[string]$Name,$Default=''){
 if($null -ne $Object){$p=$Object.PSObject.Properties[$Name];if($null -ne $p){return $p.Value}}
 return $Default
}
function ConvertTo-ExitLagEndpoints($Processes,$Tcp,$Udp,[int]$Limit=4096){
 $owners=@{};foreach($p in @($Processes)|Select-Object -First 32){$owners[[string]$p.Pid]=$p}
 $rows=[Collections.Generic.List[object]]::new()
 foreach($kind in @('TCP','UDP')){
  $connections=if($kind -eq 'TCP'){@($Tcp)}else{@($Udp)}
  foreach($c in $connections){
   $id=[string](Get-ObservationValue $c 'OwningProcess' 0);if(!$owners.ContainsKey($id)){continue}
   if($rows.Count -ge $Limit){return $rows.ToArray()}
   $p=$owners[$id];$remote=if($kind -eq 'TCP'){[string](Get-ObservationValue $c 'RemoteAddress')}else{'NOT_EXPOSED_BY_OS'}
   $remotePort=if($kind -eq 'TCP'){[string](Get-ObservationValue $c 'RemotePort')}else{''}
   $key=@($p.Pid,$p.Created,$kind,(Get-ObservationValue $c 'LocalAddress'),(Get-ObservationValue $c 'LocalPort'),$remote,$remotePort) -join '|'
   $rows.Add([pscustomobject]@{Key=$key;Pid=$p.Pid;Created=$p.Created;Name=$p.Name;Protocol=$kind;LocalAddress=(Get-ObservationValue $c 'LocalAddress');LocalPort=(Get-ObservationValue $c 'LocalPort');RemoteAddress=$remote;RemotePort=$remotePort;State=(Get-ObservationValue $c 'State' 'BOUND');RttMs=$null;RttEvidence='NOT_EXPOSED_BY_PASSIVE_API'})
  }
 }
 return $rows.ToArray()
}
