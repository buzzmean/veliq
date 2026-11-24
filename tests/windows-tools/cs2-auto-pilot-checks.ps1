# Isolated NTFS acceptance, including a deliberately failed commit. Does not touch SCM.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../../tools/windows/cs2-auto-pilot.ps1')
Initialize-Cs2PilotNative
if([Environment]::OSVersion.Platform -ne 'Win32NT'){throw 'NATIVE_WINDOWS_REQUIRED'}
$base=Join-Path ([IO.Path]::GetTempPath()) ('veliq-cs2-pilot-test-'+[Guid]::NewGuid().ToString('N'))
$made=$false
try{
 [VeliqPilotFile]::NewPrivateObject($base,$true);$made=$true
 Assert-Cs2PilotAccess $base 0xD0156
 Test-Cs2PilotTransaction $base
 $target=Join-Path $base 'fixture.dat'; $inputFile=Join-Path $base 'new.dat'
 [VeliqPilotFile]::NewPrivateObject($target,$false)
 Assert-Cs2PilotAccess $target 0xD0156
 [IO.File]::WriteAllBytes($target,[byte[]](5,2,3,2));[IO.File]::WriteAllBytes($inputFile,[byte[]](8))
 $id=[VeliqPilotFile]::Identity($target);$stock=Get-Cs2PilotHash $target;$next=Get-Cs2PilotHash $inputFile
 foreach($bad in @(@('wrong-id',$stock,$next),@($id,'wrong-stock-pin',$next),@($id,$stock,'wrong-candidate-pin'))){
  $failed=$false
  try{[VeliqPilotFile]::Write($target,$inputFile,$bad[0],$bad[1],$bad[2],$true)}catch{$failed=$true}
  if(!$failed -or (Get-Cs2PilotHash $target) -ne $stock -or [VeliqPilotFile]::Identity($target) -cne $id){throw 'TEST_BAD_INPUT_CHANGED_FILE'}
 }
 Write-Output 'PILOT_NATIVE_NTFS_CHECKS_PASS'
}finally{if($made){Remove-Item -LiteralPath $base -Force -Recurse}}
