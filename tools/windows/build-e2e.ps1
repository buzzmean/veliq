[CmdletBinding()]
param([string]$Output=(Join-Path $PSScriptRoot '..\..\bin\windows-e2e'),
 [string]$DriverDirectory=(Join-Path $PSScriptRoot '..\..\.e2e\windivert'))
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
New-Item -ItemType Directory -Force $Output|Out-Null
$Output=(Resolve-Path $Output).Path
# Only known generated payloads; preserve every config/identity/token and installed copy.
if((Get-Item -LiteralPath $Output).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'BUILD_OUTPUT_REPARSE_POINT_REFUSED'}
if((Test-Path -LiteralPath (Join-Path $Output 'service.json')) -or (Test-Path -LiteralPath (Join-Path $Output 'identity.json'))){throw 'BUILD_OUTPUT_LOOKS_INSTALLED; use a separate build directory'}
function Remove-E2EGeneratedBinaries {
 foreach($name in @('network-check.exe','veliq-service.exe','capture-acceptance.exe','lease-acceptance.exe','browser-recovery-acceptance.exe','test-game.exe','control-client.exe','udp-plus.exe','tcp-selected.exe','tcp-control.exe','tcp-plus.exe','enroll.exe','vps-provision.exe')){
  $path=Join-Path $Output $name
  if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force -ErrorAction Stop}
 }
 $linuxDir=Join-Path $Output 'linux'
 if(Test-Path -LiteralPath $linuxDir){
  if((Get-Item -LiteralPath $linuxDir).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'BUILD_LINUX_OUTPUT_REPARSE_POINT_REFUSED'}
  foreach($name in @('relay','control-plane','remote-echo','probe-client','web-test-target')){
   $path=Join-Path $linuxDir $name
   if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force -ErrorAction Stop}
  }
 }
}
# A failed compiler gate must never leave yesterday's service available to update-service.
Remove-E2EGeneratedBinaries
Push-Location $root
$oldOS=$env:GOOS;$oldArch=$env:GOARCH;$oldCGO=$env:CGO_ENABLED
try {
 $env:GOOS='windows';$env:GOARCH='amd64';$env:CGO_ENABLED='0'
 & go test ./platform/windows -run '^TestServiceWinDivertFilterInventory$'
 if($LASTEXITCODE){throw 'WinDivert filter inventory check failed'}
 & go test -c -o (Join-Path $Output 'capture-acceptance.exe') ./platform/windows
 if($LASTEXITCODE){throw 'Native capture acceptance build failed'}
 & (Join-Path $PSScriptRoot 'test-windivert-filters.ps1') -TestExecutable (Join-Path $Output 'capture-acceptance.exe') -DriverDirectory $DriverDirectory
 $targets=@{
  'network-check.exe'='./tools/network-check';
  'veliq-service.exe'='./services/client-service/cmd/service';'test-game.exe'='./tools/windows-test-client';
  'tcp-selected.exe'='./tools/tcp-test-client';'enroll.exe'='./tools/enroll';'vps-provision.exe'='./tools/vps-provision'
 }
 # The service carries the monotonic build sequence its auto-updater compares
# against signed release manifests (git commit count of the build commit).
$sequence=(& git -C $root rev-list --count HEAD).Trim();if($LASTEXITCODE -or $sequence -notmatch '^[0-9]+$'){$sequence='0'}
$ldflags='-X github.com/buzzmean/neexitlag/services/client-service.BuildSequence='+$sequence
foreach($name in $targets.Keys){& go build -trimpath -ldflags $ldflags -o (Join-Path $Output $name) $targets[$name];if($LASTEXITCODE){throw "Build failed: $name"}}
 & go test -c -o (Join-Path $Output 'lease-acceptance.exe') ./tests/integration
 if($LASTEXITCODE){throw 'Lease acceptance build failed'}
 & go test -c -o (Join-Path $Output 'browser-recovery-acceptance.exe') ./services/client-service/cmd/service
 if($LASTEXITCODE){throw 'Chrome recovery acceptance build failed'}

 Copy-Item (Join-Path $Output 'tcp-selected.exe') (Join-Path $Output 'tcp-control.exe')
 Copy-Item (Join-Path $Output 'tcp-selected.exe') (Join-Path $Output 'tcp-plus.exe')
 $scripts=Join-Path $Output 'tools\windows';New-Item -ItemType Directory -Force $scripts|Out-Null;Copy-Item (Join-Path $PSScriptRoot '*.ps1') $scripts
 $licenses=Join-Path $Output 'third_party\licenses';New-Item -ItemType Directory -Force $licenses|Out-Null;Copy-Item (Join-Path $root 'third_party\licenses\*.txt') $licenses;Copy-Item (Join-Path $root 'third_party\NOTICE.md') (Join-Path $Output 'third_party\NOTICE.md')
 $docs=Join-Path $Output 'docs';New-Item -ItemType Directory -Force $docs|Out-Null;Copy-Item (Join-Path $root 'docs\DIRECT_PLUS.md') $docs;Copy-Item (Join-Path $root 'docs\DIRECT_PLUS_V2.md') $docs;Copy-Item (Join-Path $root 'docs\WINDOWS_APPLICATION_PICKER.md') $docs;Copy-Item (Join-Path $root 'docs\AUTO_FLOW_ROUTING.md') $docs;Copy-Item (Join-Path $root 'docs\ADAPTIVE_UDP_HEALTH.md') $docs;Copy-Item (Join-Path $root 'docs\RELAY_SESSION_POOL.md') $docs;Copy-Item (Join-Path $root 'docs\WINDOWS_CAPTURE_LIFECYCLE.md') $docs;Copy-Item (Join-Path $root 'docs\WINDOWS_HOT_ATTACH.md') $docs
 Copy-Item (Join-Path $root 'docs\RELAY_LEASE_RENEWAL.md') $docs
 Copy-Item (Join-Path $Output 'test-game.exe') (Join-Path $Output 'control-client.exe')
 Copy-Item (Join-Path $Output 'test-game.exe') (Join-Path $Output 'udp-plus.exe')
 $linux=Join-Path $Output 'linux';New-Item -ItemType Directory -Force $linux|Out-Null
 $env:GOOS='linux'
 foreach($entry in @(@('relay','./services/relay/cmd/relay'),@('control-plane','./services/control-plane/cmd/control-plane'),@('remote-echo','./tools/remote-echo'),@('probe-client','./tools/windows-test-client'),@('web-test-target','./tools/web-test-target'))){& go build -trimpath -o (Join-Path $linux $entry[0]) $entry[1];if($LASTEXITCODE){throw "Linux build failed: $($entry[0])"}}
 Write-Host "Windows test binaries and Linux deployment binaries ready in $Output"
} catch {
 # Also remove partial NEW binaries if a later test/Linux build/copy failed.
 Remove-E2EGeneratedBinaries
 throw
} finally {$env:GOOS=$oldOS;$env:GOARCH=$oldArch;$env:CGO_ENABLED=$oldCGO;Pop-Location}
