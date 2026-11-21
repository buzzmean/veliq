# Isolated per-user GUI migration filesystem/shortcut regression. No real service,
# Chrome policy, credentials, installed GUI, or application process is changed.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Join-Path ([IO.Path]::GetTempPath()) ('veliq-gui-upgrade-'+[Guid]::NewGuid().ToString('N'))
$source=Join-Path $root 'build';$installed=Join-Path $root 'installed';$links=Join-Path $root 'links'
$runKey='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$hadRunKey=Test-Path $runKey;$saved=@{}
if($hadRunKey){$item=Get-Item -LiteralPath $runKey;foreach($n in 'NeExitLag','VELIQ'){if($n -in $item.GetValueNames()){$saved[$n]=@($item.GetValue($n),$item.GetValueKind($n))}}}
try{
 foreach($dir in @($source,$installed,$links)){[void][IO.Directory]::CreateDirectory($dir)}
 # These are inert fixture bytes, not an executable or private key.
 [IO.File]::WriteAllText((Join-Path $source 'VELIQ.exe'),'VELIQ GUI fixture v1')
 $legacy=Join-Path $installed 'NeExitLag.exe';[IO.File]::WriteAllText($legacy,'legacy GUI fixture')
 $protected=@('ProgramData/VELIQ/identity.json','ProgramData/VELIQ/state/profiles.json','LocalAppData/NeExitLag/desktop.json','LocalAppData/NeExitLag/chrome-proxy-policy.json','LocalAppData/NeExitLag/chrome-recovery.json')
 $hashes=@{}
 foreach($relative in $protected){$path=Join-Path $root $relative;[void][IO.Directory]::CreateDirectory((Split-Path $path));[IO.File]::WriteAllText($path,"preserve fixture $relative");$hashes[$relative]=(Get-FileHash $path).Hash}
 $shell=New-Object -ComObject WScript.Shell
 $oldLink=Join-Path $links 'NeExitLag.lnk';$link=$shell.CreateShortcut($oldLink);$link.TargetPath=$legacy;$link.Save()
 if(!$hadRunKey){New-Item -Path $runKey -Force|Out-Null}
 Set-ItemProperty -LiteralPath $runKey -Name NeExitLag -Value ('"'+$legacy+'"')
 $script=Join-Path $PSScriptRoot '../../tools/windows/install-desktop.ps1'
 & $script -SourceDirectory $source -InstallDirectory $installed -ShortcutDirectory $links
 $target=Join-Path $installed 'VELIQ.exe'
 if(Test-Path $legacy){throw 'Owned legacy NeExitLag.exe alias not removed'}
 if(Test-Path $oldLink){throw 'Owned legacy shortcut not replaced'}
 if($shell.CreateShortcut((Join-Path $links 'VELIQ.lnk')).TargetPath -ine $target){throw 'New shortcut target mismatch'}
 $runValues=Get-ItemProperty -LiteralPath $runKey;if($runValues.VELIQ -ne ('"'+$target+'"') -or $runValues.PSObject.Properties['NeExitLag']){throw 'Enabled owned startup not moved to VELIQ'}
 [IO.File]::WriteAllText((Join-Path $source 'VELIQ.exe'),'VELIQ GUI fixture v2')
 & $script -SourceDirectory $source -InstallDirectory $installed -ShortcutDirectory $links
 if([IO.File]::ReadAllText($target) -ne 'VELIQ GUI fixture v2'){throw 'Idempotent update failed'}
 foreach($relative in $protected){if((Get-FileHash (Join-Path $root $relative)).Hash -ne $hashes[$relative]){throw "Upgrade changed $relative"}}
 # Execute the service updater's exact atomic replacement expression too;
 # no SCM/IPC/credentials are used by this focused filesystem regression.
 $tokens=$null;$parseErrors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../../tools/windows/update-service.ps1'),[ref]$tokens,[ref]$parseErrors)
 if($parseErrors.Count){throw 'Service updater parsing failed'}
 $replace=$ast.Find({param($a)$a -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $a.Extent.Text.StartsWith('[IO.File]::Replace(')},$true)
 if($null -eq $replace){throw 'Atomic service replacement missing'}
 $pending=Join-Path $root 'service-pending';$targetBefore=$target;$target=Join-Path $root 'service-installed'
 [IO.File]::WriteAllText($pending,'new service fixture');[IO.File]::WriteAllText($target,'old service fixture')
 Invoke-Expression $replace.Extent.Text
 if([IO.File]::ReadAllText($target) -ne 'new service fixture' -or (Test-Path $pending)){throw 'Service atomic replacement failed'}
 $target=$targetBefore
 $backups=@(Get-ChildItem (Join-Path $installed 'backups') -Directory)
 if($backups.Count -ne 2 -or !@($backups|Where-Object {Test-Path (Join-Path $_.FullName 'NeExitLag.exe')}).Count){throw 'Persistent legacy backup missing'}
 # A pre-existing unidentified executable must not be replaced.
 $foreign=Join-Path $root 'foreign';[void][IO.Directory]::CreateDirectory($foreign)
 $foreignExe=Join-Path $foreign 'VELIQ.exe';[IO.File]::WriteAllText($foreignExe,'foreign application')
 $rejected=$false
 try{& $script -SourceDirectory $source -InstallDirectory $foreign -ShortcutDirectory $links}catch{if($_.Exception.Message -notlike '*no installation marker*'){throw};$rejected=$true}
 if(!$rejected -or [IO.File]::ReadAllText($foreignExe) -ne 'foreign application'){throw 'Foreign executable overwritten'}
 Write-Host 'PASS VELIQ legacy upgrade, identical alias, shortcut, startup, repeat install, preserved identity/profiles/recovery/preferences'
}finally{
 foreach($n in 'NeExitLag','VELIQ'){if($saved.ContainsKey($n)){New-ItemProperty -LiteralPath $runKey -Name $n -Value $saved[$n][0] -PropertyType $saved[$n][1] -Force|Out-Null}else{Remove-ItemProperty -LiteralPath $runKey -Name $n -ErrorAction SilentlyContinue}}
 if(!$hadRunKey -and (Test-Path $runKey)){if((Get-Item $runKey).ValueCount -eq 0){Remove-Item -LiteralPath $runKey}}
 Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
