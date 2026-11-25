# Инертный мастер: настоящие оформление/обработчики, без установки VELIQ.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Compiler,[switch]$AllowLocalInertFixture)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -and !$AllowLocalInertFixture){throw 'EXPLICIT_INERT_VISUAL_CHECK_REQUIRED'}
$repo=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$source=Get-Content -Raw -Encoding UTF8 (Join-Path $repo 'installer/setup.iss')
$theme=Get-Content -Raw -Encoding UTF8 (Join-Path $repo 'installer/setup-theme.iss')
$policy=Get-Content -Raw -Encoding UTF8 (Join-Path $repo 'installer/setup-mode.iss')
function Section([string]$Name){
 $m=[regex]::Match($source,'(?ms)^\['+[regex]::Escape($Name)+'\]\r?\n(.*?)(?=^\[|\z)')
 if(!$m.Success){throw ('VISUAL_SECTION_MISSING '+$Name)};return $m.Groups[1].Value
}
function Handler([string]$Start,[string]$End){
 $m=[regex]::Match($source,'(?s)'+[regex]::Escape($Start)+'.*?(?='+[regex]::Escape($End)+')')
 if(!$m.Success){throw ('VISUAL_HANDLER_MISSING '+$Start)};return $m.Value
}
$handlers=(Handler 'function RequestedVeliqOperation()' 'procedure LockNoRestartChoice;')+"`n"+
 (Handler 'procedure LockNoRestartChoice;' 'procedure InitializeWizard;')+"`n"+
 (Handler 'procedure CurPageChanged(' 'function ShouldSkipPage(').Replace('procedure CurPageChanged(','procedure ActualPageChanged(')+"`n"+
 (Handler 'function NextButtonClick(' 'function DiagnosticFile(').Replace('function NextButtonClick(','function ActualNextButtonClick(')
$appearance=@((Section 'Setup') -split "`r?`n" | Where-Object {$_ -match '^(WizardStyle|WizardSizePercent|WizardImageFile|WizardSmallImageFile|WizardImageStretch|DisableWelcomePage)='}) -join "`n"
$build=(& git -C $repo rev-list --count HEAD).Trim();if($LASTEXITCODE){throw 'VISUAL_SOURCE_VERSION_FAILED'}
$output=Join-Path $repo 'bin/installer-visual';$null=New-Item $output -ItemType Directory -Force
$directory=Join-Path ([IO.Path]::GetTempPath()) ('veliq-inert-design-'+[guid]::NewGuid().ToString('N'))
$null=New-Item $directory -ItemType Directory
Copy-Item -LiteralPath (Join-Path $repo 'installer/assets') -Destination $directory -Recurse
$fixture=@'
#define AppVersion "0.3.{BUILD}"
[Setup]
AppName=VELIQ visual fixture
AppVersion=1
DefaultDirName={tmp}\veliq-inert-visual
CreateAppDir=no
CreateUninstallRegKey=no
Uninstallable=no
UsePreviousAppDir=no
PrivilegesRequired=lowest
AlwaysRestart=no
RestartIfNeededByRun=no
CloseApplications=no
RestartApplications=no
DisableDirPage=yes
DisableProgramGroupPage=yes
OutputDir=.
OutputBaseFilename=visual
{APPEARANCE}
[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
[LangOptions]
{LANG}
[Messages]
{MESSAGES}
SetupWindowTitle=VELIQ — проверка оформления
[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Ярлыки:"
[Run]
Filename: "{cmd}"; Parameters: "/d /c exit 0"; Description: "Открыть VELIQ"; Flags: postinstall unchecked
[Code]
var ExistingInstall, ExistingManifest, PackageCompleted: Boolean;
    InstalledVersion, SelectedOperation, InstallScanDirectory, DiagnosticPath: String;
    OperationPage: TInputOptionWizardPage;
    UpdateOption, ReinstallOption, Revision, CurrentPage: Integer;
{POLICY}
{THEME}
procedure ReadVeliqInstallation;
begin
 ExistingInstall := ExpandConstant('{param:PRESENT|0}')='1';
 ExistingManifest := ExistingInstall;
 InstalledVersion := '0.3.739';
end;
{HANDLERS}
function Stage: String;
begin
 Result := 'other';
 if CurrentPage=wpWelcome then Result := 'welcome';
 if CurrentPage=wpReady then Result := 'ready';
 if CurrentPage=wpFinished then Result := 'finished';
 if CurrentPage=wpPreparing then Result := 'preparing';
 if CurrentPage=wpInstalling then Result := 'installing';
 if OperationPage<>nil then if CurrentPage=OperationPage.ID then Result := 'operation';
end;
procedure SaveState;
var Choice: Integer; S: String;
begin
 Revision := Revision+1; Choice := -1;
 if OperationPage<>nil then Choice := OperationPage.SelectedValueIndex;
 S := '{"revision":'+IntToStr(Revision)+',"stage":"'+Stage+'","dark":'+IntToStr(Ord(VeliqDark))+
   ',"window":'+IntToStr(WizardForm.Handle)+',"next":'+IntToStr(WizardForm.NextButton.Handle)+
   ',"theme":'+IntToStr(VeliqThemeButton.Handle)+',"choice":'+IntToStr(Choice)+
   ',"width":'+IntToStr(WizardForm.ClientWidth)+',"height":'+IntToStr(WizardForm.ClientHeight)+
   ',"brand_width":'+IntToStr(WizardForm.WizardBitmapImage.Width)+
   ',"brand_height":'+IntToStr(WizardForm.WizardBitmapImage.Height)+
   ',"brand_bitmap_width":'+IntToStr(WizardForm.WizardBitmapImage.Bitmap.Width)+
   ',"bitmap_background":'+IntToStr(WizardForm.WizardBitmapImage.BackColor)+
   ',"memo_background":'+IntToStr(WizardForm.ReadyMemo.Color)+'}';
 SaveStringToFile(ExpandConstant('{param:STATE}'),S,False);
end;
procedure ToggleTheme(Sender: TObject);
begin
 VeliqThemeChanged(Sender); SaveState;
end;
procedure InitializeWizard;
begin
 DiagnosticPath := 'Визуальный стенд: продукт не устанавливается';
 InitializeVeliqOperation; LockNoRestartChoice; InitializeVeliqTheme;
 VeliqThemeButton.OnClick := @ToggleTheme;
end;
procedure CurPageChanged(CurPageID: Integer);
begin
 CurrentPage := CurPageID; ActualPageChanged(CurPageID); SaveState;
end;
function NextButtonClick(CurPageID: Integer): Boolean;
begin
 Result := (CurPageID<>wpFinished) and ActualNextButtonClick(CurPageID);
end;
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
 NeedsRestart := False; Result := '';
 if ExpandConstant('{param:SHOWERROR|0}')='1' then
   Result := VeliqFailureMessage('INSTALL_FILE_IN_USE_OR_NOT_WRITABLE');
end;
procedure CurStepChanged(CurStep: TSetupStep);
begin
 if CurStep=ssPostInstall then PackageCompleted := True;
end;
'@
$fixture=$fixture.Replace('{BUILD}',$build).Replace('{APPEARANCE}',$appearance).Replace('{LANG}',(Section 'LangOptions')).Replace('{MESSAGES}',(Section 'Messages')).Replace('{POLICY}',$policy).Replace('{THEME}',$theme).Replace('{HANDLERS}',$handlers)
[IO.File]::WriteAllText((Join-Path $directory 'visual.iss'),$fixture,[Text.UTF8Encoding]::new($true))
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class InertWizardCapture {
 [StructLayout(LayoutKind.Sequential)] public struct Rect {public int Left,Top,Right,Bottom;}
 [StructLayout(LayoutKind.Sequential)] public struct Point {public int X,Y;}
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out Rect r);
 [DllImport("user32.dll")] public static extern bool ClientToScreen(IntPtr h,ref Point p);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint id);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h,IntPtr dc,uint flags);
 [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h,uint m,IntPtr w,IntPtr l);
}
'@
$shots=New-Object 'System.Collections.Generic.List[string]'
function Read-State([string]$Path,[int]$After=0,[string[]]$Stages=@()){
 $until=[DateTime]::UtcNow.AddSeconds(30)
 do{
  if(Test-Path -LiteralPath $Path){try{$s=Get-Content -Raw -LiteralPath $Path|ConvertFrom-Json;if($s.revision -gt $After -and (!$Stages.Count -or $s.stage -in $Stages)){return $s}}catch{}}
  Start-Sleep -Milliseconds 100
 }while([DateTime]::UtcNow -lt $until)
 throw 'VISUAL_STATE_TIMEOUT'
}
function Click-Own([object]$State,[string]$Control){
 [void][InertWizardCapture]::SendMessage([IntPtr]([long]$State.$Control),0xF5,[IntPtr]::Zero,[IntPtr]::Zero)
}
function Save-Shot([object]$State,[string]$Name){
 Start-Sleep -Milliseconds 250
 $rect=New-Object InertWizardCapture+Rect
 if(![InertWizardCapture]::GetWindowRect([IntPtr]([long]$State.window),[ref]$rect)){throw 'VISUAL_WINDOW_UNAVAILABLE'}
 $bitmap=New-Object Drawing.Bitmap ($rect.Right-$rect.Left),($rect.Bottom-$rect.Top)
 try{
  $graphics=[Drawing.Graphics]::FromImage($bitmap);$dc=$graphics.GetHdc()
  try{if(![InertWizardCapture]::PrintWindow([IntPtr]([long]$State.window),$dc,2)){throw 'VISUAL_PRINT_WINDOW_FAILED'}}finally{$graphics.ReleaseHdc($dc);$graphics.Dispose()}
  $path=Join-Path $output ($Name+'.png');$bitmap.Save($path,[Drawing.Imaging.ImageFormat]::Png);$shots.Add($path)
  if($State.stage -in @('welcome','finished')){
   $origin=New-Object InertWizardCapture+Point
   if(![InertWizardCapture]::ClientToScreen([IntPtr]([long]$State.window),[ref]$origin)){throw 'VISUAL_CLIENT_UNAVAILABLE'}
   $white=0;$orange=0;$dx=$origin.X-$rect.Left;$dy=$origin.Y-$rect.Top
   for($y=2;$y -lt $State.brand_height-2;$y+=2){for($x=2;$x -lt $State.brand_width-2;$x+=2){
    $color=$bitmap.GetPixel($dx+$x,$dy+$y)
    if($color.R -gt 210 -and $color.G -gt 210 -and $color.B -gt 210){$white++}
    if($color.R -gt 180 -and $color.G -gt 30 -and $color.G -lt 180 -and $color.B -lt 100){$orange++}
   }}
   if($white -lt 40 -or $orange -lt 2){
    $encoded=[Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
    for($n=0;$n -lt $encoded.Length;$n+=3000){Write-Host ('VELIQ_VISUAL_PNG failure '+[int]($n/3000)+' '+$encoded.Substring($n,[math]::Min(3000,$encoded.Length-$n)))}
    throw ('VISUAL_BRAND_MISSING '+$Name+' white='+$white+' orange='+$orange)
   }
  }
 }finally{$bitmap.Dispose()}
 [IO.File]::WriteAllText((Join-Path $output ($Name+'.json')),($State|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
}
function Both-Themes([object]$State,[string]$Name,[string]$StateFile){
 if($State.dark -ne 1){throw 'VISUAL_INITIAL_THEME_NOT_DARK'}
 if($State.bitmap_background -ne 0x0B0A0A){throw 'VISUAL_WHITE_BITMAP_FRAME'}
 Save-Shot $State ($Name+'-dark')
 Click-Own $State 'theme';$light=Read-State $StateFile $State.revision
 if($light.dark -ne 0 -or $light.choice -ne $State.choice -or $light.stage -cne $State.stage){throw 'VISUAL_THEME_CHANGED_SELECTION'}
 Save-Shot $light ($Name+'-light')
 Click-Own $light 'theme';$dark=Read-State $StateFile $light.revision
 if($dark.dark -ne 1 -or $dark.choice -ne $State.choice -or $dark.stage -cne $State.stage){throw 'VISUAL_THEME_RESTORE_CHANGED_SELECTION'}
 return $dark
}
try{
 & $Compiler '/Q' (Join-Path $directory 'visual.iss');if($LASTEXITCODE){throw 'VISUAL_FIXTURE_COMPILE_FAILED'}
 foreach($case in @(@{name='fresh';present=0;error=0},@{name='update';present=1;error=0},@{name='error';present=1;error=1})){
  $stateFile=Join-Path $directory ($case.name+'.json');$fixturePid=0
  $p=Start-Process -FilePath (Join-Path $directory 'visual.exe') -ArgumentList @('/SP-','/NORESTART',('/STATE="'+$stateFile+'"'),('/PRESENT='+$case.present),('/SHOWERROR='+$case.error)) -PassThru
  try{
   $s=Read-State $stateFile;[uint32]$windowPid=0;[void][InertWizardCapture]::GetWindowThreadProcessId([IntPtr]([long]$s.window),[ref]$windowPid)
   $processInfo=Get-CimInstance Win32_Process -Filter ('ProcessId='+$windowPid)
   if($windowPid -eq 0 -or ($windowPid -ne $p.Id -and $processInfo.ParentProcessId -ne $p.Id)){throw 'VISUAL_FOREIGN_WINDOW_REFUSED'}
   $fixturePid=$windowPid;$s=Both-Themes $s ($case.name+'-welcome') $stateFile
   for($i=0;$i -lt 10 -and $s.stage -cne 'ready';$i++){
    Click-Own $s 'next';$s=Read-State $stateFile $s.revision
    if($s.stage -eq 'operation'){$s=Both-Themes $s ($case.name+'-operation') $stateFile}
   }
   if($s.stage -cne 'ready'){throw 'VISUAL_READY_NOT_REACHED'}
   $s=Both-Themes $s ($case.name+'-ready') $stateFile
   Click-Own $s 'next'
   if($case.error){$s=Read-State $stateFile $s.revision @('preparing');Start-Sleep -Milliseconds 400;$null=Both-Themes $s 'failure' $stateFile}
   else{$s=Read-State $stateFile $s.revision @('finished');$null=Both-Themes $s ($case.name+'-finished') $stateFile}
  }finally{
   if($fixturePid -ne 0 -and $fixturePid -ne $p.Id){$child=Get-Process -Id $fixturePid -ErrorAction SilentlyContinue;if($child){$child.Kill();$child.WaitForExit();$child.Dispose()}}
   if(!$p.HasExited){$p.Kill();$p.WaitForExit()};$p.Dispose()
  }
 }
 if($env:VELIQ_INSTALLER_VISUAL_EXPORT -ceq '1'){
  foreach($flavor in @('dark','light')){
   $chosen=@('update-welcome','update-operation','update-ready','update-finished','failure')
   $tileWidth=620;$tileHeight=500;$sheet=New-Object Drawing.Bitmap ($tileWidth*2),($tileHeight*3)
   try{
    $g=[Drawing.Graphics]::FromImage($sheet);$g.Clear([Drawing.Color]::FromArgb(34,37,42));$font=New-Object Drawing.Font 'Segoe UI',10
    try{
     for($i=0;$i -lt $chosen.Count;$i++){
      $img=[Drawing.Image]::FromFile((Join-Path $output ($chosen[$i]+'-'+$flavor+'.png')))
      try{$x=($i%2)*$tileWidth;$y=[math]::Floor($i/2)*$tileHeight;$g.DrawString(('Инертный стенд: '+$chosen[$i]),$font,[Drawing.Brushes]::White,[single]($x+8),[single]($y+4));$ratio=[math]::Min(($tileWidth-16)/$img.Width,($tileHeight-30)/$img.Height);$g.DrawImage($img,[single]($x+8),[single]($y+26),[single]($img.Width*$ratio),[single]($img.Height*$ratio))}finally{$img.Dispose()}
     }
    }finally{$font.Dispose();$g.Dispose()}
    $sheetFile=Join-Path $output ('contact-'+$flavor+'.png');$sheet.Save($sheetFile,[Drawing.Imaging.ImageFormat]::Png)
    $encoded=[Convert]::ToBase64String([IO.File]::ReadAllBytes($sheetFile));for($n=0;$n -lt $encoded.Length;$n+=3000){Write-Output ('VELIQ_VISUAL_PNG '+$flavor+' '+[int]($n/3000)+' '+$encoded.Substring($n,[math]::Min(3000,$encoded.Length-$n)))}
   }finally{$sheet.Dispose()}
  }
 }
 Write-Output ('INSTALLER_VISUAL_PASS screenshots='+$shots.Count+' production_install=false')
}finally{Remove-Item -LiteralPath $directory -Recurse -Force}
