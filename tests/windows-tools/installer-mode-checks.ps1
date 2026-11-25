# Compile real mode/label handlers into an inert wizard. No files, service,
# registry, credentials, OS session or installed VELIQ are changed.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Compiler,[switch]$AllowLocalInertFixture)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -and !$AllowLocalInertFixture){throw 'EXPLICIT_INERT_MODE_CHECK_REQUIRED'}
$source=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot '../../installer/setup.iss')
$policy=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot '../../installer/setup-mode.iss')
$theme=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $PSScriptRoot '../../installer/setup-theme.iss')
function Get-ActualHandler([string]$Start,[string]$End){
 $body=[regex]::Match($source,'(?s)'+[regex]::Escape($Start)+'.*?(?='+[regex]::Escape($End)+')').Value
 if(!$body){throw ('MODE_HANDLER_NOT_FOUND '+$Start)}
 return $body
}
$initialRead=(Get-ActualHandler 'procedure ReadVeliqInstallation;' 'function RequestedVeliqOperation()').Replace('ReadVeliqInstallation','ReadRealVeliqInstallation')
$handlers=(Get-ActualHandler 'function RequestedVeliqOperation()' 'procedure LockNoRestartChoice;')+"`n"+
 (Get-ActualHandler 'function NextButtonClick(' 'function DiagnosticFile(')+"`n"+
 (Get-ActualHandler 'function UpdateArgument(' 'function TransactionErrorCode(')
$fixtureRoot=if($env:RUNNER_TEMP){$env:RUNNER_TEMP}else{[IO.Path]::GetTempPath()}
$directory=Join-Path $fixtureRoot ('veliq-mode-policy-'+[guid]::NewGuid().ToString('N'))
$null=New-Item $directory -ItemType Directory
$fixture=@'
#define AppVersion "0.3.722"
[Setup]
AppName=VELIQ inert installer modes
AppVersion=1
DefaultDirName={tmp}\veliq-inert-mode
CreateAppDir=no
Uninstallable=no
PrivilegesRequired=lowest
AlwaysRestart=no
RestartIfNeededByRun=no
CloseApplications=no
RestartApplications=no
OutputDir=.
OutputBaseFilename=modes
[Code]
var ExistingInstall, ExistingManifest: Boolean;
    InstalledVersion, SelectedOperation, InstallScanDirectory: String;
    OperationPage: TInputOptionWizardPage;
    UpdateOption, ReinstallOption: Integer;
{POLICY}
{THEME}
{INITIAL_READ}
procedure ReadVeliqInstallation;
begin
 ExistingInstall := ExpandConstant('{param:PRESENT|0}')='1';
 ExistingManifest := ExistingInstall;
 InstalledVersion := ExpandConstant('{param:VERSION|}');
end;
{HANDLERS}
procedure InitializeWizard;
var Comparison, Count: Integer; Expected, Memo: String;
begin
 InstallScanDirectory := ExpandConstant('{tmp}\veliq-inert-mode');
 ReadRealVeliqInstallation;
 InitializeVeliqOperation;
 InitializeVeliqTheme;
 if WizardForm.Color<>$0B0A0A then begin Log('MODE_DARK_THEME_FAILED'); Abort; end;
 VeliqThemeChanged(VeliqThemeButton);
 if (WizardForm.Color<>clWhite) or (WizardForm.ReadyMemo.Font.Color<>$0B0A0A) then begin Log('MODE_LIGHT_THEME_FAILED'); Abort; end;
 VeliqThemeChanged(VeliqThemeButton);
 if (WizardForm.Color<>$0B0A0A) or (WizardForm.ReadyMemo.Font.Color<>clWhite) then begin Log('MODE_THEME_RESTORE_FAILED'); Abort; end;
 Expected := ExpandConstant('{param:EXPECT|}');
 if SelectedOperation<>Expected then begin Log('MODE_UNEXPECTED=' + SelectedOperation); Abort; end;
 Count := 0;
 if UpdateOption>=0 then Count := Count + 1;
 if ReinstallOption>=0 then Count := Count + 1;
 if Count<>StrToInt(ExpandConstant('{param:CHOICES|0}')) then begin Log('MODE_CHOICES_FAILED'); Abort; end;
 if ExpandConstant('{param:SELECTREINSTALL|0}')='1' then begin
   OperationPage.SelectedValueIndex := ReinstallOption;
   if not NextButtonClick(OperationPage.ID) or (SelectedOperation<>'REINSTALL') then begin Log('MODE_REINSTALL_SELECTION_FAILED'); Abort; end;
 end;
 if (SelectedOperation='UPDATE') or (SelectedOperation='REINSTALL') then begin
   if UpdateArgument('')<>'-Update' then begin Log('MODE_OWNER_PRESERVATION_FAILED'); Abort; end;
   if LaunchDescription('')<>'Открыть VELIQ' then begin Log('MODE_LAUNCH_LABEL_FAILED'); Abort; end;
 end;
 Memo := UpdateReadyMemo(' ', #13#10, '', 'directory', '', '', '', '');
 if Pos(VeliqOperationCaption(SelectedOperation), Memo)<>1 then begin Log('MODE_READY_MEMO_FAILED'); Abort; end;
 if not CompareVeliqVersions('0.3.99', '0.3.722', Comparison) or (Comparison>=0) then begin Log('MODE_NUMERIC_ORDER_FAILED'); Abort; end;
 if not CompareVeliqVersions('0.3.722.0', '0.3.722', Comparison) or (Comparison<>0) then begin Log('MODE_VERSION_EQUIVALENCE_FAILED'); Abort; end;
 if CompareVeliqVersions('0.3.-1', '0.3.722', Comparison) or
    CompareVeliqVersions('0..722', '0.3.722', Comparison) or
    CompareVeliqVersions('0.3.999999999999999', '0.3.722', Comparison) then begin Log('MODE_MALFORMED_VERSION_ACCEPTED'); Abort; end;
 if not IsVeliqErrorCode('INSTALL_GUI_CLOSE_TIMEOUT') or IsVeliqErrorCode('private path') or
    IsVeliqErrorCode('INSTALL_ERROR' + #13#10 + 'secret') then begin Log('MODE_ERROR_SANITIZER_FAILED'); Abort; end;
 if Pos('«Выход»', VeliqFailureMessage('INSTALL_GUI_GRACEFUL_CLOSE_FAILED'))=0 then begin Log('MODE_ERROR_MESSAGE_FAILED'); Abort; end;
 Log('MODE_POLICY_PASS operation=' + SelectedOperation);
 Abort;
end;
'@
$fixture=$fixture.Replace('{POLICY}',$policy).Replace('{HANDLERS}',$handlers).Replace('{THEME}',$theme).Replace('{INITIAL_READ}',$initialRead)
[IO.File]::WriteAllText((Join-Path $directory 'modes.iss'),$fixture,[Text.UTF8Encoding]::new($true))
try{
 & $Compiler '/Q' (Join-Path $directory 'modes.iss')
 if($LASTEXITCODE){throw 'MODE_FIXTURE_COMPILE_FAILED'}
 $cases=@(
  @{name='fresh';args=@();expect='INSTALL';choices=0},
  @{name='old-update';args=@('/PRESENT=1','/VERSION=0.3.715');expect='UPDATE';choices=2},
  @{name='old-reinstall-selection';args=@('/PRESENT=1','/VERSION=0.3.715','/SELECTREINSTALL=1');expect='UPDATE';choices=2},
  @{name='same-reinstall';args=@('/PRESENT=1','/VERSION=0.3.722.0');expect='REINSTALL';choices=1},
  @{name='newer-preserved';args=@('/PRESENT=1','/VERSION=0.3.723');expect='INSTALL_DOWNGRADE_REFUSED';choices=0},
  @{name='partial-reinstall';args=@('/PRESENT=1');expect='REINSTALL';choices=1},
  @{name='explicit-reinstall';args=@('/PRESENT=1','/VERSION=0.3.715','/ACTION=REINSTALL');expect='REINSTALL';choices=1},
  @{name='service-update';args=@('/PRESENT=1','/VERSION=0.3.722','/UPDATE=1');expect='UPDATE';choices=2},
  @{name='missing-update-refused';args=@('/UPDATE=1');expect='INSTALL_EXISTING_INSTALL_REQUIRED';choices=0},
  @{name='invalid-action';args=@('/ACTION=ERASE');expect='INSTALL_ACTION_INVALID';choices=0},
  @{name='conflicting-arguments';args=@('/PRESENT=1','/VERSION=0.3.715','/UPDATE=1','/ACTION=REINSTALL');expect='INSTALL_ACTION_INVALID';choices=0}
 )
 foreach($case in $cases){
  $log=Join-Path $directory ($case.name+'.log')
  $arguments=@('/SP-','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+$log+'"'),('/EXPECT='+$case.expect),('/CHOICES='+$case.choices))+@($case.args)
  $process=Start-Process -FilePath (Join-Path $directory 'modes.exe') -ArgumentList $arguments -PassThru
  try{if(!$process.WaitForExit(30000)){throw 'MODE_FIXTURE_TIMEOUT'};if($process.ExitCode -eq 0){throw 'MODE_FIXTURE_MUST_NOT_INSTALL'}}finally{$process.Dispose()}
  $text=Get-Content -Raw -LiteralPath $log
  if($text -notmatch 'MODE_POLICY_PASS'){throw ('MODE_POLICY_FAILED '+$case.name+' '+(($text -split "`n" | Where-Object {$_ -match 'MODE_'}) -join ' '))}
  Write-Output ('MODE_POLICY_PASS '+$case.name)
 }
}finally{Remove-Item -LiteralPath $directory -Recurse -Force}
