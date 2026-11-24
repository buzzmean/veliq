; Build dependency only. Runtime uses Windows PowerShell 5.1, no SDK/Git/Go.
#ifndef StageRoot
 #define StageRoot "..\bin\installer"
#endif
#ifndef AppVersion
 #define AppVersion "0.3.0"
#endif
[Setup]
AppId={{E18D91DB-2E64-4405-A05E-AB15A4192318}
AppName=VELIQ
AppVersion={#AppVersion}
AppPublisher=VELIQ
DefaultDirName={autopf}\VELIQ
UsePreviousAppDir=no
SetupIconFile=..\brand\icons\app-icon.ico
UninstallDisplayIcon={app}\VELIQ.exe
AppPublisherURL=https://github.com/buzzmean/neexitlag
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#StageRoot}\output
OutputBaseFilename=VELIQ-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Brand images: dark side panel like app-ui/installer.html; regenerate with installer/make-wizard-images.py.
DisableWelcomePage=no
WizardImageFile=assets\wizard-100.bmp,assets\wizard-125.bmp,assets\wizard-150.bmp,assets\wizard-175.bmp,assets\wizard-200.bmp,assets\wizard-225.bmp,assets\wizard-250.bmp
WizardSmallImageFile=assets\wizard-small-100.bmp,assets\wizard-small-125.bmp,assets\wizard-small-150.bmp,assets\wizard-small-175.bmp,assets\wizard-small-200.bmp,assets\wizard-small-225.bmp,assets\wizard-small-250.bmp
WizardImageStretch=no
RestartIfNeededByRun=no
AlwaysRestart=no
SetupLogging=yes
SetupMutex=Global\VELIQ-Install-Transaction
UninstallRestartComputer=no
; A busy GUI is a preflight failure. Never defer replacement to a later boot.
; Interactive Setup selects and locks "do not restart" itself. Automation and
; uninstall retain /NORESTART because they do not use the wizard's choice.
CloseApplications=no
RestartApplications=no
UninstallDisplayName=VELIQ
[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
[Messages]
WelcomeLabel1=Установка VELIQ
WelcomeLabel2=VELIQ строит оптимальный маршрут для каждого соединения: заблокированное открывается, игры получают самый быстрый путь.%n%nWindows один раз попросит права администратора — для службы, которая строит маршруты.
FinishedHeadingLabel=Готово
FinishedLabelNoIcons=VELIQ установлен. Откройте программу, войдите в аккаунт и нажмите «Оптимизировать».
FinishedLabel=VELIQ установлен. Откройте программу, войдите в аккаунт и нажмите «Оптимизировать».
[InstallDelete]
; Pre-rebrand installs used "VELIQ Setup"; its payload is superseded by {app}.
Type: filesandordirs; Name: "{autopf}\VELIQ Setup"
; The payload is replaced as a whole: files dropped from a newer build must not stay
; behind, or the package coverage check refuses the update.
Type: filesandordirs; Name: "{app}\service"
Type: filesandordirs; Name: "{app}\gui"
Type: filesandordirs; Name: "{app}\tools"
Type: filesandordirs; Name: "{app}\installer"
Type: filesandordirs; Name: "{app}\public"
Type: filesandordirs; Name: "{app}\driver"
[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Ярлыки:"; Check: NotClubImage
[Files]
Source: "{#StageRoot}\payload\installer\transaction.ps1"; Flags: dontcopy
Source: "{#StageRoot}\payload\installer\install-safety.ps1"; Flags: dontcopy
Source: "{#StageRoot}\payload\installer\install-scope.ps1"; Flags: dontcopy
Source: "{#StageRoot}\payload\installer\install-safety.ps1"; DestName: "veliq-install-preflight.ps1"; Flags: dontcopy
Source: "{#StageRoot}\payload\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StageRoot}\payload\gui\VELIQ.exe"; DestDir: "{app}"; Flags: ignoreversion
[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ""& '{app}\installer\install-package.ps1' -DiagnosticFile '{code:DiagnosticFile}' -ClubCodeFile '{code:ClubCodeFile}' {code:ClubImageArgument} {code:UpdateArgument}"""; Flags: runhidden waituntilterminated; StatusMsg: "Устанавливаем VELIQ…"; BeforeInstall: ClearInstallMarker; AfterInstall: CheckInstall
Filename: "{app}\VELIQ.exe"; Description: "{code:LaunchDescription}"; Flags: runasoriginaluser nowait postinstall skipifsilent; Check: ShowAccountSetup
[Icons]
Name: "{autoprograms}\VELIQ"; Filename: "{app}\VELIQ.exe"
Name: "{autodesktop}\VELIQ"; Filename: "{app}\VELIQ.exe"; Tasks: desktopicon; Check: NotClubImage
[Code]
var TransactionPrepared, PackageCompleted: Boolean;
    DiagnosticPath, TransactionPath: String;
    TransactionAttempt: Integer;
    ExistingInstall, ExistingManifest: Boolean;
    InstalledVersion, SelectedOperation: String;
    OperationPage: TInputOptionWizardPage;
    UpdateOption, ReinstallOption: Integer;

#include "setup-mode.iss"

function RunTransaction(Action: String): Integer;
var Code: Integer; Command: String;
begin
 Result := 1;
 Command := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ExpandConstant('{tmp}\transaction.ps1') +
  '" -Action ' + Action + ' -AppDirectory "' + ExpandConstant('{app}') + '" -TransactionDirectory "' +
  TransactionPath + '" -DiagnosticFile "' + DiagnosticPath + '" -ErrorFile "' +
  TransactionPath + '.' + Action + '.error"';
 if Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Command, '', SW_HIDE, ewWaitUntilTerminated, Code) then Result := Code;
 Log('VELIQ transaction ' + Action + ' exit=' + IntToStr(Result));
end;
function SafeSessionArguments(RequireNoRestart: Boolean): Boolean;
var I, Separator: Integer; Arg: String; NoRestart: Boolean;
begin
 NoRestart := False;
 Result := False;
 for I := 1 to ParamCount do begin
   Arg := Uppercase(ParamStr(I));
   if Arg='/NORESTART' then NoRestart := True;
   Separator := Pos('=', Arg);
   if Separator>0 then Arg := Copy(Arg, 1, Separator-1);
   if (Arg='/LOADINF') or (Arg='/CLOSEAPPLICATIONS') or (Arg='/FORCECLOSEAPPLICATIONS') or
      (Arg='/RESTARTAPPLICATIONS') then Exit;
 end;
 Result := NoRestart or not RequireNoRestart;
 if not Result then
   Log('VELIQ_NORESTART_REQUIRED; installation has not started');
end;
function InitializeSetup(): Boolean;
begin
 Result := SafeSessionArguments(WizardSilent);
 if not Result and not WizardSilent then
   MsgBox('Установка остановлена: параметры закрытия или перезапуска приложений запрещены. Запустите установщик обычным двойным щелчком. ПК и приложения не изменены.', mbError, MB_OK);
end;

procedure ReadVeliqInstallation;
var Key, Name, Location, RegisteredVersion: String; Comparison: Integer;
begin
 InstalledVersion := '';
 ExistingManifest := FileExists(ExpandConstant('{commonappdata}\VELIQ\service.json'));
 ExistingInstall := ExistingManifest or FileExists(ExpandConstant('{app}\VELIQ.exe')) or
   FileExists(ExpandConstant('{commonappdata}\VELIQ\veliq-service.exe'));
 GetVersionNumbersString(ExpandConstant('{app}\VELIQ.exe'), InstalledVersion);
 Key := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{E18D91DB-2E64-4405-A05E-AB15A4192318}_is1';
 if RegQueryStringValue(HKLM64, Key, 'DisplayName', Name) and (Name='VELIQ') and
    RegQueryStringValue(HKLM64, Key, 'InstallLocation', Location) and
    (CompareText(RemoveBackslashUnlessRoot(Location), ExpandConstant('{app}'))=0) then begin
   ExistingInstall := True;
   if RegQueryStringValue(HKLM64, Key, 'DisplayVersion', RegisteredVersion) then begin
     if InstalledVersion='' then InstalledVersion := RegisteredVersion
     else if CompareVeliqVersions(RegisteredVersion, InstalledVersion, Comparison) then
       if Comparison>0 then InstalledVersion := RegisteredVersion;
   end;
 end;
end;

function RequestedVeliqOperation(): String;
begin
 Result := Uppercase(ExpandConstant('{param:ACTION|}'));
 if ExpandConstant('{param:UPDATE|0}')='1' then begin
   if (Result<>'') and (Result<>'UPDATE') then Result := 'INVALID' else Result := 'UPDATE';
 end;
end;

procedure InitializeVeliqOperation;
var Description: String;
begin
 ReadVeliqInstallation;
 SelectedOperation := ResolveVeliqOperation(ExistingInstall, InstalledVersion, '{#AppVersion}', RequestedVeliqOperation());
 UpdateOption := -1;
 ReinstallOption := -1;
 if ExistingInstall then begin
   if InstalledVersion='' then Description := 'Найдена существующая установка VELIQ.'
   else Description := 'Установлена версия ' + InstalledVersion + '. Версия установщика: {#AppVersion}.';
   OperationPage := CreateInputOptionPage(wpWelcome, 'VELIQ уже установлен', Description,
     'Выберите действие. Активация, настройки и профили сохранятся.', True, False);
   if SelectedOperation='UPDATE' then
     UpdateOption := OperationPage.Add('Обновить до {#AppVersion}');
   if (SelectedOperation='UPDATE') or (SelectedOperation='REINSTALL') then begin
     ReinstallOption := OperationPage.Add('Переустановить файлы VELIQ {#AppVersion}, сохранив данные');
     OperationPage.SelectedValueIndex := 0;
   end else OperationPage.SubCaptionLabel.Caption := VeliqFailureMessage(SelectedOperation);
 end;
end;

procedure LockNoRestartChoice;
begin
 { Inno 6.4.3 imNormal reads these choices when finishing/preparing. Merely
   returning False from NeedRestart does not override its internal restart flag. }
 WizardForm.NoRadio.Checked := True;
 WizardForm.YesRadio.Enabled := False;
 WizardForm.PreparingNoRadio.Checked := True;
 WizardForm.PreparingYesRadio.Enabled := False;
end;

procedure InitializeWizard;
begin
 DiagnosticPath := ExpandConstant('{commonappdata}\VELIQ-Setup\Logs\') + GetDateTimeString('yyyymmdd-hhnnss', '-', ':') + '.jsonl';
 ForceDirectories(ExtractFileDir(DiagnosticPath));
 Log('VELIQ build {#AppVersion}; diagnostics=' + DiagnosticPath);
 InitializeVeliqOperation;
 LockNoRestartChoice;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
 LockNoRestartChoice;
 if OperationPage<>nil then
   if CurPageID=OperationPage.ID then
     WizardForm.NextButton.Enabled := (UpdateOption>=0) or (ReinstallOption>=0);
 if CurPageID=wpReady then WizardForm.NextButton.Caption := VeliqOperationCaption(SelectedOperation);
 if (CurPageID=wpFinished) and PackageCompleted then begin
   if SelectedOperation='UPDATE' then WizardForm.FinishedLabel.Caption := 'VELIQ обновлён до {#AppVersion}. Активация и настройки сохранены.'
   else if SelectedOperation='REINSTALL' then WizardForm.FinishedLabel.Caption := 'VELIQ {#AppVersion} переустановлен. Активация и настройки сохранены.';
 end;
 if (CurPageID=wpFinished) and not PackageCompleted then begin
   WizardForm.FinishedHeadingLabel.Caption := 'Установка не завершена';
   WizardForm.FinishedLabel.Caption := 'Не удалось подтвердить работу VELIQ. Диагностика: ' + DiagnosticPath;
   WizardForm.RunList.Visible := False;
 end;
 { Never offer the user an enabled restart choice, even if Inno detected a
   late restart requirement. The pending operation itself remains untouched. }
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
 Result := False;
 if OperationPage<>nil then
   if PageID=OperationPage.ID then Result := WizardSilent or (RequestedVeliqOperation()<>'');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
 Result := True;
 if OperationPage<>nil then
   if CurPageID=OperationPage.ID then begin
     if (UpdateOption>=0) and (OperationPage.SelectedValueIndex=UpdateOption) then SelectedOperation := 'UPDATE'
     else if (ReinstallOption>=0) and (OperationPage.SelectedValueIndex=ReinstallOption) then SelectedOperation := 'REINSTALL'
     else Result := False;
   end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
 Result := VeliqOperationCaption(SelectedOperation) + ' VELIQ {#AppVersion}' + NewLine;
 if ExistingInstall then Result := Result + 'Активация, настройки и профили сохранятся.' + NewLine;
 Result := Result + NewLine + MemoDirInfo;
 if MemoTasksInfo<>'' then Result := Result + NewLine + NewLine + MemoTasksInfo;
end;

function LaunchDescription(Param: String): String;
begin
 if ExistingInstall then Result := 'Открыть VELIQ' else Result := 'Открыть VELIQ и подключить аккаунт';
end;

function DiagnosticFile(Param: String): String;
begin
 Result := DiagnosticPath;
end;
function ClubCodeFile(Param: String): String;
begin
 Result := ExpandConstant('{param:CLUBCODEFILE|}');
 if (Pos('''',Result)>0) or (Pos('"',Result)>0) or (Pos(#13,Result)>0) or (Pos(#10,Result)>0) then RaiseException('Недопустимый путь файла активации');
end;
function ClubImageArgument(Param: String): String;
begin
 Result := '';
 if ExpandConstant('{param:CLUBIMAGE|0}')='1' then Result := '-ClubImage';
end;
function UpdateArgument(Param: String): String;
begin
 Result := '';
 if (ExpandConstant('{param:UPDATE|0}')='1') or
    (ExistingManifest and ((SelectedOperation='UPDATE') or (SelectedOperation='REINSTALL'))) then Result := '-Update';
end;

function TransactionErrorCode(Action: String): String;
var Value: AnsiString;
begin
 Result := 'INSTALL_TRANSACTION_FAILED';
 if LoadStringFromFile(TransactionPath + '.' + Action + '.error', Value) then
   if IsVeliqErrorCode(Trim(String(Value))) then Result := Trim(String(Value));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var Code: Integer; FailureCode, Operation: String;
begin
 Result := '';
 if TransactionPrepared then Exit;
 if (SelectedOperation<>'INSTALL') and (SelectedOperation<>'UPDATE') and (SelectedOperation<>'REINSTALL') then begin
   Result := VeliqFailureMessage(SelectedOperation) + #13#10 + 'Код: ' + SelectedOperation;
   Exit;
 end;
 ReadVeliqInstallation;
 Operation := ResolveVeliqOperation(ExistingInstall, InstalledVersion, '{#AppVersion}', SelectedOperation);
 if (Operation<>'INSTALL') and (Operation<>'UPDATE') and (Operation<>'REINSTALL') then begin
   Result := VeliqFailureMessage(Operation) + #13#10 + 'Код: ' + Operation;
   Exit;
 end;
 SelectedOperation := Operation;
 Log('VELIQ_OPERATION=' + SelectedOperation + '; installed=' + InstalledVersion + '; target={#AppVersion}');
 TransactionAttempt := TransactionAttempt + 1;
 TransactionPath := ChangeFileExt(DiagnosticPath, '.' + IntToStr(TransactionAttempt) + '.transaction');
 if Pos('''', ExpandConstant('{app}'))>0 then begin
   Result := 'INSTALL_PREFLIGHT_PATH_INVALID';
   Exit;
 end;
 ExtractTemporaryFile('transaction.ps1');
 ExtractTemporaryFile('install-safety.ps1');
 ExtractTemporaryFile('install-scope.ps1');
 Code := RunTransaction('Prepare');
 if Code<>0 then begin
   FailureCode := TransactionErrorCode('Prepare');
   if Code=20 then FailureCode := 'INSTALL_REBOOT_REQUIRED';
   Log('VELIQ_PREPARE_FAILED code=' + FailureCode);
   Result := VeliqFailureMessage(FailureCode) + #13#10 + 'Файлы не заменены. Код: ' + FailureCode;
 end;
 if Result<>'' then
 begin
   if RunTransaction('Rollback')<>0 then
     Result := Result + #13#10 + 'Восстановление состояния: ' + TransactionErrorCode('Rollback');
   Result := Result + #13#10 + 'Диагностика: ' + DiagnosticPath + #13#10 + 'Журнал Setup: ' + ExpandConstant('{log}');
 end
 else TransactionPrepared := True;
end;
function NotClubImage(): Boolean;
begin
 Result := ExpandConstant('{param:CLUBIMAGE|0}')<>'1';
end;
function ShowAccountSetup(): Boolean;
begin
 Result := PackageCompleted and FileExists(ExpandConstant('{app}\install-success.json')) and
   (NotClubImage() or (ClubCodeFile('')=''));
end;
procedure ClearInstallMarker;
begin
 DeleteFile(ExpandConstant('{app}\install-success.json'));
end;
function InitializeUninstall(): Boolean;
var Code: Integer;
begin
 Result := SafeSessionArguments(True);
 if not Result then begin
   if not UninstallSilent then
     MsgBox('Удаление остановлено: требуется запуск с /NORESTART. ПК не будет перезагружен.', mbError, MB_OK);
   Exit;
 end;
 Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
  '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$ErrorActionPreference=' + #39 + 'Stop' + #39 + '; & ' + #39 + ExpandConstant('{app}\installer\install-safety.ps1') + #39 + ' -Preflight -AppDirectory ' + #39 + ExpandConstant('{app}') + #39 + '; exit $LASTEXITCODE"', '', SW_HIDE, ewWaitUntilTerminated, Code);
 Result := Result and (Code=0);
 if not Result then begin
   Log('VELIQ_UNINSTALL_PREFLIGHT_FAILED; no service/file changes performed');
   Exit;
 end;
 Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
  '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "& ' + #39 + ExpandConstant('{app}\installer\install-package.ps1') + #39 + ' -Remove"', '', SW_HIDE, ewWaitUntilTerminated, Code);
 Result := Result and (Code=0);
 if not Result then begin
   Log('VELIQ_UNINSTALL_FAILED; existing state preserved; check install-result.json');
   if not UninstallSilent then
     MsgBox('VELIQ: удаление остановлено. Данные сохранены; проверьте install-result.json.', mbError, MB_OK);
 end;
end;
procedure CheckInstall;
begin
 if not FileExists(ExpandConstant('{app}\install-success.json')) then
 begin
   if RunTransaction('Rollback')=0 then TransactionPrepared := False;
   Log('VELIQ_INSTALL_FAILED; diagnostics=' + DiagnosticPath);
   if not WizardSilent then MsgBox('Установка VELIQ не завершена. Диагностика: ' + DiagnosticPath + '. Журнал: ' + ExpandConstant('{log}'), mbError, MB_OK);
   Exit;
 end;
 if RunTransaction('Commit')<>0 then begin
   if RunTransaction('Rollback')=0 then TransactionPrepared := False;
   Log('VELIQ_COMMIT_FAILED; diagnostics=' + DiagnosticPath);
   if not WizardSilent then MsgBox('Не удалось подтвердить завершение VELIQ. Диагностика: ' + DiagnosticPath, mbError, MB_OK);
   Exit;
 end;
 PackageCompleted := True;
end;

procedure DeinitializeSetup;
begin
 if TransactionPrepared and not PackageCompleted then begin
   if RunTransaction('Rollback')<>0 then
     Log('VELIQ ROLLBACK_FAILED; backup retained at ' + TransactionPath);
 end;
end;

function GetCustomSetupExitCode(): Integer;
begin
 Result := 0;
 { Exceptions from AfterInstall can be suppressed by /SUPPRESSMSGBOXES while
   Inno otherwise returns success. The durable marker is written only by a
   successful package script and cleared before every invocation. }
 if not PackageCompleted or not FileExists(ExpandConstant('{app}\install-success.json')) then
   Result := 1;
end;
