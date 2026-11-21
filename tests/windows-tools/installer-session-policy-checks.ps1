# Compile the actual Setup policy in an inert Inno fixture on a disposable CI VM.
# No [Files]/[Run]/uninstaller, no installed VELIQ or OS/service mutations.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Compiler,[switch]$AllowLocalInertFixture)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($env:GITHUB_ACTIONS -cne 'true' -and !$AllowLocalInertFixture){throw 'EXPLICIT_INERT_POLICY_CHECK_REQUIRED'}
$source=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '../../installer/setup.iss')
$policy=[regex]::Match($source,'(?s)function SafeSessionArguments\(RequireNoRestart: Boolean\): Boolean;.*?(?=function InitializeSetup\(\))').Value
$choice=[regex]::Match($source,'(?s)procedure LockNoRestartChoice;.*?(?=procedure InitializeWizard;)').Value
if(!$policy -or !$choice){throw 'SETUP_SESSION_POLICY_NOT_FOUND'}
$fixtureRoot=if($env:RUNNER_TEMP){$env:RUNNER_TEMP}else{[IO.Path]::GetTempPath()}
$directory=Join-Path $fixtureRoot ('veliq-session-policy-'+[guid]::NewGuid().ToString('N'))
$null=New-Item $directory -ItemType Directory
$fixture=@'
[Setup]
AppName=VELIQ inert session policy fixture
AppVersion=1
DefaultDirName={tmp}\veliq-inert-policy
CreateAppDir=no
Uninstallable=no
PrivilegesRequired=lowest
AlwaysRestart=no
RestartIfNeededByRun=no
CloseApplications=no
RestartApplications=no
OutputDir=.
OutputBaseFilename=policy
[Code]
{POLICY}
{CHOICE}
function InitializeSetup(): Boolean;
begin
 Result := SafeSessionArguments(WizardSilent);
 if Result then Log('POLICY_ARGUMENTS_ACCEPTED') else Log('POLICY_ARGUMENTS_REFUSED');
end;
procedure InitializeWizard;
begin
 LockNoRestartChoice;
 if not WizardForm.NoRadio.Checked or WizardForm.YesRadio.Enabled or
    not WizardForm.PreparingNoRadio.Checked or WizardForm.PreparingYesRadio.Enabled then
   begin Log('POLICY_CHOICE_FAILED'); Abort; end;
 Log('POLICY_WIZARD_PASS');
 { Stop before the wizard loop: this fixture can never install or request restart. }
 Abort;
end;
'@
$fixture=$fixture.Replace('{POLICY}',$policy).Replace('{CHOICE}',$choice)
[IO.File]::WriteAllText((Join-Path $directory 'policy.iss'),$fixture,[Text.UTF8Encoding]::new($false))
try{
 & $Compiler '/Q' (Join-Path $directory 'policy.iss')
 if($LASTEXITCODE){throw 'SESSION_POLICY_FIXTURE_COMPILE_FAILED'}
 [IO.File]::WriteAllText((Join-Path $directory 'unsafe.inf'),"[Setup]`r`nNoRestart=no`r`n",[Text.UTF8Encoding]::new($false))
 $cases=@(
  @{name='ordinary-double-click';args=@();accepted=$true},
  @{name='explicit-norestart';args=@('/NORESTART');accepted=$true},
  @{name='silent-safe';args=@('/VERYSILENT','/NORESTART');accepted=$true},
  @{name='silent-missing-flag';args=@('/VERYSILENT');accepted=$false},
  @{name='close-apps';args=@('/CLOSEAPPLICATIONS');accepted=$false},
  @{name='force-close';args=@('/norestart','/forcecloseapplications=1');accepted=$false},
  @{name='restart-apps';args=@('/RESTARTAPPLICATIONS');accepted=$false},
  @{name='external-inf';args=@('/NORESTART',('/LOADINF="'+(Join-Path $directory 'unsafe.inf')+'"'));accepted=$false}
 )
 foreach($case in $cases){
  $log=Join-Path $directory ($case.name+'.log')
  # SUPPRESSMSGBOXES does not change WizardSilent: first case is imNormal.
  # Abort ends the inert fixture silently before Application.Run.
  $arguments=@('/SP-','/SUPPRESSMSGBOXES',('/LOG="'+$log+'"'))+@($case.args)
  $process=Start-Process -FilePath (Join-Path $directory 'policy.exe') -ArgumentList $arguments -PassThru
  try{
   if(!$process.WaitForExit(30000)){throw 'INERT_FIXTURE_TIMEOUT'}
   if($process.ExitCode -eq 0){throw 'INERT_FIXTURE_UNEXPECTED_SUCCESS'}
  }finally{$process.Dispose()}
  $text=Get-Content -Raw -LiteralPath $log
  if($case.accepted){
   if($text -notmatch 'POLICY_ARGUMENTS_ACCEPTED' -or $text -notmatch 'POLICY_WIZARD_PASS'){throw ('SESSION_POLICY_ACCEPT_FAILED '+$case.name)}
  }elseif($text -notmatch 'POLICY_ARGUMENTS_REFUSED' -or $text -match 'POLICY_WIZARD_PASS'){
   throw ('SESSION_POLICY_REFUSAL_FAILED '+$case.name)
  }
  Write-Output ('SESSION_POLICY_PASS '+$case.name)
 }
}finally{Remove-Item -LiteralPath $directory -Recurse -Force}
