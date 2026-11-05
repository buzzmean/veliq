import pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
class InstallerContract(unittest.TestCase):
 def test_browser_processes_not_closed(self):
  iss=(ROOT/'installer/setup.iss').read_text(encoding='utf-8-sig')
  self.assertIn('CloseApplications=no',iss);self.assertIn('RestartApplications=no',iss)
  scripts='\n'.join(p.read_text(encoding='utf-8-sig') for p in (ROOT/'installer').glob('*.ps1'))
  for bad in ('Stop-Process','taskkill','chrome://quit','ssh ','scp ','tools/enroll','RotateCA'):self.assertNotIn(bad,scripts)
 def test_hash_ca_and_driver_pins(self):
  contract=(ROOT/'installer/package-contract.ps1').read_text()
  for expected in ('INSTALL_PACKAGE_HASH_MISMATCH','INSTALL_CA_PIN_MISMATCH','INSTALL_DRIVER_VERSION_UNAPPROVED','INSTALL_PACKAGE_REPARSE_POINT'):self.assertIn(expected,contract)
 def test_activation_only_preserves_owner_and_legacy_paths(self):
  script=(ROOT/'installer/install-package.ps1').read_text()
  for expected in ('ActivationOnly=$true','INSTALL_OWNER_MISMATCH','INSTALL_SAME_OWNER_ELEVATION_REQUIRED','update-service.ps1','stage-club-activation.ps1','Assert-VeliqInstalledBinaries'):self.assertIn(expected,script)
  self.assertNotIn('Remove-Item $installed',script)
 def test_no_secret_payload_and_no_reboot(self):
  build=(ROOT/'installer/build.ps1').read_text()
  self.assertIn('PUBLIC_TRUST_DIRECTORY_MUST_CONTAIN_ONLY_CA',build)
  self.assertNotIn('device.pem',build);self.assertNotIn('identity.json',build)
  self.assertIn('RestartIfNeededByRun=no',(ROOT/'installer/setup.iss').read_text(encoding='utf-8-sig'))
 def test_no_deferred_replacement_or_unguarded_setup(self):
  iss=(ROOT/'installer/setup.iss').read_text(encoding='utf-8-sig')
  self.assertNotIn('restartreplace',iss.lower())
  self.assertIn('AlwaysRestart=no',iss)
  self.assertIn("Arg='/NORESTART'",iss)
  self.assertIn('function InitializeSetup()',iss)
  self.assertIn('Assert-VeliqNoPendingReboot',(ROOT/'installer/install-package.ps1').read_text())
  self.assertNotIn('reboot_required=$false',(ROOT/'installer/install-package.ps1').read_text())

class ClubImageContract(unittest.TestCase):
 def test_public_payload_only_and_club_scripts_present(self):
  text=(ROOT/'installer/build.ps1').read_text(encoding='utf-8-sig')
  for script in ('configure-club-image','club-image-boot','club-image-common','club-code-common','Set-ClubActivationCode','Get-ClubStatus'):
   self.assertIn("'"+script+"'",text)
  self.assertNotIn('club-code.txt',text)
 def test_silent_image_install_has_no_gui_launch_or_browser_kill(self):
  text=(ROOT/'installer/setup.iss').read_text(encoding='utf-8-sig')
  self.assertIn('Check: NotClubImage',text)
  seal=(ROOT/'tools/windows/configure-club-image.ps1').read_text(encoding='utf-8-sig')
  self.assertIn('Assert-ClubImageClean',seal)
  self.assertLess(seal.index('Assert-ClubBootTaskOwnership'),seal.index('Register-ScheduledTask'))
  self.assertNotIn('Start-Service',seal)
  self.assertNotIn('Stop-Process',seal)
 def test_club_ui_cannot_mutate_settings(self):
  text=(ROOT/'apps/desktop/ClubWindow.cs').read_text(encoding='utf-8')
  self.assertIn('"club.status"',text)
  for forbidden in ('"optimize"','"settings"','"profile.set"','"activation.set"','MessageBox','Process.Kill','chrome://quit'):
   self.assertNotIn(forbidden,text)
