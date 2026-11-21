"""Product entry points must never control browser process lifetime."""
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
class SilentPolicyTests(unittest.TestCase):
    def test_no_browser_process_control_or_dialog_in_activation(self):
        for name in ('ChromeRouting.cs', 'EdgeRouting.cs', 'BrowserSilentActivation.cs', 'FreshPCSetup.cs'):
            source = (ROOT / 'apps/desktop' / name).read_text(encoding='utf-8-sig')
            for forbidden in ('MessageBox.Show', 'chrome://quit', 'edge://quit', 'CHROME_STILL_RUNNING', 'Process.Start(', '.Kill(', 'WaitForExit', '--restore-last-session'):
                self.assertNotIn(forbidden, source, (name, forbidden))
    def test_boot_restores_local_policy_before_cp_and_has_logon_retry(self):
        source = (ROOT / 'services/client-service/cmd/service/main.go').read_text()
        self.assertLess(source.index('controller.RestoreBrowserTransport()'), source.index('controller.ConnectRemote('))
        source = (ROOT / 'services/client-service/browser_silent.go').read_text()
        self.assertIn('RetrySilentBrowserPolicies', source)
        self.assertIn('c.ctx.Done()', source)
        self.assertNotIn('exec.Command', source)
    def test_pending_is_a_status_not_a_restart_or_fake_proof(self):
        source = (ROOT / 'services/client-service/browser_silent.go').read_text()
        self.assertIn('POLICY_PENDING_BROWSER_REFRESH', source)
        self.assertIn('PAC_REQUEST_OBSERVED', source)
        self.assertNotIn('RestoreConfirmed', source)
        self.assertNotIn('AuthorizeProfile', source)
        source = (ROOT / 'apps/desktop-core/FreshBrowserReadiness.cs').read_text()
        self.assertIn('SilentActivation.ConfiguredProfiles.Contains(id)', source)
    def test_windows_empirical_acceptance_uses_real_policy_not_proxy_flags(self):
        source = (ROOT / 'services/client-service/browser_silent_windows_test.go').read_text()
        self.assertIn('before.CreationTime', source)
        self.assertIn('RefreshPolicy', source)
        self.assertNotIn('"--proxy-server=', source)
        self.assertNotIn('"--proxy-pac-url=', source)
        self.assertIn('wp.LookupTCPPeer', source)
