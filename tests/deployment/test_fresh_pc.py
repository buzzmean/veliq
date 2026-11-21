"""Isolated rotation failures: no SSH, service, production files or CA access."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('fresh_rotation', ROOT / 'deploy/vps/rotate-fresh-pc-ca.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class FreshRotationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.config = self.base / 'config'
        self.new = self.base / 'new'
        self.new.mkdir()
        for name in r.FILES:
            p = self.config / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(('old-' + name).encode())
            p.chmod(0o640)
            (self.new / p.name).write_bytes(('new-' + p.name).encode())
        self.dropin = self.base / 'units' / 'fresh.conf'
        self.calls = []
        self.fail_start = False
        self.writes = []
        def run(args):
            self.calls.append(args)
            if self.fail_start and args[:2] == ['systemctl', 'start']:
                self.fail_start = False
                raise RuntimeError('isolated startup failure')
            return '[Service]\nExecStart=/reviewed/binary\n'
        def atomic(path, data, mode, uid, gid):
            self.writes.append((str(path), mode, uid, gid))
            Path(path).write_bytes(data)
            Path(path).chmod(mode)
        self.addCleanup(patch.stopall)
        patch.object(r, 'atomic', atomic).start()
        self.rotation = r.Rotation(self.config, self.dropin, run)

    def test_failure_restores_every_original_without_deleting_config(self):
        self.fail_start = True
        backup = self.base / 'backup'
        with self.assertRaises(RuntimeError):
            self.rotation.apply(backup, self.new, b'credential dropin')
        for name in r.FILES:
            self.assertEqual((self.config / name).read_bytes(), ('old-' + name).encode())
        self.assertFalse(self.dropin.exists())
        self.assertEqual(json.loads((backup / 'transaction.json').read_text())['phase'], 'rolled-back')
        self.assertEqual((backup / 'config/control/ca.key').stat().st_mode & 0o777, 0o600)
        self.assertTrue((backup / 'units/neexitlag-relay.txt').exists())
        self.assertTrue(any(x[0].endswith('control/ca.key') and x[1:]==(0o600,0,0) for x in self.writes))

    def test_health_failure_after_successful_start_rolls_back(self):
        backup=self.base/'backup'
        m,unit=self.rotation.apply(backup,self.new,b'credential dropin')
        def failed_health():raise RuntimeError('isolated health failure')
        with self.assertRaises(RuntimeError):
            self.rotation.verify_commit(backup,m,unit,failed_health)
        for name in r.FILES:
            self.assertEqual((self.config/name).read_bytes(),('old-'+name).encode())
        self.assertEqual(json.loads((backup/'transaction.json').read_text())['phase'],'rolled-back')

    def test_backup_tampering_refused_before_any_service_change(self):
        backup=self.base/'backup'
        self.rotation.backup(backup)
        (backup/'config/control/server.pem').write_bytes(b'corrupt')
        before=len(self.calls)
        with self.assertRaisesRegex(RuntimeError,'BACKUP_HASH_MISMATCH'):
            self.rotation.restore(backup)
        self.assertEqual(len(self.calls),before)

    def test_committed_transaction_not_undone_by_late_watchdog(self):
        backup=self.base/'backup'
        m,unit=self.rotation.apply(backup,self.new,b'credential dropin')
        m['phase']='committed';self.rotation.state(backup,m)
        count=len(self.calls)
        self.rotation.restore(backup,automatic=True)
        self.assertEqual(len(self.calls),count)
        self.assertIn('--on-active=180',self.calls[2])

    def test_unit_parser_keeps_existing_publication_flags(self):
        unit=(ROOT/'deploy/vps/neexitlag-control-plane.service').read_text()
        unit=unit.replace('-seed-relay-id VPS-01','-publish-config-on-start -seed-relay-id VPS-01')
        dropin=r.credential_dropin(unit).decode()
        self.assertIn('-publish-config-on-start',dropin)
        self.assertIn('%d/veliq-device-ca-key',dropin)
        self.assertIn('LoadCredential=',dropin)
        with self.assertRaises(RuntimeError):
            r.credential_dropin('[Service]\nExecStart=/unknown\n')

    def test_readonly_version_preflight_rejects_old_config_consumers(self):
        def versions(args):
            role=Path(args[0]).name
            return json.dumps(dict(role=role,max_config_bytes=1048576,full_revocations=True,
                                   protocols=['neexitlag/3'],default_lease_seconds=1800))
        r.check_capabilities(versions)
        def old(args):
            value=json.loads(versions(args));value['max_config_bytes']=65536
            return json.dumps(value)
        with self.assertRaisesRegex(RuntimeError,'1MIB'):
            r.check_capabilities(old)

    def test_explicit_confirmation_hashes_and_no_provision_are_in_real_entry(self):
        text=(ROOT/'deploy/vps/rotate-fresh-pc-ca.py').read_text()
        self.assertIn('EXPLICIT_CA_ROTATION_CONFIRMATION_REQUIRED',text)
        self.assertIn('CURRENT_CA_PIN_MISMATCH',text)
        self.assertIn('HELPER_HASH_MISMATCH',text)
        self.assertIn('veliq-swe-01',text)
        self.assertNotIn('apt-get',text)
        ps=(ROOT/'tools/windows/bootstrap-fresh-pc.ps1').read_text()
        self.assertNotIn('setup-e2e.ps1',ps)
        self.assertNotIn('update-vps.ps1',ps)
        self.assertNotIn('vps-provision.exe',ps)
        self.assertNotIn('StrictHostKeyChecking=no',ps)

if __name__=='__main__':unittest.main()
