"""Local-only P0 RPC/rollback regressions; never connects to a VPS."""
import base64
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'deploy/vps'/(name.replace('_','-')+'.py'))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
r=load('relay_fleet_remote');o=load('relay_fleet_owner')

class Fleet(unittest.TestCase):
    def test_execstart_preserves_credentials_and_only_changes_seed(self):
        text=(ROOT/'deploy/vps/neexitlag-control-plane.service').read_text()
        text+='\n[Service]\nLoadCredential=veliq-device-ca-key:/etc/neexitlag/control/ca.key\nExecStart=\nExecStart='+text.split('ExecStart=')[1].splitlines()[0].replace('/etc/neexitlag/control/ca.key','%d/veliq-device-ca-key')+'\n'
        out=r.parse_exec(text,'146.0.77.98:4433')
        self.assertIn('%d/veliq-device-ca-key',out);self.assertIn('146.0.77.98:4433',out)
        self.assertNotIn('${VPS_PUBLIC_IP}',out)
        self.assertIn('-tls-key /etc/neexitlag/control/server.key',out)
    def test_invalid_exec_refused(self):
        for text in ('ExecStart=/bin/sh -c secret','ExecStart=/opt/neexitlag/bin/control-plane \\\n x'):
            with self.assertRaises(RuntimeError):r.parse_exec(text,'146.0.77.98:4433')
    def test_command_output_secret_never_exposed(self):
        with patch.object(r.subprocess,'run',return_value=subprocess.CompletedProcess(['x'],1,b'PRIVATE KEY',b'secret=never-print')):
            with self.assertRaises(r.StepError) as e:r.command(['python3'])
            self.assertEqual(e.exception.diagnostic,'COMMAND_OUTPUT_REDACTED')
            self.assertNotIn('secret',str(e.exception))
    def test_crlf_bom_is_normalized_before_remote_shell(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'test.sh';p.write_bytes(b'\xef\xbb\xbf#!/bin/bash\r\necho ok\r\n')
            item=o.item(p);b=r.artifact(item)
            self.assertEqual(b,b'#!/bin/bash\necho ok\n')
            item['sha256']='0'*64
            with self.assertRaises(RuntimeError):r.artifact(item)
    def test_atomic_refuses_symlink_and_keeps_private_mode(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'private';r.atomic(p,b'sensitive')
            self.assertEqual(p.stat().st_mode&0o777,0o600)
            link=Path(d)/'link';link.symlink_to(p)
            with self.assertRaises(RuntimeError):r.atomic(link,b'other')
            self.assertEqual(p.read_bytes(),b'sensitive')
    def test_committed_timer_cannot_rollback(self):
        w=r.Worker('control','2.56.177.4');w.job={'phase':'committed'}
        with patch.object(w,'admin',side_effect=AssertionError('must not rollback')):
            self.assertEqual(w.rollback(True)['rollback'],'NOT_REQUIRED')
    def test_inspect_branch_has_no_init_or_registry_mutation(self):
        src=(ROOT/'deploy/vps/relay-fleet-owner.py').read_text()
        branch=src.split('if a.inspect:')[1].split("control.call('init'")[0]
        self.assertIn('inspect_standalone',branch);self.assertNotIn("call('prepare'",branch)
    def test_no_database_restore_enrollment_or_client_key_transfer(self):
        src=(ROOT/'deploy/vps/relay-fleet-remote.py').read_text()
        for banned in ('pg_restore','revoke-tests','device.key','scp '):self.assertNotIn(banned,src)
        self.assertLess(src.index('fcntl.flock(lock,fcntl.LOCK_EX)',src.index("--automatic-rollback':")),src.index("job=json.loads(p.read_text())"))

if __name__=='__main__':unittest.main()
