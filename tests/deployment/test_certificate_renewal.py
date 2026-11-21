import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('leaf_renewal',ROOT/'deploy/vps/renew-server-cert.py')
leaf=importlib.util.module_from_spec(spec);spec.loader.exec_module(leaf)
class LeafRenewalTests(unittest.TestCase):
 def test_fake_clock_threshold_and_ca_expiry_never_extended(self):
  now=dt.datetime(2026,10,20,tzinfo=dt.timezone.utc);ca=now+dt.timedelta(days=365);end=now+dt.timedelta(days=30)
  self.assertFalse(leaf.renewal_due(now,ca,end));self.assertTrue(leaf.renewal_due(now+dt.timedelta(days=21),ca,end))
  self.assertTrue(leaf.renewal_due(now+dt.timedelta(days=31),ca,end))
  with self.assertRaisesRegex(RuntimeError,'CA_RENEWAL_REQUIRED'):leaf.renewal_due(now,now+dt.timedelta(days=20),end)
 def test_leaf_only_atomic_rollback_and_commit_lost_timer_ack(self):
  with tempfile.TemporaryDirectory() as root:
   root=Path(root);conf=root/'config';generated=root/'new';generated.mkdir();calls=[]
   for name in leaf.FILES:
    p=conf/name;p.parent.mkdir(exist_ok=True,parents=True);p.write_bytes(('old-'+name).encode())
   (conf/'control/ca.key').write_bytes(b'private-fixture-CA');(conf/'control/ca.pem').write_bytes(b'fixture-CA');(generated/'server.key').write_bytes(b'new-key');(generated/'server.pem').write_bytes(b'new-cert')
   run=lambda args:calls.append(args) or ''
   r=leaf.Renewal(conf,run);backup=root/'backup'
   def fail():raise RuntimeError('INJECTED_HEALTH_FAILURE')
   with self.assertRaisesRegex(RuntimeError,'INJECTED_HEALTH_FAILURE'):r.apply(backup,generated,fail)
   for name in leaf.FILES:self.assertEqual((conf/name).read_bytes(),('old-'+name).encode())
   self.assertEqual((conf/'control/ca.key').read_bytes(),b'private-fixture-CA')
   self.assertEqual(json.loads((backup/'transaction.json').read_text())['phase'],'rolled-back')
   r.apply(root/'good',generated,lambda:None);r.restore(root/'good',automatic=True)
   self.assertEqual((conf/'control/server.pem').read_bytes(),b'new-cert')
   starts=[c for c in calls if c[:2]==['systemctl','start']];self.assertEqual(starts[-2][2],'neexitlag-control-plane');self.assertEqual(starts[-1][2],'neexitlag-relay')
 def test_boot_recovers_pending_transaction_before_new_renewal(self):
  with tempfile.TemporaryDirectory() as root:
   root=Path(root);conf=root/'config';backups=root/'backups';backups.mkdir()
   for name in leaf.FILES:p=conf/name;p.parent.mkdir(exist_ok=True,parents=True);p.write_bytes(b'old')
   r=leaf.Renewal(conf,lambda args:'');m=r.backup(backups/'one');m['phase']='pending';r.state(backups/'one',m)
   (conf/'control/server.pem').write_bytes(b'interrupted-new')
   r.recover_pending(backups);self.assertEqual((conf/'control/server.pem').read_bytes(),b'old')
 def test_real_openssl_preserves_ca_and_all_sans(self):
  if not shutil.which('openssl'):self.skipTest('openssl required')
  with tempfile.TemporaryDirectory() as root:
   root=Path(root);conf=root/'config';(conf/'control').mkdir(parents=True)
   leaf.command(['openssl','req','-x509','-newkey','ed25519','-nodes','-keyout',str(conf/'control/ca.key'),'-out',str(conf/'control/ca.pem'),'-days','365','-subj','/CN=Isolated Test CA','-addext','basicConstraints=critical,CA:TRUE'])
   before=(conf/'control/ca.pem').read_bytes();r=leaf.Renewal(conf)
   sans=tuple(sorted([('IP Address','2.56.177.4'),('IP Address','127.0.0.1'),('DNS','example.test')]))
   r.generate(root/'generated',sans);self.assertEqual(leaf.certificate(root/'generated/server.pem')[1],sans)
   self.assertEqual((conf/'control/ca.pem').read_bytes(),before)

 def test_interrupted_probe_is_revoked_from_durable_journal_on_rollback(self):
  with tempfile.TemporaryDirectory() as root:
   root=Path(root);conf=root/'config';calls=[]
   for name in leaf.FILES:
    p=conf/name;p.parent.mkdir(exist_ok=True,parents=True);p.write_bytes(b'old')
   r=leaf.Renewal(conf,lambda args:calls.append(args) or '')
   backup=root/'backup';m=r.backup(backup);m['phase']='pending';r.state(backup,m)
   (backup/'probe.id').write_text('fixture-id')
   r.restore(backup,automatic=True)
   self.assertEqual(calls[0][1],'upgrade-cleanup')
   self.assertIn(str(backup/'probe.id'),calls[0])
   self.assertEqual((conf/'control/server.pem').read_bytes(),b'old')

 def test_old_helper_refuses_leaf_journal_before_any_mutation_with_safe_cause(self):
  from unittest import mock
  from types import SimpleNamespace
  import io,contextlib
  output=io.StringIO()
  failure=SimpleNamespace(returncode=1,stdout=b'',stderr=b'FRESH_PC_FAILED: UPGRADE_PROBE_JOURNAL_REQUIRED\nPRIVATE_SENTINEL')
  with mock.patch.object(leaf.diagnostics.subprocess if hasattr(leaf.diagnostics,'subprocess') else __import__('subprocess'),'run',return_value=failure),contextlib.redirect_stderr(output):
   with self.assertRaises(RuntimeError) as raised:leaf.validate_helper('/private/veliq-fresh-helper')
  report=leaf.diagnostics.failure(raised.exception)
  self.assertEqual(report['exit_code'],1)
  self.assertEqual(report['child']['stderr']['codes'],['UPGRADE_PROBE_JOURNAL_REQUIRED'])
  self.assertNotIn('PRIVATE_SENTINEL',json.dumps(report)+output.getvalue())

 def test_empty_exception_and_returncode_never_silently_accepted(self):
  report=leaf.diagnostics.failure(RuntimeError())
  self.assertTrue(report['code']);self.assertEqual(report['code'],'SAFE_OPERATION_FAILED')

 def test_command_stdout_stderr_and_timeout_always_sanitized(self):
  from unittest import mock
  from types import SimpleNamespace
  import contextlib,io,subprocess
  stream=io.StringIO()
  with mock.patch.object(subprocess,'run',return_value=SimpleNamespace(returncode=17,stdout=b'PRIVATE_SENTINEL',stderr=b'Permission denied PRIVATE_SENTINEL')),contextlib.redirect_stderr(stream):
   with self.assertRaises(RuntimeError) as raised:leaf.command(['openssl','fixture'])
  self.assertEqual(raised.exception.exit_code,17)
  self.assertIn('PERMISSION_DENIED',stream.getvalue());self.assertNotIn('PRIVATE_SENTINEL',stream.getvalue())
  with mock.patch.object(subprocess,'run',side_effect=subprocess.TimeoutExpired(['openssl'],1,output=b'PRIVATE_SENTINEL',stderr=b'PRIVATE_SENTINEL')),contextlib.redirect_stderr(stream):
   with self.assertRaisesRegex(RuntimeError,'COMMAND_TIMEOUT'):leaf.command(['openssl','fixture'])
  self.assertNotIn('PRIVATE_SENTINEL',stream.getvalue())
