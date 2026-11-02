import contextlib
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
def load(name):
 s=importlib.util.spec_from_file_location(name,ROOT/'deploy/vps'/name);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class ActivationReleaseTests(unittest.TestCase):
 def test_known_additive_schema_reaches_leaf_preflight_unknown_schema_fails_closed(self):
  for version in (1,2,3,4,5,6):
   with self.subTest(schema=version):
    release=load('deploy-activation.py')
    report={'capabilities':{'relay':{},'control-plane':{}},'applied_schema_version':version,'systemd_version':257}
    engine=SimpleNamespace(e=SimpleNamespace(Host=lambda:None),report=lambda h:report,compatible=lambda *a:True)
    preflight=mock.Mock(side_effect=RuntimeError('LEAF_PREFLIGHT_REACHED'))
    leaf=SimpleNamespace(Renewal=lambda:SimpleNamespace(preflight=preflight))
    with mock.patch.object(release,'guard'),mock.patch.object(release,'module',side_effect=[engine,leaf]),mock.patch.object(Path,'is_file',return_value=True):
     with self.assertRaisesRegex(RuntimeError,'LEAF_PREFLIGHT_REACHED' if version<=5 else 'UNSUPPORTED_SCHEMA_VERSION'):
      release.apply('fixture','a'*40,'ACTIVATE-CODES-2.56.177.4')
    self.assertEqual(preflight.call_count,1 if version<=5 else 0)
    self.assertEqual(release.PROGRESS.modified,'NO')
    self.assertIsNone(release.PROGRESS.backup)

 def test_artifact_hash_and_bounded_transport_never_trusts_manifest_claim(self):
  import base64
  transport=load('activation-release-ssh.py');raw=b'public-test-artifact'
  item={'data':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()}
  self.assertEqual(transport.decode(item),raw)
  item['sha256']='0'*64
  with self.assertRaisesRegex(RuntimeError,'ARTIFACT_HASH_OR_SIZE_MISMATCH'):transport.decode(item)
 def test_binary_force_is_explicit_and_retains_default_noop(self):
  upgrade=load('fresh-vps-upgrade.py');events=[]
  current={'upgrade_needed':False,'local_vps_address':True}
  up=SimpleNamespace(apply=lambda *a:{'id':'fixture'},prove_commit=lambda i:events.append(('prove',i)) or {'pass':True})
  with tempfile.TemporaryDirectory() as tmp:
   bundle=Path(tmp);(bundle/'deploy/vps').mkdir(parents=True)
   with mock.patch.object(upgrade,'report',return_value=current),mock.patch.object(upgrade.e,'Host'),mock.patch.object(upgrade,'LocalUpgrade',return_value=up),mock.patch.object(upgrade,'capabilities',return_value={}),mock.patch.object(upgrade.e,'digest',return_value='public-test-hash'),mock.patch.object(upgrade,'transaction_lock',side_effect=contextlib.nullcontext):
    self.assertEqual(upgrade.prepare(bundle,'helper','abc',''),current)
    with self.assertRaisesRegex(Exception,'EXPLICIT_UPGRADE_CONFIRMATION_REQUIRED'):upgrade.prepare(bundle,'helper','abc','',force_update=True)
    result=upgrade.prepare(bundle,'helper','abc','UPGRADE-VPS-2.56.177.4',force_update=True,before_commit=lambda x:events.append(('saved',x['id'])))
    self.assertTrue(result['pass']);self.assertEqual(events,[('saved','fixture'),('prove','fixture')])
 def test_failure_rollback_preserves_security_writes_and_additive_schema(self):
  release=load('deploy-activation.py');leaf=load('renew-server-cert.py')
  for boot in (False,True):
   with self.subTest(boot=boot),tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp);backup=root/'backup';(backup/'saved').mkdir(parents=True)
    old=root/'old-leaf';old.write_bytes(b'new-leaf');added=root/'activation.conf';added.write_bytes(b'new-unit')
    db=root/'security-state';db.write_bytes(b'current-nonce-current-revocations-new-devices')
    (backup/'saved/0').write_bytes(b'old-leaf')
    state={'phase':'pending','binary_id':'fixture','timer_active':False,'files':{str(old):{'name':'0','mode':0o600,'uid':__import__('os').getuid(),'gid':__import__('os').getgid(),'sha256':hashlib.sha256(b'old-leaf').hexdigest()},str(added):None}}
    release.save(backup/'state.json',state);calls=[]
    fake=SimpleNamespace(e=SimpleNamespace(Host=lambda:None),LocalUpgrade=lambda h:SimpleNamespace(rollback=lambda i,**kw:calls.append(('rollback',i,kw))),transaction_lock=contextlib.nullcontext)
    renewal=leaf.Renewal(root/'config',lambda args:calls.append(args) or '')
    with mock.patch.object(leaf,'transaction_lock',side_effect=contextlib.nullcontext),mock.patch.object(release,'module',side_effect=[fake,leaf]),mock.patch.object(leaf,'command',side_effect=lambda args:calls.append(args) or ''),mock.patch.object(leaf,'BACKUPS',root/'leaf-backups'),mock.patch.object(leaf,'Renewal',return_value=renewal):release.restore(backup,boot=boot)
    self.assertEqual(old.read_bytes(),b'old-leaf');self.assertFalse(added.exists());self.assertEqual(db.read_bytes(),b'current-nonce-current-revocations-new-devices')
    self.assertEqual(json.loads((backup/'state.json').read_text())['phase'],'rolled-back')
    self.assertIn(('rollback','fixture',{'boot':boot}),calls)
    self.assertFalse(any('pg_restore' in str(c) for c in calls))
    if boot:self.assertFalse(any(isinstance(c,list) and c[:2]==['systemctl','start'] for c in calls))
 def test_bad_backup_refuses_restore(self):
  release=load('deploy-activation.py');leaf=load('renew-server-cert.py')
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/'saved').mkdir();dest=root/'leaf';dest.write_bytes(b'new');(root/'saved/0').write_bytes(b'corrupt')
   release.save(root/'state.json',{'phase':'pending','files':{str(dest):{'name':'0','sha256':'0'*64}},'timer_active':False})
   with mock.patch.object(leaf,'transaction_lock',side_effect=contextlib.nullcontext),mock.patch.object(release,'module',side_effect=[SimpleNamespace(),leaf]),mock.patch.object(leaf,'command',return_value=''),mock.patch.object(leaf,'BACKUPS',root/'none'):
    with self.assertRaisesRegex(RuntimeError,'BACKUP_HASH_MISMATCH'):release.restore(root)
   self.assertEqual(dest.read_bytes(),b'new')

class FreshCredentialCompatibilityTests(unittest.TestCase):
 def setUp(self):
  import test_production_upgrade as base
  self.base=base;self.fixture=base.UpgradeTests('test_preflight_full_inventory_no_mutation_or_secret_output')
  self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  self.engine=load('production-upgrade.py');self.h=self.fixture.h
  self.rotate=load('rotate-fresh-pc-ca.py')
  drop=self.h.path(self.engine.FRESH_CA_DROPIN);drop.parent.mkdir(parents=True,exist_ok=True)
  drop.write_bytes(self.rotate.credential_dropin(self.h.unit))
  runtime=self.h.path('/run/credentials/neexitlag-control-plane.service/veliq-device-ca-key');runtime.parent.mkdir(parents=True);runtime.write_bytes(self.h.path(self.engine.CP+'/ca.key').read_bytes())
  original=self.h.systemctl
  self.h.systemctl=lambda *args,**kw: self.engine.FRESH_CA_DROPIN if '--property=DropInPaths' in args and args[-1]=='neexitlag-control-plane' else original(*args,**kw)
  old_run=self.h.run
  def run(args,**kw):
   if args[0]=='runuser' and args[-1]==str(self.h.path(self.engine.CP+'/ca.key')):
    raise AssertionError('root:600 CA must NEVER become readable by service user')
   return old_run(args,**kw)
  self.h.run=run
 def test_root_only_ca_via_exact_loadcredential_passes_without_acl_changes(self):
  with mock.patch.object(self.engine.shutil,'which',return_value='/fixture/tool'):
   state=self.engine.Upgrade(self.h).preflight(self.fixture.bundle,self.base.SHA,self.fixture.inventory)
  self.assertIn('%d/veliq-device-ca-key',state['cp_command'])
  self.assertNotIn('-seed-',state['cp_command'])
  self.assertEqual(self.h.path(self.engine.CP+'/ca.key').stat().st_mode&0o777,0o600)
  self.assertIn(('runuser','-u','neexitlag-control','--','test','-r',str(self.h.path('/run/credentials/neexitlag-control-plane.service/veliq-device-ca-key'))),self.h.events)
  backup=self.h.root/'override-fixture';backup.mkdir()
  upgrade=self.engine.Upgrade(self.h)
  with mock.patch.object(upgrade,'install') as install:
   upgrade.dropin(backup,state['cp_command'],True)
   self.assertEqual(install.call_args.args[1],self.engine.CREDENTIAL_EXEC_DROPIN)
  self.assertGreater(self.engine.CREDENTIAL_EXEC_DROPIN,self.engine.FRESH_CA_DROPIN)
 def test_changed_runtime_key_and_unreviewed_dropins_are_rejected(self):
  self.h.path('/run/credentials/neexitlag-control-plane.service/veliq-device-ca-key').write_bytes(b'wrong-fixture')
  with mock.patch.object(self.engine.shutil,'which',return_value='/fixture/tool'):
   with self.assertRaisesRegex(Exception,'CA_RUNTIME_CREDENTIAL_MISMATCH'):
    self.engine.Upgrade(self.h).preflight(self.fixture.bundle,self.base.SHA,self.fixture.inventory)
  p=self.h.path(self.engine.FRESH_CA_DROPIN);p.write_text(p.read_text()+'Environment=UNREVIEWED=1\n')
  with self.assertRaisesRegex(Exception,'UNREVIEWED_FRESH_CA_DROPIN'):self.engine.reviewed_credentials(self.h)
 def test_arbitrary_percent_specifier_and_direct_ca_layout_not_silently_allowed(self):
  text=self.h.path(self.engine.FRESH_CA_DROPIN).read_text()
  with self.assertRaises(Exception):self.engine.clean_cp_command(text,credential_ca=False)
  with self.assertRaises(Exception):self.engine.clean_cp_command(text.replace('%d/veliq-device-ca-key','%h/unreviewed'),credential_ca=True)

class DeploymentFailureDiagnosticsTests(unittest.TestCase):
 def test_unknown_exception_and_stderr_never_disclose_secrets(self):
  d=load('deploy-activation.py');p=d.Progress();p.step('CANDIDATE_READ_ONLY_PREFLIGHT')
  secret='PRIVATE_CODE_KEY_TOKEN_MUST_NOT_ESCAPE'
  error=RuntimeError(secret);error.command_stderr=b'Permission denied '+secret.encode()+b'\n-----BEGIN PRIVATE KEY-----\n'+secret.encode()
  error.command='runuser';error.exit_code=13
  report=p.failure(error)
  self.assertNotIn(secret,json.dumps(report));self.assertNotIn('PRIVATE KEY',json.dumps(report))
  self.assertEqual(report['stderr'],'PERMISSION_DENIED');self.assertEqual(report['exit_code'],13)
  self.assertEqual(report['vps_modified'],'NO');self.assertIsNone(report['backup'])
  self.assertEqual(report['stage'],'CANDIDATE_READ_ONLY_PREFLIGHT')
 def test_candidate_rejection_precedes_every_backup_unit_service_mutation(self):
  d=load('deploy-activation.py');events=[]
  class FakePath:
   def __init__(self,s):self.s=s
   def __truediv__(self,s):return FakePath(self.s+'/'+s)
   def is_file(self):return True
  engine=SimpleNamespace(e=SimpleNamespace(Host=lambda:None),report=lambda h:{'capabilities':{'relay':{},'control-plane':{}},'systemd_version':257,'applied_schema_version':1},compatible=lambda *a:True)
  def reject(*a,**kw):
   self.assertTrue(kw['validate_only']);events.append('candidate_preflight');raise RuntimeError('ROOT_ONLY_CA_KEY_REQUIRED')
  engine.prepare=reject
  leaf=SimpleNamespace(Renewal=lambda:SimpleNamespace(preflight=lambda *a:events.append('leaf_preflight')))
  with mock.patch.object(d,'guard'),mock.patch.object(d,'Path',FakePath),mock.patch.object(d,'module',side_effect=[engine,leaf]):
   # ROOT is untouched because candidate preflight raises before its first mkdir.
   with self.assertRaisesRegex(RuntimeError,'ROOT_ONLY_CA_KEY_REQUIRED'):d.apply('fixture','a'*40,'ACTIVATE-CODES-2.56.177.4')
  self.assertEqual(events,['leaf_preflight','candidate_preflight']);self.assertEqual(d.PROGRESS.modified,'NO');self.assertIsNone(d.PROGRESS.backup)
 def test_command_exit_and_sanitized_stderr_retained_without_private_log(self):
  d=load('deploy-activation.py');e=load('production-upgrade.py')
  error=None
  try:e.Host().run([__import__('sys').executable,'-c',"import sys;print('Permission denied PRIVATE_FIXTURE',file=sys.stderr);sys.exit(7)"])
  except e.UpgradeError as exc:error=exc
  self.assertIsNotNone(error)
  report=d.Progress().failure(error)
  self.assertEqual(report['exit_code'],7);self.assertEqual(report['stderr'],'PERMISSION_DENIED');self.assertNotIn('PRIVATE_FIXTURE',json.dumps(report))
