"""Local fault injection only: no SSH, real units, credentials or production DB."""
import contextlib
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import test_production_upgrade as original

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('fresh_upgrade',ROOT/'deploy/vps/fresh-vps-upgrade.py')
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
spec=importlib.util.spec_from_file_location('fresh_ssh',ROOT/'deploy/vps/fresh-pc-ssh.py')
ssh=importlib.util.module_from_spec(spec);spec.loader.exec_module(ssh)


class FreshVpsTests(unittest.TestCase):
 def setUp(self):
  self.fixture=original.UpgradeTests('test_preflight_full_inventory_no_mutation_or_secret_output')
  self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  self.h=self.fixture.h;self.events=self.h.events
  self.h.device_count=1;self.h.revoked=[]
  self.helper=self.fixture.bundle/'fresh-pc';self.helper.write_bytes(b'isolated helper')
  self.up=u.LocalUpgrade(self.h,self.helper)
  self.native_run=self.h.run;self.native_sql=self.h.sql
  self.fail_local=False
  def run(args,**kwargs):
   if Path(args[0]).name=='fresh-pc':
    self.events.append(tuple(args))
    if args[1]=='upgrade-local-probe':
     journal=Path(args[-1]);journal.write_text('a'*32+'\n')
     if self.fail_local: raise u.e.UpgradeError('INJECTED_LOCAL_PROOF_FAILURE')
    return 0,b'local fixture'
   if args[:2]==['systemctl','--version']: return 0,b'systemd 252\n'
   if args[:3]==['ip','-j','-4']: return 0,b'[{"addr_info":[{"local":"2.56.177.4"}]}]'
   return self.native_run(args,**kwargs)
  self.h.run=run
  def sql(query,database='neexitlag'):
   if query.startswith('SELECT coalesce(max(version)'): return '1'
   return self.native_sql(query,database)
  self.h.sql=sql

 def test_recovery_lock_is_nonblocking_while_installer_owns_it(self):
  native_open=u.os.open
  with tempfile.TemporaryDirectory() as directory:
   def local_open(path,flags,mode):
    return native_open(str(Path(directory)/Path(path).name),flags,mode)
   with patch.object(u.os,'open',side_effect=local_open):
    with u.transaction_lock():
     with self.assertRaises(BlockingIOError):
      with u.transaction_lock(nonblocking=True): pass
    # The failed contender released all acquired descriptors/locks.
    with u.transaction_lock(nonblocking=True): pass

 def test_recovery_cli_accepts_live_installer_without_running_rollback(self):
  with patch.object(u.os,'geteuid',return_value=0),patch.object(u.e,'env_value',return_value='2.56.177.4'),patch.object(u.e,'Host',return_value=self.h),patch.object(u,'transaction_lock',side_effect=BlockingIOError),patch.object(u,'recover') as recovery,patch('sys.argv',['fresh-vps-upgrade.py','recover']),contextlib.redirect_stdout(io.StringIO()) as output:
   u.main()
  self.assertEqual(json.loads(output.getvalue()),{'phase':'live-transaction-owner'})
  recovery.assert_not_called()

 def test_canonical_capability_field_not_obsolete_alias(self):
  cap=original.capability('relay')
  self.assertTrue(u.compatible(cap,'relay'))
  cap['lease_seconds']=cap.pop('default_lease_seconds')
  self.assertFalse(u.compatible(cap,'relay'))
  def versions(args,**kwargs):
   return types.SimpleNamespace(stdout=json.dumps(original.capability(Path(args[0]).name)).encode())
  with patch.object(ssh.subprocess,'run',side_effect=versions): ssh.require_current_capabilities()

 def test_report_is_read_only_and_skips_compatible_upgrade(self):
  before=u.e.config_fingerprint(self.h)
  with patch.object(u.e,'Host',return_value=self.h),contextlib.redirect_stderr(io.StringIO()):
   result=u.prepare(self.fixture.bundle,self.helper,original.SHA,'')
  self.assertFalse(result['upgrade_needed']);self.assertTrue(result['read_only'])
  self.assertEqual(before,u.e.config_fingerprint(self.h))
  self.assertFalse(any(x[0] in ('start','stop','systemd-run','pg_dump') for x in self.events))
  self.assertFalse(list(self.h.path('/etc').glob('neexitlag.bak-*')))

 def test_full_candidate_validation_is_readonly_even_when_compatible(self):
  before=u.e.config_fingerprint(self.h)
  with patch.object(u.e,'Host',return_value=self.h),contextlib.redirect_stderr(io.StringIO()):
   result=u.prepare(self.fixture.bundle,self.helper,original.SHA,'UPGRADE-VPS-2.56.177.4',force_update=True,validate_only=True)
  self.assertTrue(result['read_only']);self.assertTrue(result['pass'])
  self.assertEqual(before,u.e.config_fingerprint(self.h))
  self.assertFalse(any(x[0] in ('start','stop','systemd-run') or (x[0]=='pg_dump' and '--version' not in x) for x in self.events))
  self.assertFalse(list(self.h.path('/etc').glob('neexitlag.bak-*')))

 def test_readonly_ssh_report_has_no_remote_staging_or_lock(self):
  def code(value):
   b=value.encode();return {'data':base64.b64encode(b).decode(),'sha256':hashlib.sha256(b).hexdigest()}
  payload={'vps_ip':'2.56.177.4','preflight_only':True,'upgrade':False,'rotate':False,'confirm':'',
           'upgrade_engine':code('class Host: pass\n'),
           'upgrade_script':code('def report(h): return {"pass":True,"read_only":True,"upgrade_needed":True}\n')}
  stdin=types.SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))
  output=io.StringIO()
  with (patch.object(ssh.sys,'stdin',stdin),patch.object(ssh.os,'geteuid',return_value=0),patch.object(ssh.os,'uname',return_value=types.SimpleNamespace(nodename='isolated-fixture')),
       patch.object(Path,'read_text',return_value='VPS_PUBLIC_IP=2.56.177.4\n'),patch.object(ssh.os,'open',side_effect=AssertionError('no remote lock')),
       patch.object(ssh.tempfile,'TemporaryDirectory',side_effect=AssertionError('no remote staging')),contextlib.redirect_stdout(output)):
   ssh.main()
  self.assertTrue(json.loads(output.getvalue())['read_only'])

 def test_readonly_incompatible_report_does_not_apply(self):
  with patch.object(u,'report',return_value={'upgrade_needed':True,'read_only':True,'pass':True}),patch.object(u.LocalUpgrade,'apply',side_effect=AssertionError('must not mutate')),contextlib.redirect_stderr(io.StringIO()):
   self.assertTrue(u.prepare(self.fixture.bundle,self.helper,original.SHA,'',True)['upgrade_needed'])

 def test_explicit_confirmation_before_mutation(self):
  report={'upgrade_needed':True}
  with patch.object(u,'report',return_value=report),contextlib.redirect_stderr(io.StringIO()):
   with self.assertRaisesRegex(u.e.UpgradeError,'CONFIRMATION'):
    u.prepare(self.fixture.bundle,self.helper,original.SHA,'wrong')
  self.assertFalse(list(self.h.path('/etc').glob('neexitlag.bak-*')))

 def test_unfinished_original_transaction_refused_before_new_backup(self):
  ident='20261020T100000Z-aabbccddeeff'
  pending=self.h.path('/var/lib/neexitlag-upgrade/pending.json');pending.parent.mkdir(parents=True,exist_ok=True)
  pending.write_text(json.dumps({'id':ident}))
  prior=self.h.path(u.e.BACKUPS+'/'+ident+'/state.json');prior.parent.mkdir(parents=True);prior.write_text('{"phase":"pending-verification"}')
  with self.assertRaisesRegex(u.e.UpgradeError,'PRIOR_PRODUCTION_UPGRADE_PENDING'):self.apply()
  self.assertFalse(list(self.h.path('/etc').glob('neexitlag.bak-*')))

 def test_no_local_public_ip_refused_before_backup(self):
  with patch.object(u,'report',return_value={'upgrade_needed':True,'local_vps_address':False}),contextlib.redirect_stderr(io.StringIO()):
   with self.assertRaisesRegex(u.e.UpgradeError,'VPS_PUBLIC_IP_NOT_LOCAL'):
    u.prepare(self.fixture.bundle,self.helper,original.SHA,'UPGRADE-VPS-2.56.177.4')
  self.assertFalse(list(self.h.path('/etc').glob('neexitlag.bak-*')))

 def apply(self):
  with contextlib.redirect_stderr(io.StringIO()):
   return self.up.apply(self.fixture.bundle,original.SHA,self.fixture.inventory)

 def test_apply_local_proof_commit_backup_migrate_order(self):
  before=u.e.config_fingerprint(self.h)
  etc_mode=self.h.path('/etc').stat().st_mode&0o777
  state=self.apply();b,s=self.up.load(state['id'])
  self.assertTrue(b.name.startswith('neexitlag.bak-'))
  self.assertEqual(b.parent.stat().st_mode&0o777,self.h.path('/etc').stat().st_mode&0o777)
  for name in ['config-units.tar','database.dump','globals.sql','binaries.tar','old-relay','old-control-plane','production-engine.py','fresh-pc']:
   self.assertTrue((b/name).exists(),name)
  self.assertTrue(any(x[0]=='systemd-run' for x in self.events))
  self.assertLess(self.events.index(('pg_dump',)),next(i for i,x in enumerate(self.events) if len(x)>1 and x[1]=='upgrade-migrate'))
  result=self.up.prove_commit(state['id']);self.assertEqual(result['phase'],'committed')
  self.assertTrue(any(len(x)>1 and x[1]=='upgrade-cleanup' for x in self.events))
  self.assertEqual(before,u.e.config_fingerprint(self.h))
  guard=self.h.path(u.e.GUARD.format(service='neexitlag-relay')).read_text()
  self.assertIn('neexitlag-fresh-upgrade-recover.service',guard)
  self.assertEqual(self.h.path('/etc').stat().st_mode&0o777,etc_mode)

 def test_local_proof_failure_rolls_back_and_revokes_journal(self):
  state=self.apply();self.fail_local=True
  with self.assertRaises(u.e.UpgradeError): self.up.prove_commit(state['id'])
  b,s=self.up.load(state['id']);self.assertEqual(s['phase'],'rolled_back')
  self.assertTrue(any(len(x)>1 and x[1]=='upgrade-cleanup' for x in self.events))
  for role in ('relay','control-plane'):
   self.assertEqual(u.e.digest(self.h.path(u.e.BIN+'/'+role)),s['old_binary_hashes'][role])
  self.assertFalse(any(x[0]=='pg_restore' and '--list' not in x for x in self.events))

 def test_migration_failure_never_installs_candidates(self):
  run=self.h.run
  def failed(args,**kwargs):
   if len(args)>1 and args[1]=='upgrade-migrate':raise u.e.UpgradeError('MIGRATION_FAILED')
   return run(args,**kwargs)
  self.h.run=failed
  with self.assertRaises(u.e.UpgradeError):self.apply()
  backups=list(self.h.path('/etc').glob('neexitlag.bak-*'));self.assertEqual(len(backups),1)
  self.assertEqual(json.loads((backups[0]/'state.json').read_text())['phase'],'rolled_back')

 def test_artifact_hash_failure(self):
  with self.assertRaisesRegex(RuntimeError,'HASH'):
   ssh.artifact({'data':'YWJj','sha256':'0'*64})

 def test_recovery_survives_local_proof_process_death(self):
  state=self.apply();b,s=self.up.load(state['id']);(b/'probe.id').write_text('b'*32)
  self.up.rollback(state['id'],automatic=True,boot=True)
  self.assertTrue(any(len(x)>1 and x[1]=='upgrade-cleanup' for x in self.events))
  self.assertEqual(self.up.load(state['id'])[1]['phase'],'rolled_back')

if __name__=='__main__':unittest.main()
