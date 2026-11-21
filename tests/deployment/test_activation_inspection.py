import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
def load(name):
 s=importlib.util.spec_from_file_location(name,ROOT/'deploy/vps'/name);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class ReadOnlyInspectionTests(unittest.TestCase):
 def test_baseline_is_not_misrepresented_as_proof_of_historical_no_changes(self):
  m=load('inspect-activation.py')
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);calls=[]
   key=root/'etc/neexitlag/control/ca.key';key.parent.mkdir(parents=True);key.write_bytes(b'PRIVATE_FIXTURE_NEVER_PRINT');key.chmod(0o600)
   backup=root/'var/backups/neexitlag-activation/20261020T140000Z-aabbccdd';backup.mkdir(parents=True)
   (backup/'state.json').write_text(json.dumps({'phase':'rolled-back','files':{},'binary_id':''}))
   report={'services':{'neexitlag-control-plane':{'pid':150293},'neexitlag-relay':{'pid':150299}},'binary_sha256':{'relay':'public-binary','control-plane':'public-binary'},'capabilities':{'relay':{'commit':m.BASELINE},'control-plane':{'commit':m.BASELINE}},'applied_schema_version':1,'ports':{},'ca_migration_required':False}
   class Host:
    database='fixture'
    def path(self,s):return root/s.lstrip('/')
    def running_binary_hash(self,pid):return 'public-binary'
    def systemctl(self,*args,**kw):calls.append(args);return 'active'
    def run(self,args,**kw):calls.append(args);return (1,b'') if args[0]=='runuser' else (0,b'')
    def sql(self,q,d):
     calls.append(q)
     return '[]' if 'json_agg' in q else '0' if 'information_schema' in q else '1'
   with mock.patch.object(m,'certificate_status',return_value={'renewal_due':False}):
    out=m.inspect(SimpleNamespace(report=lambda h:report),SimpleNamespace(Host=object),root=root,host=Host())
   text=json.dumps(out)
   self.assertNotIn('PRIVATE_FIXTURE',text);self.assertFalse(out['historical_no_changes_proven'])
   self.assertTrue(out['binaries_and_schema_at_baseline']);self.assertTrue(out['database']['activation_migration_not_applied'])
   self.assertEqual(out['verdict'],'BASELINE_WITH_DEPLOYMENT_ARTIFACTS')
   self.assertFalse(out['ca_access']['direct_service_readable'])
   for call in calls:
    if isinstance(call,tuple):self.assertNotIn(call[0],('start','stop','restart','enable','disable','systemd-run'))
    elif isinstance(call,list):self.assertNotIn(call[0],('pg_dump','pg_restore'))
    else:self.assertTrue(call.startswith('SELECT '))
 def test_queries_are_server_enforced_read_only_and_use_no_tempfiles(self):
  m=load('inspect-activation.py');engine=load('production-upgrade.py');seen=[]
  def report(h):
   h.database='fixture';h.db_port=5432
   value=h.sql('SHOW server_version_num','fixture');self.assertEqual(value,'170006')
   raise RuntimeError('STOP_FIXTURE_BEFORE_OTHER_INSPECTION')
  def process(args,**kw):
   seen.append(args);return SimpleNamespace(returncode=0,stdout=b'170006\n',stderr=b'')
  with mock.patch.object(m.subprocess,'run',side_effect=process),mock.patch.object(engine.tempfile,'TemporaryFile',side_effect=AssertionError('no remote files')):
   with self.assertRaisesRegex(RuntimeError,'STOP_FIXTURE'):m.inspect(SimpleNamespace(report=report),engine)
  self.assertTrue(seen[0][-1].startswith('BEGIN READ ONLY; '));self.assertTrue(seen[0][-1].endswith('; COMMIT;'))
 def test_partial_schema2_is_an_explicit_safe_retry_not_clean_baseline(self):
  m=load('inspect-activation.py')
  db={'schema_version':2,'activation_tables':3}
  self.assertEqual(m.state_verdict([],db,[],False),'COMPATIBLE_ADDITIVE_SCHEMA2_SECURITY_STATE_PRESERVED')
  self.assertEqual(m.state_verdict([],db,[{'phase':'pending'}],False),'PENDING_RECOVERY_REQUIRES_REVIEW')
  self.assertEqual(m.state_verdict([],{'schema_version':3,'activation_tables':3},[],False),'COMPATIBLE_ADDITIVE_SCHEMA3_SECURITY_STATE_PRESERVED')
  self.assertEqual(m.state_verdict([],{'schema_version':4,'activation_tables':3},[],False),'BASELINE_DIFFERENT_REQUIRES_REVIEW')
 def test_expiry_report_uses_real_current_time_and_renewal_window(self):
  import datetime as dt
  m=load('inspect-activation.py')
  now=dt.datetime(2026,11,10,tzinfo=dt.timezone.utc)
  def cert(path):return {'notAfter':'Nov 19 13:05:54 2026 GMT' if path.endswith('server.pem') else 'Oct 20 13:05:54 2027 GMT'}
  with mock.patch.object(m.ssl._ssl,'_test_decode_cert',side_effect=cert),mock.patch.object(Path,'read_bytes',return_value=b'fixture'):
   result=m.certificate_status('/',now)
  self.assertTrue(result['renewal_due']);self.assertFalse(result['ca_rotation_required']);self.assertTrue(result['leaf_matches_relay'])
