import importlib.util
import json
import os
import io
import contextlib
from pathlib import Path
from types import SimpleNamespace
import unittest
import tempfile
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
def load():
 spec=importlib.util.spec_from_file_location('isolated_environment',ROOT/'tests/deployment/isolated_environment.py')
 m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

class IsolatedEnvironmentTests(unittest.TestCase):
 def test_activation_child_failure_keeps_private_log_and_returns_original_exit(self):
  m=load();secret=b'PRIVATE_FIXTURE_CHILD_OUTPUT'
  with tempfile.TemporaryDirectory() as tmp:
   log=Path(tmp)/'activation.log';real_path=m.Path
   def path(value):
    return log if str(value)=='/var/tmp/neexitlag-upgrade-private/activation.log' else real_path(value)
   def child(args,**kwargs):
    self.assertEqual(args,['python3','tests/deployment/isolated-activation.py'])
    self.assertEqual(kwargs['stderr'],m.subprocess.STDOUT)
    kwargs['stdout'].write(secret+b'\nRuntimeError: UNSUPPORTED_SCHEMA_VERSION\n')
    return SimpleNamespace(returncode=7)
   output=io.StringIO()
   with mock.patch.object(m,'require') as guard,mock.patch.object(m,'Path',side_effect=path),mock.patch.object(m.subprocess,'run',side_effect=child),contextlib.redirect_stderr(output):
    self.assertEqual(m.run_activation(),7)
   guard.assert_called_once()
   self.assertIn(secret,log.read_bytes());self.assertNotIn(secret.decode(),output.getvalue())
   self.assertIn('UNSUPPORTED_SCHEMA_VERSION',output.getvalue())

 def test_activation_failure_exposes_only_safe_codes_exit_and_frame_locations(self):
  m=load();secret='PRIVATE_FIXTURE_SECRET_DO_NOT_EXPORT'
  raw=('password='+secret+'\n-----BEGIN CERTIFICATE-----\n'+secret+'\n'
       '  File "/src/deploy/vps/deploy-activation.py", line 155, in apply\n'
       '    raise RuntimeError("'+secret+'")\n'
       'RuntimeError: UNSUPPORTED_SCHEMA_VERSION\n'
       '  File "/private/'+secret+'.py", line 2, in hidden\n').encode()
  report=m.activation_failure(raw,7)
  self.assertNotIn(secret,json.dumps(report));self.assertNotIn('CERTIFICATE',json.dumps(report))
  self.assertEqual(report['stage'],'ISOLATED_ACTIVATION');self.assertEqual(report['exit_code'],7)
  self.assertEqual(report['log_summary']['codes'],['UNSUPPORTED_SCHEMA_VERSION'])
  self.assertEqual(report['traceback'],[{'file':'deploy-activation.py','line':155}])

 def test_ordinary_host_and_nonroot_are_rejected(self):
  m=load()
  with mock.patch.dict(os.environ,{},clear=True),mock.patch.object(m.os,'geteuid',return_value=1000):
   with self.assertRaisesRegex(RuntimeError,'DISPOSABLE_ROOT_REQUIRED'):m.require()
  with mock.patch.dict(os.environ,{},clear=True),mock.patch.object(m.os,'geteuid',return_value=0):
   with self.assertRaisesRegex(RuntimeError,'DISPOSABLE_ENVIRONMENT_REQUIRED'):m.require()
 def check_local(self,links=None,route=None,pid='systemd',marker='disposable-docker/v1',mode=0o100600,shared=True):
  m=load()
  def read(path,*args,**kw):
   if str(path)=='/proc/1/comm':return pid
   if str(path)=='/proc/self/mountinfo':return '100 1 0:0 / /run rw '+('shared:1 ' if shared else '')+'- tmpfs tmpfs rw'
   return marker
  with mock.patch.dict(os.environ,{'VELIQ_LOCAL_ACCEPTANCE':'disposable-docker'},clear=True),mock.patch.object(m.os,'geteuid',return_value=0),mock.patch.object(Path,'exists',return_value=True),mock.patch.object(Path,'is_file',return_value=True),mock.patch.object(Path,'is_symlink',return_value=False),mock.patch.object(Path,'stat',return_value=SimpleNamespace(st_uid=0,st_mode=mode)),mock.patch.object(Path,'read_text',read),mock.patch.object(m.subprocess,'check_output',side_effect=[json.dumps(links or [{'ifname':'lo'}]).encode(),json.dumps(route or []).encode()]):
   return m.require()
 def test_true_offline_systemd_container_is_accepted(self):self.assertEqual(self.check_local(),'disposable-docker')
 def test_network_interface_or_default_route_is_rejected(self):
  with self.assertRaisesRegex(RuntimeError,'OFFLINE_LOOPBACK_ONLY_REQUIRED'):self.check_local(links=[{'ifname':'eth0'}])
  with self.assertRaisesRegex(RuntimeError,'DEFAULT_ROUTE_FORBIDDEN'):self.check_local(route=[{'dst':'default'}])
 def test_private_run_mount_is_rejected_before_deployment(self):
  with self.assertRaisesRegex(RuntimeError,'RUN_MOUNT_PROPAGATION_REQUIRED'):self.check_local(shared=False)
 def test_fake_init_or_untrusted_marker_is_rejected(self):
  with self.assertRaisesRegex(RuntimeError,'REAL_SYSTEMD_REQUIRED'):self.check_local(pid='bash')
  with self.assertRaisesRegex(RuntimeError,'DISPOSABLE_MARKER_INVALID'):self.check_local(marker='untrusted')
  with self.assertRaisesRegex(RuntimeError,'DISPOSABLE_MARKER_INVALID'):self.check_local(mode=0o100666)

 def test_fixture_health_initializes_metrics_endpoint_before_polling(self):
  m=load();host=SimpleNamespace()
  def wait():
   self.assertEqual(host.relay_health,'http://127.0.0.1:9090/healthz')
   return {'healthy':True}
  host.wait_health=wait
  with mock.patch.object(m,'require',return_value='disposable-docker'):
   self.assertEqual(m.wait_fixture_health(SimpleNamespace(Host=lambda:host)),{'healthy':True})
