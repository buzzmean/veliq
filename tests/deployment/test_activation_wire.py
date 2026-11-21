"""Execute shipped SSH launcher and embedded Python bytes, never SSH/network."""
import base64
import contextlib
import importlib.util
import io
import json
import re
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
VPS=ROOT/'deploy/vps'
def load(name):
    spec=importlib.util.spec_from_file_location(name,VPS/name)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def encoded(name, crlf=False, bom=False):
    data=(VPS/name).read_bytes().replace(b'\r\n',b'\n')
    if crlf:data=data.replace(b'\n',b'\r\n')
    return base64.b64encode((b'\xef\xbb\xbf' if bom else b'')+data).decode()

class ActivationWireTests(unittest.TestCase):
    def test_shipped_default_baseline_is_real_full_commit_and_matches_powershell(self):
        audit=load('inspect-activation.py')
        script=(ROOT/'tools/windows/verify-activation-vps.ps1').read_text()
        default=re.search(r"\$BaselineCommit='([a-f0-9]+)'",script).group(1)
        self.assertEqual(default,'2c06089f61c7b7a27cdf575f5cea4b834992426d')
        self.assertEqual(audit.BASELINE,default)
        self.assertRegex(default,r'^[a-f0-9]{40}$')

    def test_actual_engine_and_fresh_sources_compile_in_memory_all_windows_encodings(self):
        for crlf,bom in ((False,False),(True,False),(True,True)):
            audit=load('inspect-activation.py')
            payload={'engine':encoded('production-upgrade.py',crlf,bom),'fresh':encoded('fresh-vps-upgrade.py',crlf,bom)}
            def inspect(fresh,engine,expected):
                self.assertIs(fresh.e,engine)
                self.assertEqual(expected,audit.BASELINE)
                return {'pass':True}
            with mock.patch.object(audit.os,'geteuid',return_value=0),mock.patch.object(audit.os,'uname',return_value=types.SimpleNamespace(nodename='fixture')),mock.patch.object(audit.diagnostics,'require_vps_identity'),mock.patch.object(audit,'inspect',side_effect=inspect):
                self.assertEqual(audit.run(payload),{'pass':True})
                payload['baseline']='2c06089f61c7b7a2cf575f5cea4b834992426d'
                with self.assertRaisesRegex(RuntimeError,'INVALID_BASELINE_COMMIT'):
                    audit.run(payload)

    def test_bom_crlf_quoted_identity_allowed_but_duplicates_wrong_host_rejected(self):
        diag=load('activation-diagnostics.py');engine=load('production-upgrade.py')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'relay.env'
            for value in (b'VPS_PUBLIC_IP=2.56.177.4\r\n',b'\xef\xbb\xbfVPS_PUBLIC_IP="2.56.177.4"\r\n'):
                path.write_bytes(value);diag.require_vps_identity(path)
                self.assertEqual(engine.env_value(path,'VPS_PUBLIC_IP'),'2.56.177.4')
            for value in ('VPS_PUBLIC_IP=2.56.177.4\nVPS_PUBLIC_IP=2.56.177.4\n','VPS_PUBLIC_IP=127.0.0.1\n','OTHER=2.56.177.4\n'):
                path.write_text(value)
                with self.assertRaisesRegex(RuntimeError,'VPS_IDENTITY_MISMATCH'):diag.require_vps_identity(path)

    def test_real_readonly_command_error_keeps_exit_step_and_safe_stderr(self):
        audit=load('inspect-activation.py');engine=load('production-upgrade.py')
        def report(h):
            h.database='fixture';h.db_port=5432
            return h.sql('SHOW server_version_num','fixture')
        process=types.SimpleNamespace(returncode=7,stdout=b'',stderr=b'psql: connection refused; password=PRIVATE_SENTINEL; key=PRIVATE_SENTINEL')
        with mock.patch.object(audit.subprocess,'run',return_value=process):
            try:audit.inspect(types.SimpleNamespace(report=report),engine)
            except RuntimeError as exc: result=audit.diagnostics.failure(exc)
            else:self.fail('nonzero psql accepted')
        self.assertEqual(result['code'],'READ_ONLY_COMMAND_FAILED')
        self.assertEqual(result['exit_code'],7)
        self.assertEqual(result['command'],'psql')
        self.assertEqual(result['step'],'READ_ONLY_COMMAND_PSQL')
        self.assertEqual(result['stderr'],'CONNECTION_REFUSED')
        self.assertTrue(result['traceback']);self.assertNotIn('PRIVATE_SENTINEL',json.dumps(result))

    def test_exact_readonly_launcher_reports_every_runtimeerror_without_secret_text(self):
        script=(ROOT/'tools/windows/verify-activation-vps.ps1').read_text()
        launcher=script.split("$remote=@'\n",1)[1].split("\n'@",1)[0]
        diag=load('activation-diagnostics.py')
        # The in-memory module is normally preloaded by Get-ActivationRemoteCode.
        for reason in ('VPS_IDENTITY_MISMATCH','SECRET_ACTIVATION_CODE_PRIVATE_SENTINEL'):
            audit_source="def run(p):\n raise RuntimeError(%r)\n"%reason
            payload=json.dumps({'audit':base64.b64encode(audit_source.encode()).decode()}).encode()
            err=io.StringIO()
            with mock.patch.dict(sys.modules,{'activation_diagnostics':diag}),mock.patch.object(sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(b'\xef\xbb\xbf'+payload+b'\r\n'))),contextlib.redirect_stderr(err):
                with self.assertRaises(SystemExit):exec(compile(b'\xef\xbb\xbf'+launcher.replace('\n','\r\n').encode(),'<string>','exec'),{})
            report=json.loads(err.getvalue().split('ACTIVATION_READ_ONLY_FAILED ',1)[1])
            self.assertEqual(report['code'],reason if reason=='VPS_IDENTITY_MISMATCH' else 'SAFE_OPERATION_FAILED')
            self.assertEqual(report['vps_modified'],'NO_PRODUCTION_MUTATION_REQUESTED')
            self.assertTrue(report['traceback']);self.assertNotIn('PRIVATE_SENTINEL',err.getvalue())

    def test_updater_and_audit_use_same_identity_guard_and_safe_traceback(self):
        for name in ('deploy-activation.py','activation-release-ssh.py','inspect-activation.py'):
            text=(VPS/name).read_text()
            self.assertIn('diagnostics.require_vps_identity(',text)
        release=load('deploy-activation.py')
        try:raise RuntimeError('PRIVATE_SENTINEL')
        except RuntimeError as exc:report=release.Progress().failure(exc)
        self.assertIn('traceback',report['diagnostics'])
        self.assertNotIn('PRIVATE_SENTINEL',json.dumps(report))
        # Recovery is independent of /var/tmp staging lifetime, including diagnostics.
        self.assertIn("'inspect-activation.py','activation-diagnostics.py','deploy-activation.py'",(VPS/'deploy-activation.py').read_text())
        self.assertIn('activation-diagnostics.py',load('activation-release-ssh.py').NAMES)
