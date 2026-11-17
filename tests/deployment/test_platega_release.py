import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[2]/'deploy/vps/platega-release.py'
class PaymentReleaseTests(unittest.TestCase):
    def load(self):
        spec=importlib.util.spec_from_file_location('platega_release',SCRIPT)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
    def test_unit_argument_escaping(self):
        m=self.load()
        self.assertEqual(m.quote('a%$"b'), '"a%%$$\\"b"')
        with self.assertRaises(RuntimeError):m.quote('a\nb')
    def test_failed_migration_restores_binary_and_config_without_database_restore(self):
        m=self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);backup=root/'backup';backup.mkdir();binary=root/'control-plane';binary.write_bytes(b'old');new=root/'new';new.write_bytes(b'new');plans=root/'new-plans';plans.write_text(json.dumps([dict(id='player-month',price_per_seat_rub=399,period_days=30),dict(id='club-month',price_per_seat_rub=199,period_days=30)]))
            (backup/'before').write_bytes(b'old');(backup/'database.dump').write_bytes(b'private backup fixture')
            installed_plans=root/'plans';dropin=root/'unit.d/plans.conf';args=[str(binary),'-account-origin','https://example.test']
            state=dict(phase='prepared',restore_verified=True,args=args,binary_before=m.digest(binary),dump_sha256=m.digest(backup/'database.dump'),unit_sha256=hashlib.sha256(b'unit').hexdigest(),protected={'state':'unchanged'},files={str(binary):dict(name='before',sha256=m.digest(binary)),str(installed_plans):None,str(dropin):None})
            m.save(backup/'state.json',state)
            calls=[]
            def run(cmd,**kwargs):
                calls.append(cmd)
                return 'unit' if cmd[:2]==['systemctl','cat'] else ''
            with patch.object(m,'BINARY',binary),patch.object(m,'PLANS',installed_plans),patch.object(m,'DROPIN',dropin),patch.object(m,'current',return_value=(args,'fixture','5432')),patch.object(m,'protected',return_value=state['protected']),patch.object(m,'health'),patch.object(m,'run',side_effect=run),patch.object(m,'sql',return_value='6'):
                with self.assertRaisesRegex(RuntimeError,'SCHEMA_7_MISSING'):m.apply(backup,new,plans,m.digest(new))
            self.assertEqual(binary.read_bytes(),b'old');self.assertFalse(installed_plans.exists());self.assertFalse(dropin.exists())
            self.assertEqual(json.loads((backup/'state.json').read_text())['phase'],'rolled-back')
            self.assertFalse(any('pg_restore' in c for c in calls))
            self.assertTrue(any(c[0]=='systemd-run' for c in calls))
    def test_backup_path_is_confined(self):
        m=self.load()
        with self.assertRaises(RuntimeError):m.backup_path('/tmp/20261117T000000Z')

if __name__=='__main__':unittest.main()
