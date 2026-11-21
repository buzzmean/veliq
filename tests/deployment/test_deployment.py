import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('database_sql', ROOT / 'deploy/vps/database-sql.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DeploymentTests(unittest.TestCase):
    def test_sql_literal_roundtrip_and_injection(self):
        for password in ["plain", "it's quoted", "back\\slash'\\", "'; DROP ROLE postgres; --", " whitespace\r\nline ", 'пароль']:
            with self.subTest(password=password):
                sql = module.generate(password)
                prefix = "SET standard_conforming_strings = on;\nCREATE ROLE neexitlag LOGIN PASSWORD '"
                suffix = "';\nCREATE DATABASE neexitlag OWNER neexitlag;\n"
                self.assertTrue(sql.startswith(prefix) and sql.endswith(suffix))
                self.assertEqual(sql[len(prefix):-len(suffix)].replace("''", "'"), password)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'password'
                    path.write_bytes(password.encode())
                    actual = subprocess.check_output(['python3', str(ROOT / 'deploy/vps/database-sql.py'), str(path)])
                    self.assertEqual(actual.decode(), sql)
        for password in ['', '\0']:
            with self.assertRaises(ValueError):
                module.generate(password)

    def test_windows_autocrlf_checkout_keeps_deployment_lf(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            shutil.copy(ROOT / '.gitattributes', repo)
            shutil.copytree(ROOT / 'deploy/vps', repo / 'deploy/vps', ignore=shutil.ignore_patterns('__pycache__'))
            def git(*args):
                subprocess.run(['git', *args], cwd=repo, check=True, capture_output=True)
            git('init', '-q')
            git('config', 'core.autocrlf', 'true')
            git('add', '.')
            export = repo / 'export'
            export.mkdir()
            git('checkout-index', '--all', '--force', '--prefix=export/')
            for file in (export / 'deploy/vps').iterdir():
                if file.suffix in ['.sh', '.py', '.service']:
                    self.assertNotIn(b'\r', file.read_bytes(), file.name)
            subprocess.run(['bash', '-n', str(export / 'deploy/vps/install.sh')], check=True)


if __name__ == '__main__':
    unittest.main()
