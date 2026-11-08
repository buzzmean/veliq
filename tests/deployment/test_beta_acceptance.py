import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('beta', Path(__file__).resolve().parents[2] / 'tools/beta_acceptance.py')
beta = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(beta)


class BetaAcceptanceTests(unittest.TestCase):
    def test_incomplete_template_is_blocked(self):
        self.assertTrue(beta.validate({}, Path('.'), 'a'*40, 'b'*64, 'c'*64))

    def test_exact_build_evidence_and_negative_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'proof.txt').write_bytes(b'owner reviewed controlled evidence')
            row = dict(status='PASS', evidence='proof.txt', sha256=hashlib.sha256((root/'proof.txt').read_bytes()).hexdigest())
            report = dict(source_commit='a'*40, service_sha256='b'*64, gui_sha256='c'*64,
                          pilot_size=6, owner_reviewed=True)
            report['global'] = {key: copy.deepcopy(row) for key in beta.GLOBAL}
            report['pcs'] = [dict(id=name, source_commit='a'*40, service_sha256='b'*64,
                                 gui_sha256='c'*64, checks={key: copy.deepcopy(row) for key in beta.PER_PC})
                             for name in ('PC01', 'PC02')]
            check = lambda r: beta.validate(r, root, 'a'*40, 'b'*64, 'c'*64)
            self.assertEqual(check(report), [])
            for mutate in (lambda r: r['global']['origin_isolation'].update(status='FAIL'),
                           lambda r: r['global']['go_windows'].update(status='PENDING'),
                           lambda r: r['pcs'][1].update(id='PC01'),
                           lambda r: r['pcs'][0].update(service_sha256='d'*64),
                           lambda r: r['global']['filters'].update(evidence='../outside'),
                           lambda r: r['global']['filters'].update(sha256='0'*64),
                           lambda r: r.update(owner_reviewed=False),
                           lambda r: r['pcs'][0]['checks'].pop('rollback')):
                bad = copy.deepcopy(report)
                mutate(bad)
                self.assertTrue(check(bad))
            (root/'proof.txt').write_bytes(b'tampered')
            self.assertTrue(check(report))
