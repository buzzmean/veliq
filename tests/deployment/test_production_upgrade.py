"""Isolated transaction/fault tests: never connect to a remote host or use systemd."""
import base64
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('production_upgrade', ROOT / 'deploy/vps/production-upgrade.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SHA = 'a' * 40


def capability(role, full=True):
    data = {'role': role, 'commit': SHA, 'modified': False, 'max_config_bytes': m.MAX_CONFIG if full else m.LEGACY_CONFIG, 'full_revocations': full, 'migration': '001-additive'}
    if role == 'relay':
        data.update(protocols=['neexitlag/2', 'neexitlag/3'], default_lease_seconds=1800)
    return data


def proof():
    now = dt.datetime.now(dt.timezone.utc)
    p = {k: True for k in ['pass', 'same_connection', 'ticket_replay_rejected', 'wrong_ticket_rejected', 'anonymous_mtls_rejected', 'legacy_2', 'receipt_retry', 'renewal_replay_rejected']}
    p.update(alpn='neexitlag/3', renewals=2, default_lease_seconds=1800, tcp_source='2.56.177.4', udp_source='2.56.177.4', udp_flow_id=2, tcp_stream_id=4, deadlines=[(now + dt.timedelta(minutes=30, milliseconds=n)).isoformat() for n in range(3)])
    return p


class FakeHost(m.Host):
    def __init__(self, root):
        super().__init__(root)
        self.events = []
        self.fail = None
        self.health_failures = 0
        self.device_count = 5000
        self.revoked = [f'device-{n:04}' for n in range(1500)]
        self.bad_publication = False
        self.missing_echo_tcp = False
        self.metric_values = {'neexitlag_relay_health': 1, 'neexitlag_lease_renewals_total': 0, 'neexitlag_tcp_connections_total': 0, 'neexitlag_udp_packets_total': 0}
        self.caps = {r: capability(r) for r in ['relay', 'control-plane']}
        self.database, self.db_port, self.relay_health = 'neexitlag', 5432, 'http://127.0.0.1:9090/healthz'
        self.unit = (ROOT / 'deploy/vps/neexitlag-control-plane.service').read_text()
        self.active = {s: True for s in m.SERVICES}

    def configuration_owner(self, entry):
        return True  # Fixtures are owned by the unprivileged CI user, not root.

    def running_binary_hash(self, pid):
        return m.digest(self.path(m.BIN + ('/relay' if pid == '10' else '/control-plane')))

    def systemctl(self, *args, check=True):
        self.events.append(tuple(args))
        if self.fail == tuple(args):
            self.fail = None
            raise m.UpgradeError('Injected systemd failure')
        if args[0] == 'show':
            service = args[-1]
            if '--property=User' in args:
                return 'neexitlag-relay' if service == 'neexitlag-relay' else 'neexitlag-control'
            if '--property=FragmentPath' in args:
                return '/etc/systemd/system/' + service + '.service'
            if '--property=DropInPaths' in args:
                return ''
            return '10' if service == 'neexitlag-relay' else '11'
        if args[0] in ('start', 'stop') and args[1] in m.SERVICES:
            self.active[args[1]] = args[0] == 'start'
        return ''

    def run(self, args, check=True, output=None, timeout=60):
        self.events.append(tuple(args))
        if self.fail == tuple(args):
            self.fail = None
            raise m.UpgradeError('Injected command failure')
        if output:
            output.write(b'isolated fixture archive/dump')
        if args[0] == 'ss':
            return 0, b'' if self.missing_echo_tcp and '-lnt' in args else b'fixture local listener'
        if args[0] == 'pg_dump':
            return 0, b'pg_dump (PostgreSQL) 17.6'
        if args[-1] == '-version-json':
            return 0, json.dumps(self.caps[args[-2].split('/')[-1]]).encode()
        return 0, b''

    def sql(self, query, database='neexitlag'):
        if query == 'SHOW server_version_num':
            return '170006'
        if 'information_schema' in query:
            return '1'
        if 'pg_stat_activity' in query:
            return '0'
        if 'pg_database_size' in query:
            return '1048576'
        if 'count(*) FROM devices WHERE revoked' in query:
            return str(len(self.revoked))
        if 'count(*) FROM devices' in query:
            return str(self.device_count)
        if 'json_agg' in query:
            return json.dumps(self.revoked)
        if 'octet_length' in query:
            return str(len(self.document()))
        if 'encode(document' in query:
            return base64.b64encode(self.document()).decode()
        raise AssertionError(query)

    def applied_config_document(self):
        return self.document()

    def document(self):
        return json.dumps({'payload': {'revoked_devices': self.revoked[:-1] if self.bad_publication else self.revoked}}).encode()

    def backup_database(self, b):
        self.events.append(('pg_dump',))
        if self.fail == ('pg_dump',):
            self.fail = None
            raise m.UpgradeError('Injected DB failure')
        (b / 'database.dump').write_bytes(b'isolated-db')
        (b / 'globals.sql').write_bytes(b'isolated-roles')

    def health(self, candidate=False):
        if not all(self.active.values()):
            raise m.UpgradeError('Service not running')
        if self.health_failures:
            self.health_failures -= 1
            raise m.UpgradeError('Injected transient health failure')
        return self.metric_values.copy()


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.h = FakeHost(root / 'host')
        self.up = m.Upgrade(self.h)
        self.addCleanup(patch.stopall)
        patch.object(m.os, 'fchown', lambda *args: None).start()
        patch.object(m.shutil, 'which', lambda name: '/fixture/' + name).start()
        patch.object(m.time, 'sleep', lambda n: None).start()
        for directory in [m.BIN, '/var/lib/neexitlag', '/etc/neexitlag/control', '/etc/neexitlag/relay', '/etc/neexitlag/public', '/etc/systemd/system']:
            self.h.path(directory).mkdir(parents=True, mode=0o700)
        for role, files in [('control', ['ca.pem', 'ca.key', 'server.pem', 'server.key', 'signing.key', 'admin.token', 'database.password', 'control-plane.env']), ('relay', ['ca.pem', 'server.pem', 'server.key', 'trust.json', 'heartbeat.token'])]:
            for f in files:
                p = self.h.path('/etc/neexitlag/' + role + '/' + f)
                p.write_text('SECRET fixture')
                p.chmod(0o600)
        self.h.path(m.CP + '/control-plane.env').write_text('DATABASE_URL=postgres://neexitlag@127.0.0.1:5432/neexitlag?sslmode=disable\n')
        self.h.path('/etc/neexitlag/public/relay.env').write_text('VPS_PUBLIC_IP=2.56.177.4\n')
        for role in ['relay', 'control-plane']:
            self.h.path(m.BIN + '/' + role).write_bytes(b'old binary ' + role.encode())
            self.h.path('/etc/systemd/system/neexitlag-' + role + '.service').write_text(self.h.unit)
        self.h.path('/var/lib/neexitlag/replay.json').write_text('live-replay-state')
        self.h.path('/var/lib/neexitlag/signed-config.json').write_text('live-signed-state')
        self.bundle = root / 'bundle'
        files = ['bin/relay', 'bin/control-plane', 'deploy/vps/production-upgrade.py']
        for name in files:
            p = self.bundle / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b'\x7fELF\x02\x01' + bytes(12) + b'\x3e\x00' + name.encode() if name.startswith('bin') else (ROOT / name).read_bytes())
        self.manifest = {'format': 1, 'commit': SHA, 'files': {n: m.digest(self.bundle / n) for n in files}, 'capabilities': self.h.caps}
        (self.bundle / 'UPGRADE_MANIFEST.json').write_text(json.dumps(self.manifest))
        self.inventory = root / 'inventory.json'
        self.inventory.write_text(json.dumps({'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'all_config_consumers_support_1mib': True, 'validated_commit': SHA, 'inventory_reference': 'fixture inventory'}))
        self.report = root / 'proof.json'
        self.report.write_text(json.dumps(proof()))

    def apply(self):
        return self.up.apply(self.bundle, SHA, self.inventory)

    def test_preflight_full_inventory_no_mutation_or_secret_output(self):
        before = m.config_fingerprint(self.h)
        state = self.up.preflight(self.bundle, SHA, self.inventory)
        self.assertEqual((state['devices'], state['revoked']), (5000, 1500))
        self.assertNotIn('-seed-', state['cp_command'])
        self.assertEqual(before, m.config_fingerprint(self.h))
        self.assertFalse(any(e[0] in ('start', 'stop', 'systemd-run') for e in self.h.events))

    def test_apply_commit_permanent_backups_order_identity_and_same_flow_proof(self):
        config = m.config_fingerprint(self.h)
        result = self.apply()
        b, state = self.up.load(result['id'])
        self.assertEqual(result['phase'], 'pending-verification')
        self.assertTrue(state['backup_complete'])
        for file, checksum in state['backup_hashes'].items():
            self.assertEqual(m.digest(b / file), checksum)
        self.assertEqual(config, m.config_fingerprint(self.h))
        self.assertLess(self.h.events.index(('start', 'neexitlag-relay')), self.h.events.index(('start', 'neexitlag-control-plane')))
        self.assertLess(self.h.events.index(('pg_dump',)), self.h.events.index(('start', 'neexitlag-relay')))
        self.assertIn(' -publish-config-on-start', self.h.path(m.DROPIN).read_text())
        self.h.metric_values.update(neexitlag_lease_renewals_total=2, neexitlag_tcp_connections_total=1, neexitlag_udp_packets_total=3)
        committed = self.up.commit(result['id'], self.report)
        self.assertEqual(committed['phase'], 'committed')
        self.assertTrue((b / 'database.dump').exists())
        events = len(self.h.events)
        self.up.rollback(result['id'], automatic=True)
        self.assertEqual(len(self.h.events), events)

    def test_failure_at_each_service_step_rolls_back_without_rewinding_security(self):
        for failure in [('pg_dump',), ('start', 'neexitlag-relay'), ('start', 'neexitlag-control-plane')]:
            with self.subTest(failure=failure):
                self.h.fail = failure
                with self.assertRaises(m.UpgradeError):
                    self.apply()
                ident = json.loads(self.h.path(m.STATE + '/pending.json').read_text())['id']
                b, s = self.up.load(ident)
                self.assertEqual(s['phase'], 'rolled_back')
                self.assertTrue(all(self.h.active.values()))
                self.assertEqual(self.h.path('/var/lib/neexitlag/replay.json').read_text(), 'live-replay-state')
                self.assertTrue((b / 'config-units.tar').exists())
                self.assertNotIn('-seed-', self.h.path(m.DROPIN).read_text())

    def test_truncated_publication_rolls_back_not_partial_success(self):
        self.h.bad_publication = True
        with patch.object(m.time, 'monotonic', side_effect=[0,46]):
            with self.assertRaises(m.UpgradeError):
                self.apply()
        self.assertTrue(all(self.h.active.values()))

    def test_legacy_rollback_refuses_large_state_and_preserves_new_revocations(self):
        result = self.apply()
        b, state = self.up.load(result['id'])
        state['old_capabilities'] = {r: {} for r in ['relay', 'control-plane']}
        self.up.save(b, state)
        with self.assertRaises(m.UpgradeError):
            self.up.rollback(result['id'])
        _, current = self.up.load(result['id'])
        self.assertEqual(current['phase'], 'maintenance-compatibility')
        self.assertFalse(any(self.h.active.values()))
        self.assertEqual(len(self.h.revoked), 1500)
        self.assertEqual(self.h.path('/var/lib/neexitlag/replay.json').read_text(), 'live-replay-state')

    def test_pending_boot_recovers_files_without_deadlocking_later_units(self):
        result = self.apply()
        self.h.events.clear()
        self.up.rollback(result['id'], automatic=True, boot=True)
        self.assertFalse(any(e[0] in ('start', 'stop') and e[1] in m.SERVICES for e in self.h.events))
        self.assertIn('Requires=neexitlag-upgrade-recover.service', self.h.path(m.GUARD.format(service='neexitlag-relay')).read_text())

    def test_prepare_failure_does_not_stop_services(self):
        self.h.fail = ('systemctl',)  # Fail arm BEFORE quiescing.
        with patch.object(self.up, 'arm', side_effect=m.UpgradeError('fixture arm failure')):
            with self.assertRaises(m.UpgradeError):
                self.apply()
        self.assertTrue(all(self.h.active.values()))
        self.assertFalse(any(e[0] == 'stop' and e[1] in m.SERVICES for e in self.h.events))

    def test_apply_preserves_original_command_failure_after_rollback(self):
        failure = m.UpgradeError('Required command failed; private transaction log retained')
        failure.command = 'systemctl'
        failure.exit_code = 1
        failure.command_stderr = b'fixture private diagnostic'
        with patch.object(self.up, 'arm', side_effect=failure):
            with self.assertRaises(m.UpgradeError) as caught:
                self.apply()
        self.assertIs(caught.exception, failure)
        self.assertEqual(caught.exception.command, 'systemctl')
        self.assertEqual(caught.exception.exit_code, 1)
        self.assertEqual(caught.exception.command_stderr, b'fixture private diagnostic')
        self.assertTrue(all(self.h.active.values()))

    def test_invalid_artifact_inventory_and_flow_proof_refused(self):
        for edit in [dict(validated_commit='b'*40), dict(all_config_consumers_support_1mib=False), dict(checked_at='2000-01-01T00:00:00Z')]:
            data = json.loads(self.inventory.read_text()) | edit
            self.inventory.write_text(json.dumps(data))
            with self.assertRaises((m.UpgradeError, ValueError)):
                m.compatibility(self.inventory, SHA)
        for key in ['same_connection', 'ticket_replay_rejected', 'renewal_replay_rejected']:
            p = proof(); p[key] = False
            with self.assertRaises(m.UpgradeError):
                m.validate_probe(p, '2.56.177.4')
        p = proof(); p['deadlines'][2] = p['deadlines'][1]
        with self.assertRaises(m.UpgradeError):
            m.validate_probe(p, '2.56.177.4')
        (self.bundle / 'bin/relay').write_bytes(b'tamper')
        with self.assertRaises(m.UpgradeError):
            m.verify_bundle(self.bundle, SHA)

    def test_database_and_snapshot_over_1mib_rejected(self):
        self.h.revoked = ['long-device-id-' + str(i) + '-' * 100 for i in range(10000)]
        with self.assertRaises(m.UpgradeError):
            self.up.check_publication()

    def test_stale_metrics_cannot_commit_even_with_pass_json(self):
        result = self.apply()
        with self.assertRaises(m.UpgradeError):
            self.up.commit(result['id'], self.report)
        self.assertEqual(self.up.load(result['id'])[1]['phase'], 'pending-verification')

    def test_failed_backup_durability_barrier_prevents_candidate_install(self):
        sync = m.os.fsync
        fired = [False]
        def fail_at_backup(fd):
            # Linux-only OS tests: fail when syncing old relay backup data.
            link = os.readlink('/proc/self/fd/' + str(fd))
            if link.endswith('/old-relay') and not fired[0]:
                fired[0] = True
                raise OSError('injected storage failure')
            return sync(fd)
        with patch.object(m.os, 'fsync', side_effect=fail_at_backup):
            with self.assertRaises(OSError):
                self.apply()
        self.assertTrue(fired[0])
        self.assertEqual(self.h.path(m.BIN + '/relay').read_bytes(), b'old binary relay')
        self.assertTrue(all(self.h.active.values()))

    def test_missing_echo_tcp_refused_before_any_service_stop(self):
        self.h.missing_echo_tcp = True
        with self.assertRaises(m.UpgradeError):
            self.up.preflight(self.bundle, SHA, self.inventory)
        self.assertFalse(any(e[0] == 'stop' for e in self.h.events))

    def test_preflight_rejects_writable_binary_and_unit(self):
        for path in [m.BIN + '/relay', '/etc/systemd/system/neexitlag-relay.service']:
            p = self.h.path(path)
            mode = p.stat().st_mode
            p.chmod(0o777)
            try:
                with self.assertRaises(m.UpgradeError):
                    self.up.preflight(self.bundle, SHA, self.inventory)
            finally:
                p.chmod(mode & 0o777)

    def test_seed_cleanup_rejects_unknown_arguments_and_never_executes_env(self):
        command = m.clean_cp_command(self.h.unit)
        self.assertNotIn('seed', command)
        self.assertNotIn('${', command)
        with self.assertRaises(m.UpgradeError):
            m.clean_cp_command(self.h.unit.replace('-listen', '-dangerous'))
        with self.assertRaises(m.UpgradeError):
            m.clean_cp_command(self.h.unit.replace(m.CP + '/server.key', '/tmp/secret'))
        p = Path(self.tmp.name) / 'unsafe.env'
        p.write_text('DATABASE_URL=$(touch /tmp/NEVER_EXECUTE)\n')
        with self.assertRaises(m.UpgradeError):
            m.env_value(p, 'DATABASE_URL')


if __name__ == '__main__':
    unittest.main()
