#!/usr/bin/env python3
"""Explicit one-PC recovery upgrade; no lost client credentials or CA changes.
Reuses the production transaction engine, with a local proof and durable journal.
"""
import contextlib
import fcntl
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import urllib.parse

# The read-only SSH path injects this module in memory: no remote staging writes.
e = globals().get('_FRESH_ENGINE')
ENGINE = Path(__file__).with_name('production-engine.py')
if e is None:
    if not ENGINE.exists(): ENGINE = Path(__file__).with_name('production-upgrade.py')
    if ENGINE.resolve() == Path(__file__).resolve(): raise RuntimeError('RECOVERY_ENGINE_MISSING')
    spec = importlib.util.spec_from_file_location('fresh_upgrade_engine', ENGINE)
    e = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(e)
e.STATE = '/var/lib/neexitlag-fresh-upgrade'
e.RECOVERY = '/etc/systemd/system/neexitlag-fresh-upgrade-recover.service'
# The base timer/recovery CLI calls this name; install this entrypoint there.


def compatible(info, role):
    return (info.get('role') == role and info.get('max_config_bytes', 0) >= 1048576
            and info.get('full_revocations') is True and info.get('migration') == '001-additive'
            and (role != 'relay' or ('neexitlag/3' in info.get('protocols', [])
                                    and info.get('default_lease_seconds') == 1800)))


def capabilities(h, binary, role):
    code, raw = h.run([str(binary), '-version-json'], check=False, timeout=10)
    try:
        info = json.loads(raw) if code == 0 else {}
    except (ValueError, TypeError):
        info = {}
    # Never echo arbitrary binary output, unknown fields or configuration.
    return {k: info[k] for k in ('role', 'commit', 'modified', 'protocols', 'default_lease_seconds',
                                'max_config_bytes', 'full_revocations', 'migration') if k in info}


def database(h):
    u = urllib.parse.urlsplit(e.env_value(h.path(e.CP + '/control-plane.env'), 'DATABASE_URL'))
    name = u.path.lstrip('/')
    if u.scheme not in ('postgres', 'postgresql') or u.hostname not in ('127.0.0.1', 'localhost') or u.username != 'neexitlag' or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}', name):
        raise e.UpgradeError('UNSUPPORTED_LOCAL_DATABASE')
    h.database, h.db_port = name, u.port or 5432


def report(h):
    database(h)
    old = {role: capabilities(h, h.path(e.BIN + '/' + role), role) for role in ('control-plane', 'relay')}
    services = {}
    for service in ('neexitlag-control-plane', 'neexitlag-relay', 'neexitlag-echo'):
        pid = h.systemctl('show', '--value', '--property=MainPID', service)
        services[service] = {'active': h.systemctl('is-active', service, check=False) == 'active',
                             'pid': int(pid) if pid.isdigit() else 0}
    ports = {key: bool(h.run(['ss', '-H', flag, 'sport = :' + str(port)])[1].strip())
             for key, flag, port in [('tcp8443', '-lnt', 8443), ('udp4433', '-lnu', 4433),
                                    ('tcp40000', '-lnt', 40000), ('udp40000', '-lnu', 40000)]}
    version = int(h.sql('SHOW server_version_num', h.database))
    addresses=json.loads(h.run(['ip','-j','-4','addr','show'])[1])
    local_ip=any(a.get('local')=='2.56.177.4' for interface in addresses for a in interface.get('addr_info',[]))
    return {'pass': True, 'read_only': True, 'capabilities': old, 'services': services, 'ports': ports,
            'local_vps_address':local_ip,
            'ca_migration_required':not h.path('/etc/systemd/system/neexitlag-control-plane.service.d/91-veliq-fresh-ca.conf').exists(),
            'pg_version': version, 'schema_migration': '001-additive',
            'applied_schema_version': int(h.sql('SELECT coalesce(max(version),0) FROM schema_migrations', h.database)),
            'paths': {'binaries':e.BIN,'configuration':'/etc/neexitlag','database':'local PostgreSQL socket'},
            'additive_column_present': h.sql("SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='devices' AND column_name='last_authenticated_at'",h.database)=='1',
            'architecture':os.uname().machine,
            'systemd_version': int(h.run(['systemctl', '--version'])[1].decode().split()[1]),
            'binary_sha256': {role: e.digest(h.path(e.BIN + '/' + role)) for role in old},
            'upgrade_needed': not all(compatible(old[role], role) for role in old)}


class LocalUpgrade(e.Upgrade):
    def __init__(self, host, helper=None):
        super().__init__(host)
        self.helper = Path(helper) if helper else host.path(e.STATE + '/fresh-pc')

    def backup_path(self, ident):
        if not e.ID_RE.fullmatch(ident):
            raise e.UpgradeError('INVALID_BACKUP_ID')
        return self.h.path('/etc/neexitlag.bak-' + ident)

    def create_backup(self, ident):
        b = self.backup_path(ident)
        b.mkdir(mode=0o700)  # NEVER chmod /etc (base engine uses a dedicated parent).
        print('VPS_UPGRADE_BACKUP=' + str(b), file=sys.stderr, flush=True)
        return b

    def validate_schema(self, name):
        for table, column in [('devices', 'public_key'), ('devices', 'revoked'), ('relay_nodes', 'metadata'), ('config_versions', 'document')]:
            if self.h.sql("SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='%s' AND column_name='%s'" % (table, column), name) != '1':
                raise e.UpgradeError('UNRECOGNIZED_EXISTING_SCHEMA')

    def preflight(self, bundle, expected, inventory):
        prior=self.h.path('/var/lib/neexitlag-upgrade/pending.json')
        if prior.exists():
            ident=json.loads(prior.read_text()).get('id','')
            if not e.ID_RE.fullmatch(ident): raise e.UpgradeError('INVALID_PRIOR_TRANSACTION')
            state_path=self.h.path(e.BACKUPS+'/'+ident+'/state.json')
            if not state_path.is_file() or json.loads(state_path.read_text()).get('phase') not in ('committed','rolled_back','aborted'):
                raise e.UpgradeError('PRIOR_PRODUCTION_UPGRADE_PENDING')
        state = super().preflight(bundle, expected, inventory)
        # Reserve two temporary rows/config publications so rollback to legacy
        # readers remains possible. Never restore DB/replay to an older snapshot.
        if state['devices'] > 998 or state['config_bytes'] > 48000:
            if any(not compatible(cap, role) for role, cap in state['old_capabilities'].items()):
                raise e.UpgradeError('LEGACY_ROLLBACK_CAPACITY_REQUIRES_REVIEW')
        return state

    def arm(self, b, state):
        # Include ALL binaries as well as the base per-role backups and config/unit
        # tar. Preserve root-owned recovery dependencies before changing services.
        with (b / 'binaries.tar').open('xb') as output:
            os.chmod(b / 'binaries.tar', 0o600)
            self.h.run(['tar', '--acls', '--xattrs', '-C', '/', '-cpf', '-', 'opt/neexitlag/bin'], output=output)
        shutil.copy2(ENGINE, b / 'production-engine.py')
        shutil.copy2(__file__, b / 'production-upgrade.py')
        shutil.copy2(self.helper, b / 'fresh-pc')
        self.install(ENGINE, e.STATE + '/production-engine.py', 0o700)
        self.install(self.helper, e.STATE + '/fresh-pc', 0o700)
        # The engine derives its guard dependency from RECOVERY; preserve its
        # boot/timer protocol with an independent persistent entrypoint.
        super().arm(b, state)

    def migrate(self, state):
        self.h.run([str(self.helper), 'upgrade-migrate', '--vps-ip', '2.56.177.4'], timeout=35)

    def cleanup(self, ident):
        journal = self.backup_path(ident) / 'probe.id'
        if journal.exists():
            self.h.run([str(self.h.path(e.STATE + '/fresh-pc')), 'upgrade-cleanup', '--vps-ip', '2.56.177.4', '--journal', str(journal)], timeout=30)

    def rollback_safe(self, state):
        self.cleanup(state['id'])  # also after SSH loss/process kill/boot
        return super().rollback_safe(state)

    def prove_commit(self, ident):
        b, state = self.load(ident)
        self.h.log = open(b / 'private.log', 'ab', buffering=0)
        os.chmod(b / 'private.log', 0o600)
        try:
            self.h.run([str(self.helper), 'upgrade-local-probe', '--vps-ip', '2.56.177.4', '--journal', str(b / 'probe.id')], timeout=70)
            self.cleanup(ident)
            self.h.wait_health(candidate=True)
            deadline = time.monotonic() + 45
            while True:
                try:
                    self.check_publication(require_applied=True)
                    break
                except e.UpgradeError:
                    if time.monotonic() >= deadline: raise
                    time.sleep(0.25)
            if e.config_fingerprint(self.h) != state['config_fingerprint']:
                raise e.UpgradeError('CONFIGURATION_CHANGED')
            for role in ('relay', 'control-plane'):
                self.verify_installed(role, state)
                service = 'neexitlag-' + role
                pid = self.h.systemctl('show', '--value', '--property=MainPID', service)
                if not pid.isdigit() or self.h.running_binary_hash(pid) != e.digest(self.h.path(e.BIN + '/' + role)):
                    raise e.UpgradeError('RUNNING_BINARY_HASH_MISMATCH')
            for flag, port in [('-lnt',8443),('-lnu',4433),('-lnt',40000),('-lnu',40000)]:
                if not self.h.run(['ss','-H',flag,'sport = :'+str(port)])[1].strip():
                    raise e.UpgradeError('LOCAL_LISTENER_MISSING')
            state['phase'] = 'committed'
            self.save(b, state)
            self.disarm(state)
            return {'pass': True, 'phase': 'committed', 'backup': str(b), 'proof': 'local authenticated TCP/UDP /3; temporary identity revoked'}
        except BaseException:
            self.rollback(ident, automatic=True)
            raise e.UpgradeError('LOCAL_UPGRADE_PROOF_FAILED_ROLLED_BACK') from None
        finally:
            self.h.log.close()
            self.h.log = None


def prepare(bundle, helper, commit, confirm, preflight_only=False, force_update=False, before_commit=None, validate_only=False):
    h = e.Host()
    current = report(h)
    print('VPS_PREFLIGHT=' + json.dumps(current, sort_keys=True), file=sys.stderr, flush=True)
    if preflight_only or (not current['upgrade_needed'] and not force_update and not validate_only):
        return current
    if confirm != 'UPGRADE-VPS-2.56.177.4':
        raise e.UpgradeError('EXPLICIT_UPGRADE_CONFIRMATION_REQUIRED')
    if not current.get('local_vps_address'):
        raise e.UpgradeError('VPS_PUBLIC_IP_NOT_LOCAL')
    bundle = Path(bundle)
    files = ['bin/relay','bin/control-plane','deploy/vps/production-upgrade.py']
    caps = {role: capabilities(h, bundle / 'bin' / role, role) for role in ('relay','control-plane')}
    manifest = {'format':1,'commit':commit,'files':{name:e.digest(bundle/name) for name in files},'capabilities':caps}
    (bundle/'UPGRADE_MANIFEST.json').write_text(json.dumps(manifest))
    inventory = bundle/'single-pc-inventory.json'
    inventory.write_text(json.dumps({'all_config_consumers_support_1mib':True,'validated_commit':commit,
                                    'inventory_reference':'owner-authorized single freeze PC rebuilt from this commit',
                                    'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}))
    up = LocalUpgrade(h, helper)
    if validate_only:
        up.preflight(bundle, commit, inventory)
        return {'pass': True, 'read_only': True, 'candidate_commit': commit}
    with transaction_lock():
        summary = up.apply(bundle, commit, inventory)
        if before_commit is not None: before_commit(summary)
        return up.prove_commit(summary['id'])


@contextlib.contextmanager
def transaction_lock(nonblocking=False):
    descriptors=[]
    try:
        # Serialize with the existing production updater as well as this path.
        for path in ('/run/neexitlag-production-upgrade.lock','/run/neexitlag-fresh-upgrade.lock'):
            fd=os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);descriptors.append(fd)
            os.fchmod(fd,0o600);fcntl.flock(fd,fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
        yield
    finally:
        for fd in reversed(descriptors): os.close(fd)


def main():
    # Recovery-only CLI used by the independent timer/boot guard and owner.
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=['rollback','recover'])
    p.add_argument('--backup-id');p.add_argument('--automatic',action='store_true')
    a=p.parse_args()
    if os.geteuid()!=0 or os.uname().nodename.split('.')[0].lower()=='veliq-swe-01':
        raise e.UpgradeError('ROOT_REQUIRED_OR_EXCLUDED_HOST')
    if e.env_value('/etc/neexitlag/public/relay.env','VPS_PUBLIC_IP')!='2.56.177.4':
        raise e.UpgradeError('VPS_IDENTITY_MISMATCH')
    h=e.Host();up=LocalUpgrade(h)
    try:
        # arm() starts this oneshot while the installer owns both locks. Boot
        # recovery must not wait for its parent installer (which is waiting for
        # systemctl enable --now). The watchdog rollback still waits normally.
        with transaction_lock(nonblocking=a.action=='recover'):
            result=recover(up,h,a)
    except BlockingIOError:
        if a.action!='recover': raise
        result={'phase':'live-transaction-owner'}
    print(json.dumps(result))


def recover(up,h,a):
    if a.action=='recover':
        pending=h.path(e.STATE+'/pending.json')
        result={'phase':'no-pending-upgrade'} if not pending.exists() else up.rollback(json.loads(pending.read_text())['id'],automatic=True,boot=True)
    else:
        b,state=up.load(a.backup_id)
        if not a.automatic and state['phase']=='committed' and e.config_fingerprint(h)!=state['config_fingerprint']:
            raise e.UpgradeError('CA_OR_CONFIG_CHANGED_MANUAL_MAINTENANCE_REQUIRED')
        result=up.rollback(a.backup_id,automatic=a.automatic)
    return result

if __name__=='__main__':
    try: main()
    except BaseException:
        print('FRESH_VPS_RECOVERY_FAILED: inspect root-only backup/state; no secrets emitted',file=sys.stderr)
        sys.exit(1)
