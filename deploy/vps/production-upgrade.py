#!/usr/bin/env python3
"""Existing-installation upgrade only. No enrollment, provisioning or secret output."""
import argparse
import base64
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse

MAX_CONFIG = 1024 * 1024
LEGACY_CONFIG = 65536
SERVICES = ('neexitlag-relay', 'neexitlag-control-plane')
CP = '/etc/neexitlag/control'
RELAY = '/etc/neexitlag/relay'
BIN = '/opt/neexitlag/bin'
STATE = '/var/lib/neexitlag-upgrade'
BACKUPS = '/var/backups/neexitlag-upgrades'
DROPIN = '/etc/systemd/system/neexitlag-control-plane.service.d/40-neexitlag-production-upgrade.conf'
FRESH_CA_DROPIN = '/etc/systemd/system/neexitlag-control-plane.service.d/91-veliq-fresh-ca.conf'
ACTIVATION_DROPIN = '/etc/systemd/system/neexitlag-control-plane.service.d/92-veliq-activation.conf'
CREDENTIAL_EXEC_DROPIN = '/etc/systemd/system/neexitlag-control-plane.service.d/94-veliq-production-upgrade.conf'
CA_CREDENTIAL = '%d/veliq-device-ca-key'
GUARD = '/etc/systemd/system/{service}.service.d/10-neexitlag-upgrade-guard.conf'
RECOVERY = '/etc/systemd/system/neexitlag-upgrade-recover.service'
ID_RE = re.compile(r'^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$')
COMMIT_RE = re.compile(r'^[0-9a-f]{40}$')


class UpgradeError(Exception):
    """Messages must be static/sanitized: never interpolate command output."""


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for part in iter(lambda: f.read(1024 * 1024), b''):
            h.update(part)
    return h.hexdigest()


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.state-')
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(data, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        d = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def verify_bundle(bundle, expected):
    bundle = Path(bundle)
    if not COMMIT_RE.fullmatch(expected):
        raise UpgradeError('Full expected commit is required')
    manifest = json.loads((bundle / 'UPGRADE_MANIFEST.json').read_text())
    required = {'bin/relay', 'bin/control-plane', 'deploy/vps/production-upgrade.py'}
    if manifest.get('format') != 1 or manifest.get('commit') != expected or set(manifest.get('files', {})) != required:
        raise UpgradeError('Unexpected upgrade manifest/commit/files')
    for name in required:
        p = bundle / name
        if any(x.is_symlink() for x in [p, *p.parents]):
            raise UpgradeError('Bundle path contains link')
        if p.is_symlink() or not p.is_file() or digest(p) != manifest['files'][name]:
            raise UpgradeError('Upgrade file checksum or type mismatch')
    for role in ('relay', 'control-plane'):
        p = bundle / 'bin' / role
        with p.open('rb') as executable:
            header = executable.read(20)
        if len(header) != 20 or header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\x3e\x00':
            raise UpgradeError('Expected Linux amd64 ELF')
        caps = manifest['capabilities'][role]
        if caps.get('role') != role or caps.get('commit') != expected or caps.get('modified') or caps.get('max_config_bytes') != MAX_CONFIG or not caps.get('full_revocations') or caps.get('migration') != '001-additive':
            raise UpgradeError('Candidate upgrade capabilities are incompatible')
        if role == 'relay' and (caps.get('default_lease_seconds') != 1800 or caps.get('protocols') != ['neexitlag/2', 'neexitlag/3']):
            raise UpgradeError('Candidate relay protocol/lease mismatch')
    return manifest


def compatibility(path, expected):
    data = json.loads(Path(path).read_text())
    # This is an operator inventory attestation, NOT automatic fleet discovery.
    checked = datetime.datetime.fromisoformat(data.get('checked_at', '').replace('Z', '+00:00'))
    age = datetime.datetime.now(datetime.timezone.utc) - checked
    if data.get('all_config_consumers_support_1mib') is not True or data.get('validated_commit') != expected or not isinstance(data.get('inventory_reference'), str) or not 1 <= len(data['inventory_reference']) <= 512 or not 0 <= age.total_seconds() <= 86400:
        raise UpgradeError('Fresh fleet compatibility inventory attestation required')
    return digest(path)


def validate_probe(proof, egress):
    flags = ['pass', 'same_connection', 'ticket_replay_rejected', 'wrong_ticket_rejected', 'anonymous_mtls_rejected', 'legacy_2', 'receipt_retry', 'renewal_replay_rejected']
    if any(proof.get(k) is not True for k in flags) or proof.get('alpn') != 'neexitlag/3' or proof.get('renewals') != 2 or proof.get('default_lease_seconds') != 1800 or proof.get('tcp_source') != egress or proof.get('udp_source') != egress or proof.get('udp_flow_id') != 2 or not isinstance(proof.get('tcp_stream_id'), int):
        raise UpgradeError('Live protocol/security/flow proof incomplete')
    times = [datetime.datetime.fromisoformat(v.replace('Z', '+00:00')) for v in proof.get('deadlines', [])]
    if len(times) != 3 or any(t.tzinfo is None for t in times) or not times[0] < times[1] < times[2]:
        raise UpgradeError('Live renewal deadlines did not advance twice')


class Host:
    """Small injectable OS boundary; tests never redirect production CLI paths."""
    def __init__(self, root=Path('/')):
        self.root = Path(root)
        self.log = None

    def path(self, absolute):
        return self.root / absolute.lstrip('/')

    def run(self, args, check=True, output=None, timeout=60):
        # Command stderr and dump contents never enter the public status stream.
        with tempfile.TemporaryFile() as errors, tempfile.TemporaryFile() as captured:
            target = output if output is not None else captured
            try:
                result = subprocess.run(args, stdout=target, stderr=errors, timeout=timeout, check=False)
            except (OSError, subprocess.TimeoutExpired):
                error = UpgradeError('Required command unavailable or timed out')
                error.command = Path(args[0]).name
                raise error from None
            observer=globals().get('PROCESS_OBSERVER')
            if observer is not None:
                errors.seek(0);captured.seek(0)
                observer(args,result.returncode,captured.read(8192),errors.read(8192))
            if self.log:
                self.log.write(('command=' + Path(args[0]).name + ' code=' + str(result.returncode) + '\n').encode())
                errors.seek(0)
                shutil.copyfileobj(errors, self.log)
                self.log.flush()
            if check and result.returncode:
                error = UpgradeError('Required command failed; private transaction log retained')
                error.exit_code = result.returncode
                error.command = Path(args[0]).name
                errors.seek(0); error.command_stderr = errors.read(4096)
                raise error
            captured.seek(0)
            raw = captured.read(2 * MAX_CONFIG + 1)
            if len(raw) > 2 * MAX_CONFIG:
                raise UpgradeError('Command response exceeds safety bound')
            return result.returncode, raw

    def systemctl(self, *args, check=True):
        return self.run(['systemctl', *args], check=check)[1].decode().strip()

    def running_binary_hash(self, pid):
        return digest('/proc/' + pid + '/exe')

    def configuration_owner(self, entry):
        return entry.st_uid == 0

    def sql(self, query, database='neexitlag'):
        return self.run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-h', '/var/run/postgresql', '-p', str(self.db_port), '-d', database, '-c', query], timeout=5)[1].decode().strip()

    def applied_config_document(self):
        try:
            with self.path('/var/lib/neexitlag/signed-config.json').open('rb') as f:
                return f.read(MAX_CONFIG + 1)
        except OSError:
            raise UpgradeError('Relay verified configuration cache unavailable') from None

    def backup_database(self, backup):
        for filename, command in [('database.dump', ['pg_dump', '--format=custom', '--dbname=' + self.database]), ('globals.sql', ['pg_dumpall', '--globals-only'])]:
            with open(backup / filename, 'xb') as output:
                os.chmod(backup / filename, 0o600)
                self.run(['runuser', '-u', 'postgres', '--', *command, '-h', '/var/run/postgresql', '-p', str(self.db_port)], output=output, timeout=180)
                output.flush()
                os.fsync(output.fileno())
        self.run(['pg_restore', '--list', str(backup / 'database.dump')])

    def health(self, candidate=False):
        for service in SERVICES:
            self.systemctl('is-active', '--quiet', service)
        self.run(['curl', '--noproxy', '*', '--fail', '--silent', '--max-time', '3', '--cacert', CP + '/ca.pem', 'https://127.0.0.1:8443/healthz'])
        self.run(['curl', '--noproxy', '*', '--fail', '--silent', '--max-time', '3', self.relay_health])
        raw = self.run(['curl', '--noproxy', '*', '--fail', '--silent', '--max-time', '3', self.relay_health.replace('/healthz', '/metrics')])[1].decode()
        values = {}
        for line in raw.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] in {'neexitlag_relay_health', 'neexitlag_lease_renewals_total', 'neexitlag_tcp_connections_total', 'neexitlag_udp_packets_total'}:
                values[fields[0]] = int(fields[1])
        if values.get('neexitlag_relay_health') != 1 or candidate and 'neexitlag_lease_renewals_total' not in values:
            raise UpgradeError('Relay metrics/capabilities unhealthy')
        return values

    def wait_health(self, candidate=False):
        for _ in range(15):
            try:
                return self.health(candidate)
            except UpgradeError:
                time.sleep(1)
        raise UpgradeError('Service health deadline exceeded')


def env_value(path, name):
    found = []
    for line in Path(path).read_text(encoding='utf-8-sig').splitlines():
        if line.strip().startswith(name + '='):
            value = shlex.split(line.strip().partition('=')[2], comments=False)
            if len(value) != 1:
                raise UpgradeError('Unsupported EnvironmentFile syntax')
            found.append(value[0])
    if len(found) != 1:
        raise UpgradeError('Required EnvironmentFile setting absent/duplicated')
    return found[0]


def config_fingerprint(host):
    data = {}
    for p in [host.path('/etc/neexitlag'), *sorted(host.path('/etc/neexitlag').rglob('*'))]:
        if p.is_symlink() or not (p.is_dir() or p.is_file()):
            raise UpgradeError('Configuration contains unsupported link/type')
        st = p.stat()
        if not host.configuration_owner(st) or st.st_mode & 0o022:
            raise UpgradeError('Configuration owner/write permissions unsafe')
        if any(x.startswith('system.posix_acl_') for x in os.listxattr(p)):
            raise UpgradeError('Extended configuration ACL requires explicit review')
        data[str(p.relative_to(host.root))] = [digest(p) if p.is_file() else 'directory', stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid]
    if not data:
        raise UpgradeError('Existing configuration missing')
    return data


def clean_cp_command(text, credential_ca=False):
    lines = [line.partition('=')[2] for line in text.splitlines() if line.startswith('ExecStart=') and line.partition('=')[2]]
    if len(lines) != 1:
        raise UpgradeError('Unsupported control-plane ExecStart layout')
    args = shlex.split(lines[0])
    if not args or args[0] != BIN + '/control-plane':
        raise UpgradeError('Custom control-plane launcher requires review')
    allowed = {'-listen', '-tls-cert', '-tls-key', '-signing-key', '-key-id', '-ca', '-ca-key', '-admin-token-file', '-database-password-file'}
    seeds = {'-seed-relay-id', '-seed-relay-address', '-seed-heartbeat-token-file'}
    result = [args[0]]
    i = 1
    while i < len(args):
        flag = args[i]
        if flag == '-publish-config-on-start':
            i += 1
            continue
        if flag not in allowed | seeds or i + 1 >= len(args):
            raise UpgradeError('Unsupported control-plane flags; review before upgrade')
        value = args[i + 1]
        if flag in allowed:
            if not re.fullmatch(r'[A-Za-z0-9_./:-]+', value) and not (credential_ca and flag == '-ca-key' and value == CA_CREDENTIAL):
                raise UpgradeError('Unsupported control-plane argument syntax')
            result += [flag, value]
        i += 2
    required = {'-tls-cert', '-tls-key', '-signing-key', '-ca', '-ca-key', '-admin-token-file', '-database-password-file'}
    if not required.issubset(result):
        raise UpgradeError('Expected credential-file arguments missing')
    for flag, name in [('-tls-cert', 'server.pem'), ('-tls-key', 'server.key'), ('-signing-key', 'signing.key'), ('-ca', 'ca.pem'), ('-ca-key', 'ca.key'), ('-admin-token-file', 'admin.token'), ('-database-password-file', 'database.password')]:
        expected = CA_CREDENTIAL if credential_ca and flag == '-ca-key' else CP + '/' + name
        if result[result.index(flag) + 1] != expected or result.count(flag) != 1:
            raise UpgradeError('Custom credential layout requires review')
    # Never repeat bootstrap seed operations on an established installation.
    return ' '.join(result)


def reviewed_credentials(host):
    """Only the exact owned fresh CA mechanism; never relax the root CA ACL."""
    path = host.path(FRESH_CA_DROPIN)
    if not path.exists(): return False
    st = path.stat()
    if path.is_symlink() or not host.configuration_owner(st) or st.st_mode & 0o022:
        raise UpgradeError('UNSAFE_FRESH_CA_DROPIN')
    lines = path.read_text().strip().splitlines()
    if len(lines) != 4 or lines[:3] != ['[Service]', 'LoadCredential=veliq-device-ca-key:/etc/neexitlag/control/ca.key', 'ExecStart='] or not lines[3].startswith('ExecStart='):
        raise UpgradeError('UNREVIEWED_FRESH_CA_DROPIN')
    clean_cp_command(lines[3], credential_ca=True)
    override = host.path(CREDENTIAL_EXEC_DROPIN)
    if override.exists():
        text = override.read_text()
        command = clean_cp_command(text, credential_ca=True)
        expected = '[Service]\nExecStart=\nExecStart=' + command
        if text not in (expected+'\n', expected+' -publish-config-on-start\n'):
            raise UpgradeError('UNREVIEWED_CREDENTIAL_EXEC_DROPIN')
    return True


def reviewed_activation_dropin(host):
    path = host.path(ACTIVATION_DROPIN)
    if not path.exists(): return
    expected = '# VELIQ_OWNED_ACTIVATION_V1 -- measurement credential only, never admin token.\n[Service]\nLoadCredential=veliq-echo-probe:/etc/neexitlag/echo/echo.token\nEnvironment=VELIQ_ENROLL_PROBE_TOKEN_FILE=%d/veliq-echo-probe\n'
    if path.read_text() != expected:
        raise UpgradeError('UNREVIEWED_ACTIVATION_DROPIN')


class Upgrade:
    def __init__(self, host):
        self.h = host

    def backup_path(self, ident):
        return self.h.path(BACKUPS + '/' + ident)

    def create_backup(self, ident):
        b = self.backup_path(ident)
        b.mkdir(parents=True, mode=0o700)
        os.chmod(b.parent, 0o700)
        return b

    def validate_schema(self, database):
        for table, column in [('devices', 'last_authenticated_at'), ('relay_nodes', 'heartbeat_token_hash'), ('config_versions', 'document')]:
            if self.h.sql("SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='%s' AND column_name='%s'" % (table, column), database) != '1':
                raise UpgradeError('Unrecognized existing DB schema')

    def migrate(self, state):
        # Default deployment keeps the established CP startup migration path.
        pass

    def preflight(self, bundle, expected, evidence):
        h = self.h
        manifest = verify_bundle(bundle, expected)
        compatibility_hash = compatibility(evidence, expected)
        if os.uname().machine != 'x86_64':
            raise UpgradeError('Only Linux amd64 supported')
        for tool in ['systemctl', 'systemd-run', 'runuser', 'psql', 'pg_dump', 'pg_dumpall', 'pg_restore', 'curl', 'openssl', 'tar', 'ss']:
            if shutil.which(tool) is None:
                raise UpgradeError('Required preinstalled dependency missing')
        for name in [BIN, '/etc/systemd/system', '/etc/neexitlag', '/var/lib/neexitlag', STATE, BACKUPS]:
            p = h.path(name)
            while p != h.root:
                if p.is_symlink():
                    raise UpgradeError('Managed path contains symlink')
                if p.exists() and str(p) != str(h.path('/var/lib/neexitlag')):
                    entry = p.stat()
                    if not h.configuration_owner(entry) or entry.st_mode & 0o022:
                        raise UpgradeError('Managed path owner/write permissions unsafe')
                p = p.parent
        fingerprint = config_fingerprint(h)
        credential_ca = reviewed_credentials(h)
        reviewed_activation_dropin(h)
        for role, names in [('control', ['ca.pem', 'ca.key', 'server.pem', 'server.key', 'signing.key', 'admin.token', 'database.password', 'control-plane.env']), ('relay', ['ca.pem', 'server.pem', 'server.key', 'trust.json', 'heartbeat.token'])]:
            for name in names:
                p = h.path('/etc/neexitlag/' + role + '/' + name)
                if not p.is_file() or p.stat().st_mode & 0o007:
                    raise UpgradeError('Private deployment file absent or world-accessible')
                if role == 'control' and name == 'ca.key' and credential_ca:
                    if not h.configuration_owner(p.stat()) or stat.S_IMODE(p.stat().st_mode) != 0o600:
                        raise UpgradeError('ROOT_ONLY_CA_KEY_REQUIRED')
                    runtime = h.path('/run/credentials/neexitlag-control-plane.service/veliq-device-ca-key')
                    if runtime.is_symlink() or not runtime.is_file() or digest(runtime) != digest(p):
                        raise UpgradeError('CA_RUNTIME_CREDENTIAL_MISMATCH')
                    h.run(['runuser', '-u', 'neexitlag-control', '--', 'test', '-r', str(runtime)])
                else:
                    h.run(['runuser', '-u', 'neexitlag-' + role, '--', 'test', '-r', str(p)])
        unit_files = []
        cp_text = None
        for service, user in [('neexitlag-relay', 'neexitlag-relay'), ('neexitlag-control-plane', 'neexitlag-control')]:
            if h.systemctl('show', '--value', '--property=User', service) != user:
                raise UpgradeError('Unexpected service identity')
            fragment = h.systemctl('show', '--value', '--property=FragmentPath', service)
            if fragment != '/etc/systemd/system/' + service + '.service':
                raise UpgradeError('Custom/vendor unit location requires review')
            drops = shlex.split(h.systemctl('show', '--value', '--property=DropInPaths', service))
            allowed_drops = {GUARD.format(service=service)} | ({DROPIN} if service == 'neexitlag-control-plane' else set())
            if service == 'neexitlag-control-plane':
                allowed_drops |= {ACTIVATION_DROPIN}
                if credential_ca: allowed_drops |= {FRESH_CA_DROPIN, CREDENTIAL_EXEC_DROPIN}
            if set(drops) - allowed_drops:
                raise UpgradeError('Unknown service drop-in requires review')
            for unit in [fragment] + drops:
                entry = h.path(unit).stat()
                if h.path(unit).is_symlink() or not h.configuration_owner(entry) or entry.st_mode & 0o022:
                    raise UpgradeError('Service unit ownership/type/permissions unsafe')
            unit_files += [fragment] + drops
            if service == 'neexitlag-control-plane':
                chosen = next((x for x in (CREDENTIAL_EXEC_DROPIN, FRESH_CA_DROPIN, DROPIN) if x in drops), fragment)
                cp_text = h.path(chosen).read_text()
            binary = h.path(BIN + '/' + ('relay' if service == 'neexitlag-relay' else 'control-plane'))
            if not binary.is_file() or binary.is_symlink() or not h.configuration_owner(binary.stat()) or binary.stat().st_mode & 0o022:
                raise UpgradeError('Installed binary missing or linked')
            pid = h.systemctl('show', '--value', '--property=MainPID', service)
            if not pid.isdigit() or int(pid) < 1 or h.running_binary_hash(pid) != digest(binary):
                raise UpgradeError('Running binary differs from installed file')
        cp_command = clean_cp_command(cp_text, credential_ca=credential_ca)
        url = urllib.parse.urlsplit(env_value(h.path(CP + '/control-plane.env'), 'DATABASE_URL'))
        name = url.path.lstrip('/')
        if url.scheme not in ('postgres', 'postgresql') or url.hostname not in ('127.0.0.1', 'localhost') or url.username != 'neexitlag' or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', name) or set(urllib.parse.parse_qs(url.query)) - {'sslmode'}:
            raise UpgradeError('Only existing local dedicated PostgreSQL layout supported')
        h.database, h.db_port = name, url.port or 5432
        version = int(h.sql('SHOW server_version_num', name))
        if not 140000 <= version < 180000:
            raise UpgradeError('PostgreSQL major outside validated 14..17 range')
        client = h.run(['pg_dump', '--version'])[1].decode()
        if not re.search(r'\b' + str(version // 10000) + r'\.', client):
            raise UpgradeError('pg_dump/server major mismatch')
        self.validate_schema(name)
        if h.sql("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state='idle in transaction'", name) != '0':
            raise UpgradeError('Open DB transaction blocks safe maintenance')
        db_size = int(h.sql('SELECT pg_database_size(current_database())', name))
        devices = int(h.sql('SELECT count(*) FROM devices', name))
        revoked = int(h.sql('SELECT count(*) FROM devices WHERE revoked', name))
        latest = h.sql('SELECT coalesce(max(octet_length(document)),0) FROM (SELECT document FROM config_versions ORDER BY version DESC LIMIT 1) s', name)
        for cert in [CP + '/ca.pem', CP + '/server.pem', RELAY + '/server.pem']:
            h.run(['openssl', 'x509', '-checkend', '86400', '-noout', '-in', cert])
        h.relay_health = 'http://127.0.0.1:9090/healthz'
        relay_env = h.path(RELAY + '/relay.env')
        if relay_env.exists():
            listen = env_value(relay_env, 'RELAY_METRICS') if any(line.strip().startswith('RELAY_METRICS=') for line in relay_env.read_text().splitlines()) else '127.0.0.1:9090'
            host, port = listen.rsplit(':', 1)
            if host != '127.0.0.1' or not port.isdigit():
                raise UpgradeError('Only explicit loopback relay metrics supported')
            h.relay_health = 'http://' + listen + '/healthz'
        metrics = h.health()
        # Do not enter maintenance only to discover that the existing proof
        # target cannot serve TCP. Never install/reconfigure that service here.
        h.systemctl('is-active', '--quiet', 'neexitlag-echo')
        h.run(['curl', '--noproxy', '*', '--fail', '--silent', '--max-time', '3', 'http://127.0.0.1:9092/healthz'])
        for flags in ['-lnt', '-lnu']:
            if not h.run(['ss', '-H', flags, 'sport = :40000'])[1].strip():
                raise UpgradeError('Existing authenticated echo must already listen on TCP and UDP 40000')
        space = max(1024**3, db_size * 3 + sum(h.path(BIN + '/' + n).stat().st_size for n in ['relay', 'control-plane']) * 4 + 256 * 1024**2)
        for directory in [BIN, '/etc/systemd/system', '/var/lib/neexitlag', BACKUPS]:
            p = h.path(directory)
            while not p.exists():
                p = p.parent
            if shutil.disk_usage(p).free < space:
                raise UpgradeError('Insufficient free space for persistent backup/atomic staging')
        old_caps = {}
        for role, user in [('relay', 'neexitlag-relay'), ('control-plane', 'neexitlag-control')]:
            code, raw = h.run(['runuser', '-u', user, '--', BIN + '/' + role, '-version-json'], check=False)
            try:
                old_caps[role] = json.loads(raw) if code == 0 else {}
            except ValueError:
                old_caps[role] = {}
        return {'commit': expected, 'manifest': manifest, 'compatibility_hash': compatibility_hash, 'config_fingerprint': fingerprint, 'cp_command': cp_command, 'unit_files': unit_files, 'database': name, 'db_port': h.db_port, 'pg_version': version, 'devices': devices, 'revoked': revoked, 'config_bytes': int(latest), 'required_free_bytes': space, 'old_capabilities': old_caps, 'old_binary_hashes': {role: digest(h.path(BIN + '/' + role)) for role in ['relay', 'control-plane']}, 'expected_egress': env_value(h.path('/etc/neexitlag/public/relay.env'), 'VPS_PUBLIC_IP'), 'relay_health': h.relay_health, 'metrics': metrics}

    def save(self, b, state):
        atomic_json(b / 'state.json', state)

    def install(self, source, dest, mode=0o755):
        dest = self.h.path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_symlink():
            raise UpgradeError('Refusing linked install destination')
        fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix='.upgrade-')
        try:
            with os.fdopen(fd, 'wb') as f, open(source, 'rb') as src:
                shutil.copyfileobj(src, f)
                os.fchmod(f.fileno(), mode)
                os.fchown(f.fileno(), 0, 0)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, dest)
            directory = os.open(dest.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def dropin(self, b, command, publish):
        text = '[Service]\nExecStart=\nExecStart=' + command + (' -publish-config-on-start' if publish else '') + '\n'
        p = b / ('new-cp.conf' if publish else 'rollback-cp.conf')
        p.write_text(text)
        os.chmod(p, 0o600)
        destination = CREDENTIAL_EXEC_DROPIN if CA_CREDENTIAL in shlex.split(command) else DROPIN
        self.install(p, destination, 0o644)

    def arm(self, b, state):
        h = self.h
        recovery_name = Path(RECOVERY).name
        h.path(STATE).mkdir(parents=True, exist_ok=True, mode=0o700)
        self.install(b / 'production-upgrade.py', STATE + '/production-upgrade.py', 0o700)
        # Persistent boot recovery runs before either application service. It
        # restores files only; it never waits for services ordered after itself.
        unit = b / 'recovery.service'
        unit.write_text('[Unit]\nDescription=VELIQ pending upgrade boot recovery\nAfter=postgresql.service\nRequires=postgresql.service\nBefore=neexitlag-relay.service neexitlag-control-plane.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 ' + STATE + '/production-upgrade.py recover\nTimeoutStartSec=240\n[Install]\nWantedBy=multi-user.target\n')
        self.install(unit, RECOVERY, 0o644)
        guard = b / 'guard.conf'
        guard.write_text('[Unit]\nRequires=' + recovery_name + '\nAfter=' + recovery_name + '\n')
        for service in SERVICES:
            self.install(guard, GUARD.format(service=service), 0o644)
        h.systemctl('daemon-reload')
        h.systemctl('enable', '--now', recovery_name)
        atomic_json(h.path(STATE + '/pending.json'), {'id': state['id']})
        h.run(['systemd-run', '--quiet', '--unit=neexitlag-upgrade-' + state['id'], '--on-active=10min', '--timer-property=AccuracySec=1s', '--property=TimeoutStartSec=15min', '/usr/bin/python3', STATE + '/production-upgrade.py', 'rollback', '--backup-id', state['id'], '--automatic'])

    def load(self, ident):
        if not ID_RE.fullmatch(ident):
            raise UpgradeError('Invalid backup identifier')
        b = self.backup_path(ident)
        state = json.loads((b / 'state.json').read_text())
        if state['id'] != ident:
            raise UpgradeError('Backup identifier mismatch')
        self.h.database, self.h.db_port, self.h.relay_health = state['database'], state['db_port'], state['relay_health']
        return b, state

    def apply(self, bundle, expected, evidence):
        h = self.h
        if h.path(STATE + '/pending.json').exists():
            pending = json.loads(h.path(STATE + '/pending.json').read_text())
            _, old = self.load(pending['id'])
            if old['phase'] not in ('committed', 'rolled_back', 'aborted'):
                raise UpgradeError('Unresolved prior transaction; inspect before a new upgrade')
        state = self.preflight(bundle, expected, evidence)
        ident = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + os.urandom(6).hex()
        b = self.create_backup(ident)
        state.update(id=ident, phase='prepared', backup_complete=False, transaction_version=1)
        self.save(b, state)
        h.log = open(b / 'private.log', 'ab', buffering=0)
        os.chmod(b / 'private.log', 0o600)
        try:
            for role in ['relay', 'control-plane']:
                shutil.copy2(h.path(BIN + '/' + role), b / ('old-' + role))
            shutil.copy2(Path(bundle) / 'deploy/vps/production-upgrade.py', b / 'production-upgrade.py')
            os.chmod(b / 'production-upgrade.py', 0o700)
            with open(b / 'config-units.tar', 'xb') as f:
                os.chmod(b / 'config-units.tar', 0o600)
                h.run(['tar', '--acls', '--xattrs', '-C', '/', '-cpf', '-', 'etc/neexitlag', *[x.lstrip('/') for x in state['unit_files']]], output=f)
                f.flush()
                os.fsync(f.fileno())
            self.arm(b, state)
            state['phase'] = 'quiescing'
            self.save(b, state)
            h.systemctl('stop', 'neexitlag-control-plane')
            h.backup_database(b)
            h.systemctl('stop', 'neexitlag-relay')
            with open(b / 'relay-state.tar', 'xb') as f:
                os.chmod(b / 'relay-state.tar', 0o600)
                h.run(['tar', '--acls', '--xattrs', '-C', '/', '-cpf', '-', 'var/lib/neexitlag'], output=f)
                f.flush()
                os.fsync(f.fileno())
            state['backup_hashes'] = {p.name: digest(p) for p in b.iterdir() if p.is_file() and p.name not in ['state.json', 'private.log']}
            # copy2/close is not a durability barrier. Persist every recovery
            # file and its directory entries BEFORE replacing a running binary.
            for saved in b.iterdir():
                if saved.is_file():
                    with saved.open('rb') as source:
                        os.fsync(source.fileno())
            for directory in [b, b.parent]:
                fd = os.open(directory, os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            state['backup_complete'] = True
            self.save(b, state)
            self.migrate(state)
            state['phase'] = 'installing-relay'
            self.save(b, state)
            self.install(Path(bundle) / 'bin/relay', BIN + '/relay')
            self.verify_installed('relay', state)
            h.systemctl('start', 'neexitlag-relay')
            # CP is intentionally stopped: relay still must start and advertise
            # /3 metrics before a producer can publish a >64 KiB configuration.
            h.systemctl('is-active', '--quiet', 'neexitlag-relay')
            h.run(['curl', '--noproxy', '*', '--fail', '--silent', '--retry', '10', '--retry-connrefused', '--retry-delay', '1', '--retry-max-time', '15', '--max-time', '2', h.relay_health])
            state['phase'] = 'installing-control-plane'
            self.save(b, state)
            self.install(Path(bundle) / 'bin/control-plane', BIN + '/control-plane')
            self.verify_installed('control-plane', state)
            self.dropin(b, state['cp_command'], True)
            h.systemctl('daemon-reload')
            h.systemctl('start', 'neexitlag-control-plane')
            metrics = h.wait_health(candidate=True)
            deadline = time.monotonic() + 45
            while True:
                try:
                    self.check_publication(require_applied=True)
                    break
                except UpgradeError:
                    if time.monotonic() >= deadline:
                        raise UpgradeError('Complete signed publication not applied by relay before deadline') from None
                    time.sleep(1)
            if config_fingerprint(h) != state['config_fingerprint']:
                raise UpgradeError('Existing configuration/identity metadata changed')
            state['phase'] = 'pending-verification'
            state['baseline'] = metrics
            self.save(b, state)
            return self.summary(state)
        except BaseException:
            # An unclean kill/reboot is handled by the independently armed
            # watchdog/boot guard. Catchable failures also rollback immediately.
            try:
                self.rollback(ident, automatic=True)
            except BaseException:
                pass
            # Keep the original command/exit status for the sanitized outer
            # diagnostics; replacing it here hid real systemd/OS failures.
            raise
        finally:
            h.log.close()
            h.log = None

    def verify_installed(self, role, state):
        user = 'neexitlag-relay' if role == 'relay' else 'neexitlag-control'
        raw = self.h.run(['runuser', '-u', user, '--', BIN + '/' + role, '-version-json'])[1]
        if json.loads(raw) != state['manifest']['capabilities'][role]:
            raise UpgradeError('Installed binary capabilities differ from pinned artifact')

    def check_publication(self, require_applied=False):
        h = self.h
        encoded = h.sql("SELECT encode(document,'base64') FROM config_versions ORDER BY version DESC LIMIT 1", h.database)
        raw = base64.b64decode(encoded)
        if len(raw) > MAX_CONFIG:
            raise UpgradeError('Published configuration exceeds consumer bound')
        config = json.loads(raw)['payload']
        ids = json.loads(h.sql("SELECT coalesce(json_agg(id ORDER BY id),'[]') FROM devices WHERE revoked", h.database))
        if sorted(config.get('revoked_devices', [])) != ids:
            raise UpgradeError('Revocation publication incomplete or inconsistent')
        if require_applied and self.h.applied_config_document() != raw:
            raise UpgradeError('Relay has not applied latest complete signed configuration')
        return len(raw)

    def rollback_safe(self, state):
        h = self.h
        devices = int(h.sql('SELECT count(*) FROM devices', h.database))
        raw_size = int(h.sql('SELECT coalesce(max(octet_length(document)),0) FROM (SELECT document FROM config_versions ORDER BY version DESC LIMIT 1) s', h.database))
        for role in ['relay', 'control-plane']:
            cap = state['old_capabilities'][role]
            if raw_size > cap.get('max_config_bytes', LEGACY_CONFIG) or devices > 1000 and not cap.get('full_revocations', False):
                return False
        cache = h.path('/var/lib/neexitlag/signed-config.json')
        if cache.exists() and cache.stat().st_size > state['old_capabilities']['relay'].get('max_config_bytes', LEGACY_CONFIG):
            return False
        return True

    def rollback(self, ident, automatic=False, boot=False):
        h = self.h
        b, state = self.load(ident)
        if state['phase'] in ('rolled_back', 'aborted') or automatic and state['phase'] == 'committed':
            return self.summary(state)
        if state['phase'] == 'prepared':
            state['phase'] = 'aborted'
            self.save(b, state)
            self.disarm(state)
            return self.summary(state)
        # Preserve ALL current DB security writes, replay cache and signed cache.
        if not boot:
            for service in reversed(SERVICES):
                h.systemctl('stop', service)
        if not self.rollback_safe(state):
            state['phase'] = 'maintenance-compatibility'
            self.save(b, state)
            if boot:
                h.systemctl('mask', '--runtime', *SERVICES)
            raise UpgradeError('Rollback incompatible with current security state; services stopped, DB/replay retained')
        for role in ['relay', 'control-plane']:
            if digest(b / ('old-' + role)) != state['old_binary_hashes'][role]:
                raise UpgradeError('Permanent backup binary checksum mismatch')
            self.install(b / ('old-' + role), BIN + '/' + role)
        # Units were never replaced. Restore a compatible seed-free override,
        # preventing the original bootstrap unit from overwriting relay metadata.
        self.dropin(b, state['cp_command'], False)
        h.systemctl('daemon-reload')
        if not boot:
            h.systemctl('start', 'neexitlag-control-plane')
            h.systemctl('start', 'neexitlag-relay')
            h.wait_health()
        state['phase'] = 'rolled_back'
        self.save(b, state)
        self.disarm(state)
        return self.summary(state)

    def commit(self, ident, report):
        h = self.h
        b, state = self.load(ident)
        if state['phase'] != 'pending-verification':
            raise UpgradeError('Transaction is not awaiting verification')
        proof = json.loads(Path(report).read_text())
        validate_probe(proof, state['expected_egress'])
        state['probe_sha256'] = digest(report)
        values = h.health(candidate=True)
        for metric, delta in [('neexitlag_lease_renewals_total', 2), ('neexitlag_tcp_connections_total', 1), ('neexitlag_udp_packets_total', 3)]:
            if values.get(metric, 0) - state['baseline'].get(metric, 0) < delta:
                raise UpgradeError('Live relay metrics do not prove post-upgrade TCP/UDP/renewal')
        self.check_publication(require_applied=True)
        if config_fingerprint(h) != state['config_fingerprint']:
            raise UpgradeError('Configuration or identity changed during verification')
        for role in ['relay', 'control-plane']:
            self.verify_installed(role, state)
        state['phase'] = 'committed'
        self.save(b, state)  # Durable before stopping timer; late rollback is a no-op.
        self.disarm(state)
        return self.summary(state)

    def disarm(self, state):
        self.h.systemctl('stop', 'neexitlag-upgrade-' + state['id'] + '.timer', check=False)

    @staticmethod
    def summary(state):
        return {k: state[k] for k in ['id', 'commit', 'phase', 'backup_complete']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['preflight', 'apply', 'commit', 'rollback', 'status', 'recover'])
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--expected-commit')
    parser.add_argument('--compatibility', type=Path)
    parser.add_argument('--backup-id')
    parser.add_argument('--automatic', action='store_true')
    parser.add_argument('--probe-report', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise UpgradeError('Root via existing SSH key/noninteractive sudo is required')
    os.umask(0o077)
    h = Host()
    upgrade = Upgrade(h)
    # The fixed CLI has no alternate-root/test bypass or shell-command hooks.
    with open('/run/neexitlag-production-upgrade.lock', 'a') as lock:
        try:
            # A watchdog waits behind an active bounded transaction rather than
            # disappearing if its deadline overlaps the final commit/rollback.
            flags = fcntl.LOCK_EX if args.action == 'rollback' and args.automatic else fcntl.LOCK_EX | fcntl.LOCK_NB
            fcntl.flock(lock, flags)
        except BlockingIOError:
            if args.action == 'recover':
                print(json.dumps({'phase': 'live-transaction-owner'}))
                return
            raise UpgradeError('Another upgrade operation owns the transaction lock') from None
        if args.action in ('apply', 'preflight'):
            if args.bundle is None or args.compatibility is None:
                raise UpgradeError('Pinned bundle and compatibility inventory are required')
            result = upgrade.apply(args.bundle, args.expected_commit, args.compatibility) if args.action == 'apply' else upgrade.preflight(args.bundle, args.expected_commit, args.compatibility)
            if args.action == 'preflight':
                result = {k: result[k] for k in ['commit', 'pg_version', 'devices', 'revoked', 'config_bytes', 'required_free_bytes']}
                result['pass'] = True
        elif args.action == 'recover':
            pending = h.path(STATE + '/pending.json')
            result = {'phase': 'no-pending-upgrade'} if not pending.exists() else upgrade.rollback(json.loads(pending.read_text())['id'], automatic=True, boot=True)
        elif args.action == 'status':
            _, state = upgrade.load(args.backup_id)
            result = upgrade.summary(state)
        elif args.action == 'commit':
            result = upgrade.commit(args.backup_id, args.probe_report)
        else:
            result = upgrade.rollback(args.backup_id, automatic=args.automatic)
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except UpgradeError as error:
        print(json.dumps({'pass': False, 'error': str(error)}))
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError):
        # Never print raw exceptions, env, psql/curl output or private paths.
        print(json.dumps({'pass': False, 'error': 'Upgrade operation refused/failed; inspect root-only transaction state and private.log'}))
        sys.exit(1)
