#!/usr/bin/env python3
"""Explicit, root-only CA maintenance transaction. Never invoked on import.
No package install, firewall, signing-key, DB restore or fleet reprovisioning.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

SERVICES = ('neexitlag-control-plane', 'neexitlag-relay')
DROPIN = Path('/etc/systemd/system/neexitlag-control-plane.service.d/91-veliq-fresh-ca.conf')
FILES = ('control/ca.pem', 'control/ca.key', 'control/server.pem', 'control/server.key',
         'relay/ca.pem', 'relay/server.pem', 'relay/server.key')

def fingerprint(path):
    raw = Path(path).read_text('ascii')
    der = ssl.PEM_cert_to_DER_cert(raw)
    return hashlib.sha256(der).hexdigest()

def command(argv):
    # Capture everything: systemctl/openssl errors must not dump configuration.
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=50, check=False)
    if p.returncode:
        raise RuntimeError('COMMAND_FAILED:' + Path(argv[0]).name)
    return p.stdout.decode('utf-8', errors='strict')

def atomic(path, data, mode, uid, gid):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.veliq-ca-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, path)
        d = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def credential_dropin(unit):
    # Interpret the effective concatenated unit's reset/override assignments,
    # never run a shell or discard deployment flags such as publication mode.
    joined = unit.replace('\\\n', ' ')
    starts = []
    section = ''
    for line in joined.splitlines():
        line = line.strip()
        if line.startswith('['):
            section = line
        if section == '[Service]' and line.startswith('ExecStart='):
            value = line.split('=', 1)[1]
            if not value:
                starts = []
            else:
                starts.append(value)
    if len(starts) != 1:
        raise RuntimeError('UNSUPPORTED_CP_UNIT')
    args = shlex.split(starts[0])
    if args[0] != '/opt/neexitlag/bin/control-plane' or '-ca-key' not in args:
        raise RuntimeError('UNSUPPORTED_CP_UNIT')
    index = args.index('-ca-key') + 1
    if args[index] != '/etc/neexitlag/control/ca.key':
        raise RuntimeError('UNSUPPORTED_CP_CA_KEY_PATH_OR_ALREADY_MIGRATED')
    # Require the reviewed deployment contract rather than guessing custom paths.
    for flag, value in (('-tls-cert', '/etc/neexitlag/control/server.pem'),
                        ('-tls-key', '/etc/neexitlag/control/server.key'),
                        ('-ca', '/etc/neexitlag/control/ca.pem'), ('-key-id', 'vps-1')):
        if flag not in args or args[args.index(flag) + 1] != value:
            raise RuntimeError('UNSUPPORTED_CP_UNIT')
    args[index] = '%d/veliq-device-ca-key'
    # systemd quoting, not shell evaluation. Preserve ${VPS_PUBLIC_IP} expansion.
    quoted = ' '.join('"' + x.replace('\\', '\\\\').replace('"', '\\"') + '"' for x in args)
    return ('[Service]\nLoadCredential=veliq-device-ca-key:/etc/neexitlag/control/ca.key\n'
            'ExecStart=\nExecStart=' + quoted + '\n').encode()

class Rotation:
    def __init__(self, config=Path('/etc/neexitlag'), dropin=DROPIN, run=command):
        self.config, self.dropin, self.run = Path(config), Path(dropin), run

    def backup(self, directory):
        directory = Path(directory)
        directory.mkdir(mode=0o700)
        for p in [self.config, *self.config.rglob('*')]:
            if p.is_symlink():
                raise RuntimeError('CONFIG_SYMLINK_REFUSED')
        shutil.copytree(self.config, directory / 'config')
        # Entire backup is inaccessible to service users; CA key at rest is 0600.
        for key in (directory / 'config').rglob('*.key'):
            key.chmod(0o600)
        manifest = {'phase': 'prepared', 'files': {}, 'dropin': self.dropin.exists()}
        for name in FILES:
            path = self.config / name
            st = path.stat()
            manifest['files'][name] = {'mode': st.st_mode & 0o777, 'uid': st.st_uid,
                                       'gid': st.st_gid,
                                       'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        if self.dropin.exists():
            if self.dropin.is_symlink():
                raise RuntimeError('DROPIN_SYMLINK_REFUSED')
            shutil.copy2(self.dropin, directory / 'previous-dropin')
        (directory / 'transaction.json').write_text(json.dumps(manifest))
        (directory / 'transaction.json').chmod(0o600)
        units = directory / 'units'
        units.mkdir(mode=0o700)
        for service in SERVICES:
            (units / (service + '.txt')).write_text(self.run(['systemctl', 'cat', service]))
            (units / (service + '.txt')).chmod(0o600)
        return manifest

    def state(self, directory, value):
        atomic(Path(directory) / 'transaction.json', json.dumps(value).encode(),
               0o600, os.geteuid(), os.getegid())

    def restore(self, directory, automatic=False):
        directory = Path(directory)
        m = json.loads((directory / 'transaction.json').read_text())
        if automatic and m['phase'] != 'pending':
            return
        if set(m['files']) != set(FILES):
            raise RuntimeError('INCOMPLETE_BACKUP_MANIFEST')
        # Validate whole backup BEFORE stopping services or changing any byte.
        for name, meta in m['files'].items():
            if name not in FILES or hashlib.sha256((directory / 'config' / name).read_bytes()).hexdigest() != meta['sha256']:
                raise RuntimeError('BACKUP_HASH_MISMATCH')
        self.run(['systemctl', 'stop', *SERVICES])
        for name, meta in m['files'].items():
            atomic(self.config / name, (directory / 'config' / name).read_bytes(),
                   meta['mode'], meta['uid'], meta['gid'])
        if m['dropin']:
            atomic(self.dropin, (directory / 'previous-dropin').read_bytes(), 0o644, 0, 0)
        elif self.dropin.exists():
            self.dropin.unlink()
        self.run(['systemctl', 'daemon-reload'])
        self.run(['systemctl', 'start', *SERVICES])
        m['phase'] = 'rolled-back'
        self.state(directory, m)

    def apply(self, directory, generated, dropin_bytes):
        m = self.backup(directory)
        # Root-owned durable code and transaction survive the SSH session.
        shutil.copy2(__file__, Path(directory) / 'rollback.py')
        (Path(directory) / 'rollback.py').chmod(0o700)
        unit = 'veliq-ca-rollback-' + Path(directory).name.removeprefix('neexitlag.bak-')
        m['phase'] = 'pending'
        self.state(directory, m)
        self.run(['systemd-run', '--unit=' + unit, '--on-active=180',
                  '--timer-property=AccuracySec=1s', '/usr/bin/python3',
                  str(Path(directory) / 'rollback.py'), 'rollback', '--backup',
                  str(directory), '--automatic'])
        try:
            self.run(['systemctl', 'stop', *SERVICES])
            for name in FILES:
                src = Path(generated) / Path(name).name
                meta = m['files'][name]
                is_ca_key = name == 'control/ca.key'
                atomic(self.config / name, src.read_bytes(), 0o600 if is_ca_key else meta['mode'],
                       0 if is_ca_key else meta['uid'], 0 if is_ca_key else meta['gid'])
            self.dropin.parent.mkdir(parents=True, exist_ok=True)
            atomic(self.dropin, dropin_bytes, 0o644, 0, 0)
            self.run(['systemctl', 'daemon-reload'])
            self.run(['systemctl', 'start', 'neexitlag-control-plane'])
            self.run(['systemctl', 'start', 'neexitlag-relay'])
        except BaseException:
            self.restore(directory)
            raise
        return m, unit

    def verify_commit(self, directory, manifest, unit, verify):
        try:
            verify()
            manifest['phase'] = 'committed'
            self.state(directory, manifest)
            self.run(['systemctl', 'stop', unit + '.timer'])
        except BaseException:
            self.restore(directory)
            raise


def check_capabilities(run=command):
    for role in ('control-plane', 'relay'):
        info = json.loads(run(['/opt/neexitlag/bin/' + role, '-version-json']))
        if info.get('role') != role or info.get('max_config_bytes', 0) < 1048576 or info.get('full_revocations') is not True:
            raise RuntimeError('FULL_REVOCATION_1MIB_SUPPORT_REQUIRED')
        if role == 'relay' and ('neexitlag/3' not in info.get('protocols', []) or info.get('default_lease_seconds') != 1800):
            raise RuntimeError('PRODUCTION_PROTOCOL_3_REQUIRED')


def check_root(ip):
    if os.geteuid() != 0 or os.uname().nodename.split('.')[0].lower() == 'veliq-swe-01':
        raise RuntimeError('ROOT_REQUIRED_OR_EXCLUDED_HOST')
    # This maintenance tool is scoped to the owner's explicit existing server.
    if ip != '2.56.177.4' or 'VPS_PUBLIC_IP=' + ip not in Path('/etc/neexitlag/public/relay.env').read_text().splitlines():
        raise RuntimeError('VPS_IDENTITY_MISMATCH')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('apply', 'rollback'))
    p.add_argument('--vps-ip', default='2.56.177.4')
    p.add_argument('--confirm', default='')
    p.add_argument('--expected-current-ca-sha256')
    p.add_argument('--helper')
    p.add_argument('--helper-sha256')
    p.add_argument('--backup')
    p.add_argument('--automatic', action='store_true')
    a = p.parse_args()
    check_root(a.vps_ip)
    rotation = Rotation()
    if a.mode == 'rollback':
        if not a.backup or not re.fullmatch(r'/etc/neexitlag\.bak-\d{8}T\d{6}Z-[a-f0-9]{8}', a.backup):
            raise RuntimeError('EXACT_BACKUP_REQUIRED')
        if not a.automatic and a.confirm != 'ROLLBACK-CA-2.56.177.4':
            raise RuntimeError('EXPLICIT_ROLLBACK_CONFIRMATION_REQUIRED')
        rotation.restore(a.backup, a.automatic)
        print('CA_ROLLBACK_COMPLETE (DB/replay state never restored)')
        return
    if a.confirm != 'ROTATE-CA-2.56.177.4':
        raise RuntimeError('EXPLICIT_CA_ROTATION_CONFIRMATION_REQUIRED')
    if not re.fullmatch('[a-f0-9]{64}', a.expected_current_ca_sha256 or '') or fingerprint('/etc/neexitlag/control/ca.pem') != a.expected_current_ca_sha256:
        raise RuntimeError('CURRENT_CA_PIN_MISMATCH')
    helper = Path(a.helper or '')
    if not helper.is_absolute() or not helper.is_file() or helper.is_symlink() or hashlib.sha256(helper.read_bytes()).hexdigest() != a.helper_sha256:
        raise RuntimeError('HELPER_HASH_MISMATCH')
    version = int(command(['systemctl', '--version']).split()[1])
    if version < 247:
        raise RuntimeError('SYSTEMD_LOADCREDENTIAL_247_REQUIRED')
    for service in (*SERVICES, 'neexitlag-echo'):
        command(['systemctl', 'is-active', '--quiet', service])
    if DROPIN.exists() or DROPIN.is_symlink() or DROPIN.parent.is_symlink():
        raise RuntimeError('EXISTING_OR_UNSAFE_CA_DROPIN_REFUSED')
    check_capabilities()
    dropin = credential_dropin(command(['systemctl', 'cat', 'neexitlag-control-plane']))
    # No signing/admin/heartbeat/echo/DB identity is rotated. No firewall changes.
    base = Path('/var/lib/neexitlag-fresh')
    if base.is_symlink():
        raise RuntimeError('STATE_SYMLINK_REFUSED')
    base.mkdir(mode=0o700, exist_ok=True)
    base.chmod(0o700)
    suffix = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + os.urandom(4).hex()
    backup = Path('/etc/neexitlag.bak-' + suffix)
    with tempfile.TemporaryDirectory(prefix='ca-', dir=base) as tmp:
        generated = Path(tmp) / 'new'
        command([str(helper), 'generate-ca', '--vps-ip', a.vps_ip, '--out', str(generated)])
        m, unit = rotation.apply(backup, generated, dropin)
        def verify():
            context = ssl.create_default_context(cafile='/etc/neexitlag/control/ca.pem')
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
            for endpoint in ('https://127.0.0.1:8443/healthz', 'http://127.0.0.1:9090/healthz'):
                until = time.monotonic() + 20
                while True:
                    try:
                        with opener.open(endpoint, timeout=2) as response:
                            if response.status != 200:
                                raise RuntimeError('HEALTH_STATUS_FAILED')
                        break
                    except Exception:
                        if time.monotonic() >= until:
                            raise RuntimeError('HEALTH_TIMEOUT') from None
                        time.sleep(0.25)
            command([str(helper), 'migration-probe', '--vps-ip', a.vps_ip])
        rotation.verify_commit(backup, m, unit, verify)
    print('CA_ROTATION_COMMITTED backup=' + str(backup) + ' ca_der_sha256=' + fingerprint('/etc/neexitlag/control/ca.pem'))

if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        # No raw subprocess/config/DB exception is printed. Backup remains root-only.
        if isinstance(exc, SystemExit):
            raise
        code = str(exc).split(':', 1)[0] if type(exc) is RuntimeError else ''
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{1,95}', code):
            code = type(exc).__name__
        print('CA_ROTATION_FAILED; inspect root-only backup/transaction; error_code=' + code, file=sys.stderr)
        sys.exit(1)
