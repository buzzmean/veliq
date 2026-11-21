#!/usr/bin/env python3
"""Root SSH RPC for relay-only installation and signed registry publication.
Private replies MUST stay in captured SSH transport. CLI rollback survives owner exit.
No CA rotation, client enrollment, activation/code mutation, DB restore or CP restart.
"""
import base64
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
import tempfile

ROOT = Path('/var/lib/veliq-relay-fleet')
MAINT = Path('/opt/neexitlag/maintenance')
STEP = 'ENTRY'
FILES = {'relay', 'relay-admin', 'relay-install.sh', 'relay-start.sh',
         'neexitlag-relay.service', 'update.sh', 'validate-env.py'}

def command(args, data=None, timeout=90):
    global STEP
    p = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    if p.returncode:
        # Root-private evidence; stdout can be certificates/tokens. Never echo it.
        diagnostic=p.stderr.decode('utf-8','replace').strip()
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{1,95}',diagnostic): diagnostic='COMMAND_OUTPUT_REDACTED'
        raise StepError(Path(args[0]).name, p.returncode,diagnostic)
    return p.stdout

class StepError(RuntimeError):
    def __init__(self, program, code, diagnostic):
        self.program, self.code, self.diagnostic = program, code, diagnostic
        super().__init__('REMOTE_COMMAND_FAILED')

def atomic(path, data, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError('SYMLINK_REFUSED')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name('.' + path.name + '.pending')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        tmp.unlink(missing_ok=True)

def artifact(item):
    b = base64.b64decode(item['data'], validate=True)
    if len(b) > 40*1024*1024 or hashlib.sha256(b).hexdigest() != item['sha256']:
        raise RuntimeError('ARTIFACT_DIGEST_OR_SIZE_FAILED')
    return b

def identity(role, ip):
    if os.geteuid() != 0 or os.uname().nodename.lower().startswith('veliq-swe-01'):
        raise RuntimeError('ROOT_REQUIRED_OR_EXCLUDED_HOST')
    addr = ipaddress.IPv4Address(ip)
    if not addr.is_global or (role == 'control' and ip != '2.56.177.4') or (role == 'relay' and ip == '2.56.177.4'):
        raise RuntimeError('HOST_ROLE_MISMATCH')
    interfaces = json.loads(command(['ip', '-j', '-4', 'addr', 'show']))
    if ip not in {a['local'] for n in interfaces for a in n.get('addr_info', [])}:
        raise RuntimeError('EXPECTED_PUBLIC_IP_NOT_LOCAL')

def preflight(role, ip):
    identity(role, ip)
    for name in ('python3', 'openssl', 'systemctl', 'curl', 'ip'):
        if not shutil.which(name):
            raise RuntimeError('MISSING_TOOL_' + name.upper())
    if shutil.disk_usage('/var/lib').free < 512*1024*1024:
        raise RuntimeError('INSUFFICIENT_SPACE')
    if role == 'control':
        command(['systemctl', 'is-active', '--quiet', 'neexitlag-control-plane'])
        command(['systemctl', 'is-active', '--quiet', 'neexitlag-relay'])
    return {'read_only': True, 'role': role, 'ip': ip,
            'free_bytes': shutil.disk_usage('/var/lib').free}

def root_dir(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    s = path.lstat()
    if path.is_symlink() or s.st_uid != 0 or s.st_mode & 0o077:
        raise RuntimeError('UNSAFE_ROOT_STATE')

def parse_exec(text, address):
    """Retain all existing credential paths/flags. No shell evaluation."""
    active = ''
    for line in text.splitlines():
        if line.startswith('ExecStart='):
            active = line[len('ExecStart='):]
    if '\\' in active or '\n' in active:
        raise RuntimeError('UNSUPPORTED_CONTROL_EXECSTART')
    args = shlex.split(active)
    if not args or args[0] != '/opt/neexitlag/bin/control-plane':
        raise RuntimeError('UNEXPECTED_CONTROL_EXECSTART')
    if '-seed-relay-id' not in args or args[args.index('-seed-relay-id')+1] != 'VPS-01':
        return None
    for flag in ('-seed-relay-address', '-seed-heartbeat-token-file'):
        if flag not in args or args.index(flag)+1 >= len(args):
            raise RuntimeError('INCOMPLETE_CONTROL_SEED')
    args[args.index('-seed-relay-address')+1] = address
    args[args.index('-seed-heartbeat-token-file')+1] = '/etc/neexitlag/control/heartbeat.token'
    return '[Service]\nExecStart=\nExecStart=' + ' '.join(shlex.quote(v) for v in args) + '\n'

class Worker:
    def __init__(self, role, ip):
        self.role, self.ip = role, ip
        self.job = None
        self.lock = None

    def state_path(self):
        return ROOT / ('job-' + self.ident + '.json')

    def save(self):
        atomic(self.state_path(), json.dumps(self.job).encode())

    def init(self, p):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', p['id']):
            raise RuntimeError('INVALID_RELAY_ID')
        self.ident, self.address = p['id'], p['address']
        root_dir(ROOT)
        MAINT.mkdir(mode=0o755,parents=True,exist_ok=True)
        if MAINT.is_symlink() or MAINT.stat().st_uid!=0 or MAINT.stat().st_mode&0o022:raise RuntimeError('UNSAFE_MAINTENANCE_DIRECTORY')
        self.lock = os.fdopen(os.open(ROOT / '.fleet.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600),'a')
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.stage = ROOT / ('stage-' + self.ident); root_dir(self.stage)
        for name, item in p['files'].items():
            if name not in FILES:
                raise RuntimeError('UNEXPECTED_ARTIFACT')
            atomic(self.stage / name, artifact(item), 0o700)
        if self.role == 'control':
            atomic(MAINT / 'relay-admin', (self.stage / 'relay-admin').read_bytes(), 0o700)
            atomic(MAINT / 'relay-fleet-remote.py', base64.b64decode(p['source'], validate=True), 0o700)
        if self.role=='control':
            recovery=Path('/etc/systemd/system/veliq-relay-fleet-recover.service')
            unit=("# VELIQ_OWNED_RELAY_FLEET_RECOVERY_V1\n[Unit]\nDescription=VELIQ pending relay registry recovery\nAfter=network-online.target neexitlag-control-plane.service\nWants=network-online.target\n[Service]\nType=oneshot\nUser=root\nRestart=on-failure\nRestartSec=30s\nExecStart=/usr/bin/python3 /opt/neexitlag/maintenance/relay-fleet-remote.py --recover-pending\n[Install]\nWantedBy=multi-user.target\n")
            if recovery.exists() and not recovery.read_text().startswith('# VELIQ_OWNED_RELAY_FLEET_RECOVERY_V1'):raise RuntimeError('RECOVERY_UNIT_NOT_OWNED')
            atomic(recovery,unit.encode(),0o644)
            command(['systemctl','daemon-reload']);command(['systemctl','enable','veliq-relay-fleet-recover.service'])
        if self.state_path().exists():
            self.job = json.loads(self.state_path().read_text())
            if self.job['address'] != self.address:
                raise RuntimeError('EXISTING_JOB_ADDRESS_MISMATCH')
        else:
            self.job = {'id': self.ident, 'address': self.address, 'role': self.role,
                        'ip': self.ip, 'phase': 'staged', 'seed_backup': {}, 'seed_written': {},
                        'legacy_created': False}
            self.save()
        return {'phase': self.job['phase']}

    def admin(self, op, ident=None, address=None, csr=''):
        q = {'Op': op, 'ID': ident or self.ident, 'Address': address or self.address,
             'Name': self.job.get('name', self.ident), 'CSR': csr}
        return json.loads(command([str(MAINT / 'relay-admin')], json.dumps(q).encode()))

    def keys(self, legacy=False):
        base = self.stage / ('legacy' if legacy else 'keys'); root_dir(base)
        key, csr = base / 'server.key', base / 'server.csr'
        if key.is_symlink() or csr.is_symlink():
            raise RuntimeError('UNSAFE_KEY_PATH')
        if not key.exists():
            command(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)])
            key.chmod(0o600)
        if not csr.exists():
            command(['openssl', 'req', '-new', '-key', str(key), '-subj', '/CN=VELIQ relay', '-out', str(csr)])
        return {'csr': csr.read_text()}

    def seed(self, bundle):
        if self.ident != 'VPS-01':
            return
        override = Path('/etc/systemd/system/neexitlag-control-plane.service.d/95-veliq-relay-registry.conf')
        # Exclude our override to derive the original command from all other units.
        text = command(['systemctl', 'cat', 'neexitlag-control-plane.service']).decode()
        if override.exists():
            if not self.job['seed_written'] or hashlib.sha256(override.read_bytes()).hexdigest() != self.job['seed_written'].get(str(override)):
                raise RuntimeError('SEED_OVERRIDE_OWNERSHIP_CHANGED')
            for path,expected in self.job['seed_written'].items():
                if not Path(path).exists() or hashlib.sha256(Path(path).read_bytes()).hexdigest()!=expected:raise RuntimeError('SEED_OWNERSHIP_CHANGED')
            return
        unit = parse_exec(text, self.address)
        if unit is None:
            return
        token = Path('/etc/neexitlag/control/heartbeat.token')
        for path, data, mode in ((override, unit.encode(), 0o644), (token, bundle['heartbeat'].encode(), token.stat().st_mode & 0o777)):
            self.job['seed_backup'][str(path)] = {'data': base64.b64encode(path.read_bytes()).decode() if path.exists() else None,
                                                'mode': path.stat().st_mode & 0o777 if path.exists() else mode,
                                                'uid': path.stat().st_uid if path.exists() else 0,
                                                'gid': path.stat().st_gid if path.exists() else 0}
            self.save()  # durable undo BEFORE any change
            meta = self.job['seed_backup'][str(path)]
            atomic(path, data, mode); os.chown(path, meta['uid'], meta['gid'])
            self.job['seed_written'][str(path)] = hashlib.sha256(data).hexdigest(); self.save()
        command(['systemctl', 'daemon-reload'])  # never restart control plane

    def prepare(self, p):
        self.job['name'] = p['name']; self.save()
        result = self.admin('prepare', csr=p['csr'])
        if result['phase'] != 'committed':
            self.job['phase'] = 'prepared'; self.save()
            unit = 'veliq-relay-fleet-' + self.ident
            command(['systemd-run', '--quiet', '--unit='+unit, '--on-active=10min',
                     '--timer-property=AccuracySec=1s', '--property=Restart=on-failure', '--property=RestartSec=30s', '--collect', '/usr/bin/python3',
                     str(MAINT/'relay-fleet-remote.py'), '--automatic-rollback', self.ident])
        self.job['pending_heartbeat']=result['heartbeat'];self.save()
        return result  # PRIVATE credentials; caller must not print

    def install(self, p):
        bundle = p['bundle']; creds = self.stage / 'credentials'; root_dir(creds)
        for name, b in {'ca.pem': bundle['ca'].encode(), 'cp-ca.pem': bundle['ca'].encode(),
                        'server.pem': bundle['certificate'].encode(),
                        'server.key': (self.stage/'keys/server.key').read_bytes(),
                        'trust.json': json.dumps(bundle['trust']).encode(),
                        'heartbeat.token': bundle['heartbeat'].encode()}.items():
            atomic(creds/name, b)
        command(['openssl', 'verify', '-CAfile', str(creds/'ca.pem'), str(creds/'server.pem')])
        command(['openssl', 'x509', '-checkend', '86400', '-noout', '-in', str(creds/'server.pem')])
        cert_pub = command(['openssl', 'x509', '-in', str(creds/'server.pem'), '-pubkey', '-noout'])
        key_pub = command(['openssl', 'pkey', '-in', str(creds/'server.key'), '-pubout'])
        if cert_pub != key_pub:
            raise RuntimeError('SERVER_KEY_CERTIFICATE_MISMATCH')
        env = ('RELAY_LISTEN=0.0.0.0:4433\nRELAY_METRICS=127.0.0.1:9090\nRELAY_ID='+self.ident+
               '\nRELAY_DESTINATION_POLICY=public-only\nRELAY_CONTROL_PLANE=https://2.56.177.4:8443\nRELAY_CONTROL_PLANE_CA_FILE=/etc/neexitlag/relay/cp-ca.pem\n')
        atomic(self.stage/'relay.env', env.encode())
        binary = Path('/opt/neexitlag/bin/relay')
        # Do not adopt an unrelated existing installation. Owned retries may only
        # rotate our leaf/heartbeat; CA, private key and environment stay fixed.
        owned=self.job.get('installed_hashes',{})
        managed=[Path('/etc/neexitlag/relay')/n for n in ('server.pem','server.key','heartbeat.token','ca.pem','cp-ca.pem','trust.json')]
        managed += [Path('/etc/neexitlag/relay/relay.env'),binary,Path('/opt/neexitlag/bin/relay-start'),Path('/etc/systemd/system/neexitlag-relay.service')]
        expected={str(path):hashlib.sha256((creds/path.name).read_bytes()).hexdigest() for path in managed[:6]}
        expected[str(managed[6])]=hashlib.sha256(env.encode()).hexdigest()
        expected[str(binary)]=hashlib.sha256((self.stage/'relay').read_bytes()).hexdigest()
        expected[str(managed[8])]=hashlib.sha256((self.stage/'relay-start.sh').read_bytes()).hexdigest()
        expected[str(managed[9])]=hashlib.sha256((self.stage/'neexitlag-relay.service').read_bytes()).hexdigest()
        for path in managed:
            if path.is_symlink():raise RuntimeError('INSTALLED_PATH_SYMLINK')
            if not path.exists():continue
            actual=hashlib.sha256(path.read_bytes()).hexdigest()
            if not owned or actual not in (owned.get(str(path)),expected[str(path)]):raise RuntimeError('EXISTING_INSTALL_NOT_OWNED_OR_CHANGED')
        # Durable manifest before installer writes permits an interrupted first
        # install to resume only with the exact previously approved artifacts.
        self.job['installed_hashes']=expected;self.save()
        rotated=False
        for path in managed[:6]:
            if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()!=expected[str(path)]:
                if path.name not in ('server.pem','heartbeat.token'):raise RuntimeError('FIXED_RELAY_CREDENTIAL_CHANGED')
                meta=path.stat();atomic(path,(creds/path.name).read_bytes(),meta.st_mode&0o777);os.chown(path,meta.st_uid,meta.st_gid);rotated=True

        same = binary.exists() and hashlib.sha256(binary.read_bytes()).digest() == hashlib.sha256((self.stage/'relay').read_bytes()).digest()
        same = same and all((Path('/etc/neexitlag/relay')/n).exists() and (Path('/etc/neexitlag/relay')/n).read_bytes() == (creds/n).read_bytes() for n in ('server.pem','server.key','heartbeat.token','ca.pem','cp-ca.pem','trust.json'))
        same = same and not rotated and all(path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==expected[str(path)] for path in managed)
        if not same:
            command(['bash', str(self.stage/'relay-install.sh'), str(self.stage/'relay'), str(creds), str(self.stage/'relay.env')], timeout=180)
        command(['systemctl', 'is-active', '--quiet', 'neexitlag-relay'])
        command(['curl', '--fail', '--silent', '--max-time', '3', 'http://127.0.0.1:9090/healthz'])
        if shutil.which('ufw') and b'Status: active' in command(['ufw','status']):
            command(['ufw','allow','4433/udp','comment','VELIQ relay'])
        self.job['phase']='installed'; self.save()
        return {'local_health': True, 'idempotent_no_restart': same}

    def publish(self):
        self.seed({'heartbeat':self.job['pending_heartbeat']})
        result = self.admin('commit'); self.job['phase']='published'; self.save(); return result

    def finalize(self):
        result = self.admin('finalize'); self.job['phase']='committed'; self.save()
        subprocess.run(['systemctl','stop','veliq-relay-fleet-'+self.ident+'.timer'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if subprocess.run(['systemctl','is-active','--quiet','veliq-relay-fleet-'+self.ident+'.timer']).returncode==0: raise RuntimeError('TIMER_DISARM_FAILED')
        return result

    def rollback(self, automatic=False):
        if automatic and self.job['phase']=='committed':
            return {'phase':'committed','rollback':'NOT_REQUIRED'}
        result=self.admin('rollback')
        for name, old in self.job['seed_backup'].items():
            path=Path(name)
            if path.exists() and self.job['seed_written'].get(name) != hashlib.sha256(path.read_bytes()).hexdigest():
                raise RuntimeError('SEED_ROLLBACK_OWNERSHIP_CHANGED')
            if old['data'] is None: path.unlink(missing_ok=True)
            else:
                atomic(path,base64.b64decode(old['data']),old['mode']); os.chown(path,old['uid'],old['gid'])
        command(['systemctl','daemon-reload']); self.job['phase']='rolled_back'; self.save()
        subprocess.run(['systemctl','stop','veliq-relay-fleet-'+self.ident+'.timer'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return result

    def heartbeat(self):
        v=self.admin('inspect')
        return {'healthy':v['heartbeat_healthy'],'fresh':v['heartbeat_fresh'],'at':v.get('heartbeat_at')}



def main():
    global STEP
    if len(sys.argv)==2 and sys.argv[1]=='--recover-pending':
        identity('control','2.56.177.4')
        lock = os.fdopen(os.open(ROOT/'.fleet.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600),'a')
        fcntl.flock(lock,fcntl.LOCK_EX)
        for path in sorted(ROOT.glob('job-*.json')):
            job=json.loads(path.read_text())
            if job.get('role')!='control' or job.get('phase') not in ('prepared','published'):continue
            w=Worker('control','2.56.177.4');w.ident=job['id'];w.address=job['address'];w.job=job
            w.rollback(True)
        return
    if len(sys.argv)==3 and sys.argv[1]=='--automatic-rollback':
        ident=sys.argv[2]
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',ident): raise RuntimeError('BAD_ID')
        identity('control','2.56.177.4')
        lock = os.fdopen(os.open(ROOT/'.fleet.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600),'a')
        fcntl.flock(lock,fcntl.LOCK_EX)
        p=ROOT/('job-'+ident+'.json');job=json.loads(p.read_text())
        w=Worker('control','2.56.177.4');w.ident=ident;w.address=job['address'];w.job=job
        w.rollback(True);return
    role, ip = ROLE, HOST_IP  # supplied by the authenticated SSH bootstrap
    identity(role,ip);w=Worker(role,ip)
    while True:
        line=sys.stdin.buffer.readline(100*1024*1024+1)
        if not line:break
        try:
            if len(line)>100*1024*1024: raise RuntimeError('BOUNDED_REQUEST_EXCEEDED')
            q=json.loads(line);STEP=q['op']
            if STEP=='preflight': result=preflight(role,ip)
            elif STEP=='inspect_standalone' and role=='control':
                with tempfile.TemporaryDirectory(prefix='veliq-relay-readonly-',dir='/var/tmp') as tmp:
                    helper=Path(tmp)/'relay-admin';helper.write_bytes(artifact(q['helper']));helper.chmod(0o700)
                    request={'Op':'inspect','ID':q['id'],'Address':q['address']}
                    result=json.loads(command([str(helper)],json.dumps(request).encode()))
            elif STEP=='init': result=w.init(q)
            elif STEP=='keys': result=w.keys()
            elif STEP=='prepare' and role=='control': result=w.prepare(q)
            elif STEP=='install' and role=='relay': result=w.install(q)
            elif STEP=='publish' and role=='control': result=w.publish()
            elif STEP=='finalize' and role=='control': result=w.finalize()
            elif STEP=='rollback' and role=='control': result=w.rollback()
            elif STEP=='heartbeat' and role=='control': result=w.heartbeat()
            elif STEP=='inspect' and role=='control': result=w.admin('inspect')
            else: raise RuntimeError('RPC_OPERATION_NOT_ALLOWED')
            print(json.dumps({'ok':True,'result':result}),flush=True)
        except BaseException as e:
            code=str(e) if isinstance(e,RuntimeError) and re.fullmatch('[A-Z][A-Z0-9_]{1,95}',str(e)) else 'SAFE_FLEET_STEP_FAILED'
            print(json.dumps({'ok':False,'step':STEP,'code':code,'class':type(e).__name__,
                              'program':getattr(e,'program',None),'exit_code':getattr(e,'code',None),'diagnostic':getattr(e,'diagnostic',None)}),flush=True)

if __name__=='__main__':
    try: main()
    except BaseException as e:
        print(json.dumps({'ok':False,'step':STEP,'code':'FLEET_BOOTSTRAP_FAILED','class':type(e).__name__}),flush=True);sys.exit(1)
