#!/usr/bin/env python3
"""Root-only leaf renewal. Never rotate CA, publish credentials or run on import."""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request

FILES=('control/server.pem','control/server.key','relay/server.pem','relay/server.key')
SERVICES=('neexitlag-control-plane','neexitlag-relay')
BACKUPS=Path('/var/backups/neexitlag-certificates')
import importlib.util
try:
    import activation_diagnostics as diagnostics
except ModuleNotFoundError:
    _spec=importlib.util.spec_from_file_location('activation_diagnostics',Path(__file__).with_name('activation-diagnostics.py'))
    diagnostics=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(diagnostics)


def command(argv):
    return diagnostics.run_process(argv,timeout=50).stdout.decode('utf-8')

def validate_helper(helper):
    command([str(helper),'probe-journal-check','--journal','/var/backups/neexitlag-certificates/20000101T000000Z-00000000/probe.id'])


@contextlib.contextmanager
def transaction_lock():
    fd=os.open('/run/veliq-cert-renewal.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as file:
        fcntl.flock(file,fcntl.LOCK_EX)
        yield


def disarm(directory,run=command):
    timer='veliq-leaf-rollback-'+Path(directory).name+'.timer'
    if run(['systemctl','show','--value','--property=LoadState',timer]).strip()!='not-found':
        run(['systemctl','stop',timer])


def certificate(path):
    value=ssl._ssl._test_decode_cert(str(path))
    return (dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(value['notAfter']),dt.timezone.utc),
            tuple(sorted(value.get('subjectAltName',()))))

def renewal_due(now,ca_expiry,leaf_expiry,before_days=10):
    if not 1<=before_days<=15: raise RuntimeError('INVALID_RENEWAL_THRESHOLD')
    if ca_expiry<=now+dt.timedelta(days=31): raise RuntimeError('CA_RENEWAL_REQUIRED')
    return leaf_expiry<=now+dt.timedelta(days=before_days)

def atomic(path,data,meta):
    path=Path(path)
    if path.is_symlink() or path.parent.is_symlink(): raise RuntimeError('SYMLINK_REFUSED')
    fd,name=tempfile.mkstemp(prefix='.veliq-leaf-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        os.chmod(name,meta['mode']);os.chown(name,meta['uid'],meta['gid']);os.replace(name,path)
        d=os.open(path.parent,os.O_DIRECTORY)
        try: os.fsync(d)
        finally: os.close(d)
    finally:
        if os.path.exists(name): os.unlink(name)

class Renewal:
    def __init__(self,config=Path('/etc/neexitlag'),run=command):
        self.config=Path(config);self.run=run
    def recover_pending(self,root):
        root=Path(root)
        if not root.exists(): return
        pending=[]
        directories=sorted(root.iterdir())
        if len(directories)>1000: raise RuntimeError('BACKUP_RETENTION_REVIEW_REQUIRED')
        for directory in directories:
            if directory.is_symlink(): raise RuntimeError('BACKUP_SYMLINK_REFUSED')
            manifest=directory/'transaction.json'
            if manifest.exists() and json.loads(manifest.read_text())['phase']=='pending': pending.append(directory)
        if len(pending)>1: raise RuntimeError('AMBIGUOUS_PENDING_RENEWAL')
        if pending: self.restore(pending[0])
    def preflight(self,now,ip,before=10,force=False):
        for p in [self.config,*self.config.rglob('*')]:
            if p.is_symlink(): raise RuntimeError('CONFIG_SYMLINK_REFUSED')
        ca=self.config/'control/ca.pem';leaf=self.config/'control/server.pem'
        expiry,sans=certificate(leaf);ca_expiry,_=certificate(ca)
        expected={('IP Address',ip),('IP Address','127.0.0.1')}
        if not expected.issubset(set(sans)): raise RuntimeError('REQUIRED_SAN_MISSING')
        for name in ('ca.pem','server.pem'):
            if (self.config/'control'/name).read_bytes()!=(self.config/'relay'/name).read_bytes(): raise RuntimeError('TLS_COPIES_MISMATCH')
        key=self.config/'control/ca.key';st=key.stat()
        if st.st_uid!=0 or st.st_mode&0o777!=0o600: raise RuntimeError('ROOT_ONLY_CA_KEY_REQUIRED')
        self.run(['openssl','verify','-CAfile',str(ca),str(ca)])
        # Inspect an expired OLD leaf at its last valid instant. All HTTPS/mTLS
        # network checks and the NEW leaf are verified at the real current time.
        at=str(int(min(now.timestamp(),expiry.timestamp()-1)))
        self.run(['openssl','verify','-attime',at,'-CAfile',str(ca),str(leaf)])
        due=renewal_due(now,ca_expiry,expiry,before)
        return due or force,expiry,ca_expiry,sans
    def generate(self,directory,sans):
        directory=Path(directory);directory.mkdir(mode=0o700)
        # Copy every existing SAN, not just the IPs expected by this deployment.
        values=[]
        for kind,value in sans:
            if kind=='IP Address': values.append('IP:'+value)
            elif kind=='DNS' and re.fullmatch(r'[A-Za-z0-9.*-]+',value): values.append('DNS:'+value)
            else: raise RuntimeError('UNSUPPORTED_SAN')
        ext=directory/'server.ext';ext.write_text('subjectAltName='+','.join(values)+'\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n')
        self.run(['openssl','genpkey','-algorithm','ED25519','-out',str(directory/'server.key')])
        (directory/'server.key').chmod(0o600)
        self.run(['openssl','req','-new','-key',str(directory/'server.key'),'-subj','/CN=VELIQ','-out',str(directory/'server.csr')])
        self.run(['openssl','x509','-req','-in',str(directory/'server.csr'),'-CA',str(self.config/'control/ca.pem'),'-CAkey',str(self.config/'control/ca.key'),'-set_serial',str(secrets.randbits(127)+1),'-days','30','-extfile',str(ext),'-out',str(directory/'server.pem')])
        self.run(['openssl','verify','-CAfile',str(self.config/'control/ca.pem'),str(directory/'server.pem')])
        if certificate(directory/'server.pem')[1]!=sans: raise RuntimeError('SAN_CHANGED')
    def state(self,directory,m):
        atomic(Path(directory)/'transaction.json',json.dumps(m).encode(),{'mode':0o600,'uid':os.geteuid(),'gid':os.getegid()})
    def backup(self,directory):
        directory=Path(directory);directory.mkdir(mode=0o700)
        shutil.copytree(self.config,directory/'config')
        for p in (directory/'config').rglob('*.key'): p.chmod(0o600)
        shutil.copy2(Path(__file__).with_name('activation-diagnostics.py'),directory/'activation-diagnostics.py')
        shutil.copy2(__file__,directory/'renew-server-cert.py');(directory/'renew-server-cert.py').chmod(0o700)
        m={'phase':'prepared','config':str(self.config),'files':{}}
        for name in FILES:
            p=self.config/name;st=p.stat();m['files'][name]={'mode':st.st_mode&0o777,'uid':st.st_uid,'gid':st.st_gid,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        self.state(directory,m);return m
    def restore(self,directory,automatic=False):
        directory=Path(directory);m=json.loads((directory/'transaction.json').read_text())
        if automatic and m['phase']!='pending': return
        if m['config']!=str(self.config) or set(m['files'])!=set(FILES): raise RuntimeError('BACKUP_MANIFEST_INVALID')
        for name,meta in m['files'].items():
            if hashlib.sha256((directory/'config'/name).read_bytes()).hexdigest()!=meta['sha256']: raise RuntimeError('BACKUP_HASH_MISMATCH')
        if (directory/'probe.id').exists():
            self.run(['/opt/neexitlag/maintenance/veliq-fresh-helper','upgrade-cleanup','--vps-ip','2.56.177.4','--journal',str(directory/'probe.id')])
        self.run(['systemctl','stop',*SERVICES])
        for name,meta in m['files'].items(): atomic(self.config/name,(directory/'config'/name).read_bytes(),meta)
        self.run(['systemctl','start',SERVICES[0]]);self.run(['systemctl','start',SERVICES[1]])
        m['phase']='rolled-back';self.state(directory,m);disarm(directory,self.run)
    def apply(self,directory,generated,verify):
        directory=Path(directory);m=self.backup(directory)
        unit='veliq-leaf-rollback-'+directory.name;m['phase']='pending';self.state(directory,m)
        self.run(['systemd-run','--unit='+unit,'--on-active=180','--timer-property=AccuracySec=1s','/usr/bin/python3',str(directory/'renew-server-cert.py'),'rollback','--backup',str(directory),'--automatic'])
        try:
            self.run(['systemctl','stop',*SERVICES])
            for name,meta in m['files'].items(): atomic(self.config/name,(Path(generated)/Path(name).name).read_bytes(),meta)
            self.run(['systemctl','start',SERVICES[0]]);self.run(['systemctl','start',SERVICES[1]])
            verify()
            m['phase']='committed';self.state(directory,m);disarm(directory,self.run)
        except BaseException:
            self.restore(directory);raise

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('run','rollback'));p.add_argument('--vps-ip',default='2.56.177.4');p.add_argument('--before-days',type=int,default=10);p.add_argument('--force',action='store_true');p.add_argument('--confirm',default='');p.add_argument('--backup');p.add_argument('--automatic',action='store_true');p.add_argument('--helper',default='/opt/neexitlag/maintenance/veliq-fresh-helper')
    a=p.parse_args();os.umask(0o077);diagnostics.step('LEAF_PREFLIGHT')
    if os.geteuid()!=0 or os.uname().nodename.split('.')[0].lower()=='veliq-swe-01': raise RuntimeError('ROOT_REQUIRED_OR_EXCLUDED_HOST')
    if a.vps_ip!='2.56.177.4': raise RuntimeError('VPS_IDENTITY_MISMATCH')
    diagnostics.require_vps_identity('/etc/neexitlag/public/relay.env',a.vps_ip)
    r=Renewal()
    def rollback():
        if not a.backup or not re.fullmatch(r'/var/backups/neexitlag-certificates/\d{8}T\d{6}Z-[a-f0-9]{8}',a.backup): raise RuntimeError('INVALID_BACKUP_PATH')
        r.restore(a.backup,a.automatic);print('SERVER_CERT_ROLLED_BACK')
    if a.force and a.confirm!='RENEW-SERVER-2.56.177.4': raise RuntimeError('EXPLICIT_RENEWAL_CONFIRMATION_REQUIRED')
    with transaction_lock():
        if a.mode=='rollback':
            rollback();return
        r.recover_pending(BACKUPS)
        due,expiry,ca_expiry,sans=r.preflight(dt.datetime.now(dt.timezone.utc),a.vps_ip,a.before_days,a.force)
        print('SERVER_CERT_STATUS leaf_not_after='+expiry.isoformat()+' ca_not_after='+ca_expiry.isoformat())
        if not due: return
        helper=Path(a.helper);st=helper.stat()
        if helper.is_symlink() or st.st_uid!=0 or st.st_mode&0o022: raise RuntimeError('TRUSTED_LOCAL_HELPER_REQUIRED')
        validate_helper(helper)
        for s in (*SERVICES,'neexitlag-echo'): command(['systemctl','is-active','--quiet',s])
        BACKUPS.mkdir(mode=0o700,parents=True,exist_ok=True)
        if BACKUPS.is_symlink() or BACKUPS.stat().st_mode&0o077: raise RuntimeError('UNSAFE_BACKUP_ROOT')
        directory=BACKUPS/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4))
        with tempfile.TemporaryDirectory(prefix='veliq-leaf-') as stage:
            diagnostics.step('LEAF_GENERATE')
            generated=Path(stage)/'tls';r.generate(generated,sans)
            def verify():
                context=ssl.create_default_context(cafile='/etc/neexitlag/control/ca.pem')
                until=time.monotonic()+30
                while True:
                    try:
                        with urllib.request.urlopen('https://127.0.0.1:8443/healthz',context=context,timeout=2) as response:
                            if response.status!=200: raise RuntimeError('CP_HEALTH_FAILED')
                        break
                    except Exception:
                        if time.monotonic()>=until: raise RuntimeError('CP_TLS_HEALTH_FAILED') from None
                        time.sleep(.25)
                try:
                    command([str(helper),'upgrade-local-probe','--vps-ip',a.vps_ip,'--journal',str(directory/'probe.id')])
                finally:
                    if (directory/'probe.id').exists():
                        command([str(helper),'upgrade-cleanup','--vps-ip',a.vps_ip,'--journal',str(directory/'probe.id')])
            diagnostics.step('LEAF_INSTALL_AND_PROVE')
            r.apply(directory,generated,verify)
        print('SERVER_CERT_RENEWAL_COMMITTED backup='+str(directory))

if __name__=='__main__':
    try: main()
    except BaseException as e:
        if isinstance(e,SystemExit): raise
        print('SERVER_CERT_RENEWAL_FAILED '+json.dumps(diagnostics.failure(e)),file=sys.stderr,flush=True);sys.exit(1)
