#!/usr/bin/env python3
"""Owner host-verified SSH entry. Stdout is a private protocol response, not log."""
import base64
import hashlib
import fcntl
import importlib.util
import json
import os
import re
import ssl
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types


def artifact(item):
    value = base64.b64decode(item['data'], validate=True)
    if len(value) > 32 * 1024 * 1024 or hashlib.sha256(value).hexdigest() != item['sha256']:
        raise RuntimeError('ARTIFACT_HASH_OR_SIZE_MISMATCH')
    return value


def require_current_capabilities():
    for role in ('control-plane','relay'):
        out = subprocess.run(['/opt/neexitlag/bin/'+role,'-version-json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)
        info=json.loads(out.stdout)
        if info.get('role')!=role or info.get('max_config_bytes',0)<1048576 or info.get('full_revocations') is not True:
            raise RuntimeError('EXISTING_FULL_REVOCATION_SUPPORT_REQUIRED')
        if role=='relay' and ('neexitlag/3' not in info.get('protocols',[]) or info.get('default_lease_seconds')!=1800):
            raise RuntimeError('EXISTING_PROTOCOL_3_REQUIRED')


def main():
    if os.geteuid()!=0 or os.uname().nodename.split('.')[0].lower()=='veliq-swe-01':
        raise RuntimeError('ROOT_REQUIRED_OR_EXCLUDED_HOST')
    raw=sys.stdin.buffer.read(160*1024*1024+1)
    if len(raw)>160*1024*1024: raise RuntimeError('BOUNDED_REQUEST_EXCEEDED')
    p=json.loads(raw)
    if p['vps_ip']!='2.56.177.4' or 'VPS_PUBLIC_IP='+p['vps_ip'] not in Path('/etc/neexitlag/public/relay.env').read_text().splitlines():
        raise RuntimeError('EXISTING_VPS_IDENTITY_MISMATCH')
    preflight=p.get('preflight_only') is True
    upgrade=p.get('upgrade') is True
    if preflight and (upgrade or p['rotate']): raise RuntimeError('READONLY_MODE_CONFLICT')
    if upgrade and p.get('upgrade_confirm')!='UPGRADE-VPS-2.56.177.4': raise RuntimeError('EXPLICIT_UPGRADE_CONFIRMATION_REQUIRED')
    if p['rotate'] and p['confirm']!='ROTATE-CA-2.56.177.4': raise RuntimeError('EXPLICIT_CA_ROTATION_CONFIRMATION_REQUIRED')
    if preflight:
        engine=types.ModuleType('readonly_upgrade_engine');engine.__file__='<readonly-engine>'
        exec(compile(artifact(p['upgrade_engine']),engine.__file__,'exec'),engine.__dict__)
        report=types.ModuleType('readonly_upgrade_report');report.__file__='<readonly-report>'
        report.__dict__['_FRESH_ENGINE']=engine
        exec(compile(artifact(p['upgrade_script']),report.__file__,'exec'),report.__dict__)
        print(json.dumps(report.report(engine.Host())));return
    helper=artifact({'data':p['helper'],'sha256':p['helper_sha256']})
    # No permanent lock/state directory for the read-only report. Transport
    # staging is ephemeral root-only /var/tmp, never /etc or application state.
    lock=None
    if not preflight:
        lock_dir=Path('/run/neexitlag-fresh')
        lock_dir.mkdir(mode=0o700,exist_ok=True)
        if lock_dir.is_symlink() or lock_dir.stat().st_uid!=0 or lock_dir.stat().st_mode&0o077: raise RuntimeError('UNSAFE_LOCK_DIRECTORY')
        fd=os.open(lock_dir/'enrollment.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        lock=os.fdopen(fd,'a');fcntl.flock(lock,fcntl.LOCK_EX)
    try:
        with tempfile.TemporaryDirectory(prefix='veliq-fresh-',dir='/var/tmp') as tmp:
            stage=Path(tmp);tool=stage/'fresh-pc';tool.write_bytes(helper);tool.chmod(0o700)
            if preflight or upgrade:
                script=stage/'fresh-vps-upgrade.py';script.write_bytes(artifact(p['upgrade_script']))
                engine=stage/'production-engine.py';engine.write_bytes(artifact(p['upgrade_engine']))
                bundle=stage/'bundle';(bundle/'bin').mkdir(parents=True);(bundle/'deploy/vps').mkdir(parents=True)
                shutil.copy2(engine,bundle/'deploy/vps/production-upgrade.py')
                for role in ('relay','control-plane'):
                    binary=bundle/'bin'/role;binary.write_bytes(artifact(p['binaries'][role]));binary.chmod(0o700)
                spec=importlib.util.spec_from_file_location('fresh_vps_prepare',script)
                module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                result=module.prepare(bundle,tool,p['commit'],p.get('upgrade_confirm',''),preflight)
                if preflight:
                    print(json.dumps(result));return
                print('VPS_PREPARE_RESULT='+json.dumps(result),file=sys.stderr,flush=True)
            require_current_capabilities() # includes correct default_lease_seconds field
            if p['rotate']:
                migration=stage/'rotate.py';migration.write_bytes(base64.b64decode(p['migration'],validate=True))
                current=hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path('/etc/neexitlag/control/ca.pem').read_text())).hexdigest()
                subprocess.run(['/usr/bin/python3',str(migration),'apply','--confirm',p['confirm'],'--expected-current-ca-sha256',p['expected_ca'] or current,'--helper',str(tool),'--helper-sha256',p['helper_sha256']],check=True,stdout=sys.stderr)
            current=hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path('/etc/neexitlag/control/ca.pem').read_text())).hexdigest()
            subprocess.run([str(tool),'serve','--vps-ip',p['vps_ip'],'--ca-sha256',p['enrollment_ca'] or current],input=json.dumps(p['request']).encode(),check=True)
    finally:
        if lock is not None: lock.close()

if __name__=='__main__':
    try: main()
    except BaseException as exc:
        code=str(exc).split(':',1)[0] if type(exc) is RuntimeError or type(exc).__name__=='UpgradeError' else ''
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{1,95}',code): code=type(exc).__name__
        print('FRESH_SSH_FAILED: '+code,file=sys.stderr);sys.exit(1)
