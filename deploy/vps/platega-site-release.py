#!/usr/bin/env python3
"""Only account HTML/JS and the exact payment webhook location; guarded rollback."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import datetime

ROOT=Path('/var/lib/veliq-site-stage-20261103')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def command(args):
    r=subprocess.run(args,capture_output=True)
    if r.returncode:raise RuntimeError('COMMAND_FAILED_'+Path(args[0]).name)
def apply(payload):
    manifest=json.loads((payload/'site-manifest.json').read_text())
    files=[ROOT/'release/assets/account.js',ROOT/'release/account.html',ROOT/'nginx/account-server.conf',ROOT/'nginx/account-proxy.conf']
    for path in files:
        if digest(path)!=manifest[str(path)]:raise RuntimeError('SITE_CHANGED_SINCE_REVIEW')
    proxy=ROOT/'nginx/payment-proxy.conf'
    if proxy.exists():raise RuntimeError('PAYMENT_PROXY_ALREADY_EXISTS')
    backup=Path('/var/backups/veliq-platega-site')/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup.mkdir(parents=True,mode=0o700)
    state={}
    for path in files:
        shutil.copy2(path,backup/path.name);state[str(path)]=path.name
    (backup/'state.json').write_text(json.dumps(state));(backup/'state.json').chmod(0o600)
    # Preserve the verified TLS upstream. Callback requests do not use login limits.
    text=files[3].read_text()
    lines=[line for line in text.splitlines() if not line.strip().startswith(('limit_req ', 'proxy_set_header Cookie ', 'proxy_set_header Origin '))]
    callback='\n'.join(lines)+'\n'
    server=files[2].read_text()
    location='location = /api/v1/payments/webhook {\n    include '+str(proxy)+';\n}\n'
    try:
        proxy.write_text(callback)
        files[2].write_text(location+server)
        command(['nginx','-t'])
        for name,dest in [('account.js',files[0]),('account.html',files[1])]:
            tmp=dest.with_suffix(dest.suffix+'.payment-new');shutil.copyfile(payload/name,tmp);tmp.chmod(0o644);tmp.replace(dest)
        command(['systemctl','reload','nginx'])
        print(json.dumps(dict(backup=str(backup),status='published',hashes={str(p):digest(p) for p in files[:3]})))
    except BaseException:
        for path,name in state.items():shutil.copy2(backup/name,path)
        if proxy.exists():proxy.unlink()
        command(['nginx','-t']);command(['systemctl','reload','nginx'])
        raise
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('payload',type=Path);apply(parser.parse_args().payload)
