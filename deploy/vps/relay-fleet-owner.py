#!/usr/bin/env python3
"""Owner workstation orchestrator. Never print private RPC responses/artifacts."""
import argparse
import base64
import hashlib
import json
import ipaddress
import re
import threading
from pathlib import Path
import shlex
import subprocess
import sys
import time

class RPCError(RuntimeError):
    pass

class Remote:
    def __init__(self, host, role, key, source):
        bootstrap = "import base64,sys;ROLE=sys.argv[1];HOST_IP=sys.argv[2];exec(compile(base64.b64decode(sys.stdin.buffer.readline()),'relay-fleet-remote.py','exec'))"
        remote = 'python3 -u -c '+shlex.quote(bootstrap)+' '+role+' '+host
        self.process = subprocess.Popen(['ssh','-T','-F','none','-i',str(key),
              '-o','StrictHostKeyChecking=accept-new','-o','ConnectTimeout=15',
              '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3',
              'root@'+host,remote],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
        self.process.stdin.write(base64.b64encode(source)+b'\n');self.process.stdin.flush()

    def call(self, op, **data):
        p=self.process
        payload=json.dumps(dict(data,op=op),ensure_ascii=True).encode()+b'\n'
        if len(payload)>100*1024*1024:raise RPCError('BOUNDED_REQUEST_EXCEEDED')
        p.stdin.write(payload);p.stdin.flush()
        timer=threading.Timer(210 if op=='install' else 90,p.kill);timer.start()
        try:line=p.stdout.readline(100*1024*1024+1)
        finally:timer.cancel()
        if not line or len(line)>100*1024*1024:
            raise RPCError('SSH_RESPONSE_MISSING_OR_TOO_LARGE')
        reply=json.loads(line)
        if not reply.get('ok'):
            # Only fixed diagnostic keys; never include result/private bundles.
            safe={k:reply.get(k) for k in ('step','code','class','program','exit_code','diagnostic')}
            raise RPCError(json.dumps(safe))
        return reply['result']

    def close(self):
        p=self.process
        try:
            p.stdin.close();p.wait(timeout=10)
        except (OSError,subprocess.TimeoutExpired):
            p.kill();p.wait(timeout=10)
        p.stdout.close()

def item(path):
    b=path.read_bytes()
    if path.suffix in ('.sh','.py','.service'):b=b.decode('utf-8-sig').replace('\r\n','\n').encode()
    if len(b)>40*1024*1024:raise RuntimeError('ARTIFACT_TOO_LARGE')
    return {'data':base64.b64encode(b).decode(),'sha256':hashlib.sha256(b).hexdigest()}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host',required=True);p.add_argument('--name',required=True)
    p.add_argument('--key',required=True);p.add_argument('--bin',required=True)
    p.add_argument('--manifest',required=True);p.add_argument('--promote',action='store_true')
    p.add_argument('--rollback',action='store_true');p.add_argument('--inspect',action='store_true')
    a=p.parse_args()
    if not ipaddress.IPv4Address(a.host).is_global or a.host=='2.56.177.4' or not re.fullmatch('[A-Za-z0-9_-]{1,64}',a.name) or not Path(a.key).is_file():raise RuntimeError('OWNER_ARGUMENTS_INVALID')
    root=Path(__file__).resolve().parents[2];binary=Path(a.bin)
    source=(root/'deploy/vps/relay-fleet-remote.py').read_bytes()
    ident='VPS-PRIMARY' if a.promote else a.name;address=a.host+':4433'
    files={n:item(binary/n if n in ('relay','relay-admin') else root/'deploy/vps'/n)
           for n in ('relay','relay-admin','relay-install.sh','relay-start.sh','neexitlag-relay.service','update.sh','validate-env.py')}
    control=None;new=None;prepared=False;was_committed=False;step='SSH_PREFLIGHT'
    try:
        control=Remote('2.56.177.4','control',Path(a.key),source)
        print(json.dumps({'stage':step,'control':control.call('preflight')}),flush=True)
        if a.inspect:
            print(json.dumps({'stage':'READ_ONLY_REGISTRY','state':control.call('inspect_standalone',id=ident,address=address,helper=files['relay-admin'])}));return 0
        legacy=control.call('inspect_standalone',id='VPS-01',address='2.56.177.4:4433',helper=files['relay-admin'])
        if not legacy.get('exists') or legacy['relay'].get('address')!='2.56.177.4:4433':raise RPCError('ORIGINAL_VPS01_NOT_AT_EXPECTED_STANDBY_REVIEW_REQUIRED')
        control.call('init',id=ident,address=address,files={'relay-admin':files['relay-admin']},source=base64.b64encode(source).decode())
        if a.rollback:
            print(json.dumps({'stage':'ROLLBACK','state':control.call('rollback')}));return 0
        new=Remote(a.host,'relay',Path(a.key),source)
        print(json.dumps({'stage':step,'relay':new.call('preflight')}),flush=True)
        step='NEW_SERVER_KEY';new.call('init',id=ident,address=address,files={k:v for k,v in files.items() if k!='relay-admin'})
        csr=new.call('keys')['csr']
        step='SIGN_SERVER_CSR';bundle=control.call('prepare',csr=csr,name=a.name)
        was_committed=bundle['phase']=='committed';prepared=True
        step='RELAY_INSTALL';print(json.dumps({'stage':step,'result':new.call('install',bundle=bundle)}),flush=True)
        step='CLIENT_QUIC_TLS_HTTP_UDP_PROOF'
        probe=subprocess.run([str(binary/'relay-client.exe'),'--mode','probe','--manifest',a.manifest,
                              '--relay-id',ident,'--address',address],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=95)
        if probe.returncode:
            reason=probe.stderr.decode('utf-8','replace').strip()
            if not reason or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_\r\n' for c in reason):reason='PROOF_FAILED'
            raise RPCError(reason)
        proof=json.loads(probe.stdout)
        if proof.get('pass') is not True:raise RPCError('PROOF_NOT_PASS')
        print(json.dumps({'stage':step,'proof':proof}),flush=True)
        step='SIGNED_REGISTRY_PUBLICATION';print(json.dumps({'stage':step,'state':control.call('publish')}),flush=True)
        step='FRESH_HEARTBEAT'
        until=time.monotonic()+90
        while time.monotonic()<until:
            h=control.call('heartbeat')
            if h.get('healthy') and h.get('fresh'):break
            time.sleep(1)
        else:raise RPCError('NEW_RELAY_HEARTBEAT_NOT_OBSERVED')
        step='FINALIZE';done=control.call('finalize')
        print(json.dumps({'pass':True,'stage':step,'relay_id':ident,'address':address,
                          'state':done,'clients':'new connections use published endpoint after signed config refresh; established TCP stays pinned',
                          'legacy':'2.56.177.4:4433 retained as VPS-01 with independent ticket audience; updated client chooses primary for new relay opens; existing streams stay pinned'}),flush=True)
        return 0
    except BaseException as e:
        rollback='NOT_REQUESTED';details=None
        if prepared and not was_committed and control:
            try:
                observed=control.call('inspect')
                if observed.get('phase')=='committed':
                    details=observed;rollback='ALREADY_COMMITTED; RERUN_TO_DISARM_TIMER'
                else:
                    details=control.call('rollback');rollback='REGISTRY_RESTORED_SECURITY_PRESERVED'
            except BaseException:rollback='ACK_UNAVAILABLE; independent timer/journal must be checked'
        # RPCError contains only allowlisted codes; never stringify arbitrary errors.
        diagnostic=str(e) if isinstance(e,RPCError) else type(e).__name__
        print(json.dumps({'pass':False,'stage':step,'diagnostic':diagnostic,'rollback':rollback,'state':details,
                          'change_state':'SEE_ACKNOWLEDGED_STEPS; transport loss can leave a pending timer',
                          'journal':'/var/lib/veliq-relay-fleet/job-'+ident+'.json',
                          'new_host':'relay files/service may remain installed; registry rollback does not delete its private key or reboot/restart old VPS services'}),file=sys.stderr,flush=True)
        return 1
    finally:
        for r in (new,control):
            if r:
                try:r.close()
                except BaseException:pass

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as e:
        print(json.dumps({'pass':False,'stage':'LOCAL_ARTIFACTS_OR_ARGUMENTS','class':type(e).__name__}),file=sys.stderr);sys.exit(1)
