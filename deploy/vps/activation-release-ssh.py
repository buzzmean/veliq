#!/usr/bin/env python3
"""Host-verified SSH stdin artifact transport; no enrollment and no CA rotation."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import importlib.util as _diagnostic_import
try:
 import activation_diagnostics as diagnostics
except ModuleNotFoundError:
 _spec=_diagnostic_import.spec_from_file_location('activation_diagnostics',Path(__file__).with_name('activation-diagnostics.py'))
 diagnostics=_diagnostic_import.module_from_spec(_spec);_spec.loader.exec_module(diagnostics)
import sys
import tempfile

STAGE='ENTRY'
NAMES={'deploy-activation.py','fresh-vps-upgrade.py','production-engine.py','renew-server-cert.py','fresh-pc','codes','relay','control-plane','veliq-certificate-renewal.service','veliq-certificate-renewal.timer','92-veliq-activation.conf','activation-diagnostics.py','inspect-activation.py'}
def decode(item):
 raw=base64.b64decode(item['data'],validate=True)
 if len(raw)>32*1024*1024 or hashlib.sha256(raw).hexdigest()!=item['sha256']:raise RuntimeError('ARTIFACT_HASH_OR_SIZE_MISMATCH')
 return raw

def main():
 global STAGE
 STAGE='REMOTE_IDENTITY'
 if os.geteuid()!=0 or os.uname().nodename.split('.')[0].lower()=='veliq-swe-01':raise RuntimeError('ROOT_REQUIRED_OR_EXCLUDED_HOST')
 diagnostics.require_vps_identity('/etc/neexitlag/public/relay.env')
 raw=sys.stdin.buffer.read(160*1024*1024+1)
 if len(raw)>160*1024*1024:raise RuntimeError('BOUNDED_REQUEST_EXCEEDED')
 STAGE='ARTIFACT_MANIFEST'
 p=json.loads(raw)
 if set(p['files'])!=NAMES or not re.fullmatch('[a-f0-9]{40}',p['commit']):raise RuntimeError('RELEASE_MANIFEST_INVALID')
 if p['confirm']!='ACTIVATE-CODES-2.56.177.4':raise RuntimeError('EXPLICIT_DEPLOYMENT_CONFIRMATION_REQUIRED')
 lock=os.open('/run/veliq-activation-release.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 with os.fdopen(lock,'a') as f:
  fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  with tempfile.TemporaryDirectory(prefix='veliq-activation-',dir='/var/tmp') as tmp:
   stage=Path(tmp)
   STAGE='ARTIFACT_HASH_VERIFICATION'
   for name,item in p['files'].items():
    dest=stage/name;dest.write_bytes(decode(item));dest.chmod(0o700)
   bundle=stage/'bundle';(bundle/'bin').mkdir(parents=True);(bundle/'deploy/vps').mkdir(parents=True)
   import shutil
   for role in ('relay','control-plane'):shutil.copy2(stage/role,bundle/'bin'/role)
   shutil.copy2(stage/'production-engine.py',bundle/'deploy/vps/production-upgrade.py')
   STAGE='DEPLOYMENT_PROCESS'
   outcome=stage/'outcome.json'
   result=None
   try:
    result=diagnostics.run_process(['/usr/bin/python3',str(stage/'deploy-activation.py'),'apply','--stage',str(stage),'--commit',p['commit'],'--confirm',p['confirm'],'--result-file',str(outcome)],check=False,timeout=570)
   finally:
    if outcome.exists():
     final=json.loads(outcome.read_text())
     print('ACTIVATION_FINAL_STATE '+json.dumps(final),flush=True)
    else:
     print('ACTIVATION_FINAL_STATE '+json.dumps({'vps_modified':'UNVERIFIED','reason':'CHILD_DID_NOT_PRODUCE_FINAL_SNAPSHOT','child_exit_code':result.returncode if result is not None else None}),flush=True)
   if result.returncode:
    print('ACTIVATION_RELEASE_PROCESS_EXIT '+json.dumps({'stage':STAGE,'exit_code':result.returncode,'vps_modified':'SEE_SAFE_DEPLOYMENT_REPORT_ABOVE'}),file=sys.stderr,flush=True)
    raise RuntimeError('ACTIVATION_RELEASE_FAILED_SEE_SAFE_CODE')

if __name__=='__main__':
 try:main()
 except BaseException as exc:
  if isinstance(exc,SystemExit):raise
  code=str(exc) if str(exc) in ('ROOT_REQUIRED_OR_EXCLUDED_HOST','VPS_IDENTITY_MISMATCH','BOUNDED_REQUEST_EXCEEDED','RELEASE_MANIFEST_INVALID','EXPLICIT_DEPLOYMENT_CONFIRMATION_REQUIRED','ARTIFACT_HASH_OR_SIZE_MISMATCH','ACTIVATION_RELEASE_FAILED_SEE_SAFE_CODE') else 'SAFE_RELEASE_FAILED'
  print('ACTIVATION_RELEASE_FAILED '+json.dumps({'code':code,'stage':STAGE,'exit_code':getattr(exc,'returncode',None),'vps_modified':'SEE_FINAL_STATE_ABOVE' if STAGE=='DEPLOYMENT_PROCESS' else 'NO','diagnostics':diagnostics.failure(exc,STAGE)}),file=sys.stderr);sys.exit(1)
