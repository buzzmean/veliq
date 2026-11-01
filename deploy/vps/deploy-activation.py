#!/usr/bin/env python3
"""Explicit existing-VPS activation release. Import is side-effect free.
Uses the proven fresh binary transaction; never restores DB security history.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import subprocess

import importlib.util as _diagnostic_import
try:
 import activation_diagnostics as diagnostics
except ModuleNotFoundError:
 _spec=_diagnostic_import.spec_from_file_location('activation_diagnostics',Path(__file__).with_name('activation-diagnostics.py'))
 diagnostics=_diagnostic_import.module_from_spec(_spec);_spec.loader.exec_module(diagnostics)
import tempfile

ROOT=Path('/var/backups/neexitlag-activation')
RECOVERY=Path('/etc/systemd/system/veliq-activation-recover.service')
MANAGED={
 'activation-diagnostics.py':'/opt/neexitlag/maintenance/activation-diagnostics.py',
 'renew-server-cert.py':'/opt/neexitlag/maintenance/renew-server-cert.py',
 'fresh-pc':'/opt/neexitlag/maintenance/veliq-fresh-helper',
 'codes':'/opt/neexitlag/maintenance/veliq-codes',
 'veliq-certificate-renewal.service':'/etc/systemd/system/veliq-certificate-renewal.service',
 'veliq-certificate-renewal.timer':'/etc/systemd/system/veliq-certificate-renewal.timer',
 '92-veliq-activation.conf':'/etc/systemd/system/neexitlag-control-plane.service.d/92-veliq-activation.conf',
}

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def save(path,state):
 tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(state));tmp.chmod(0o600)
 with tmp.open('rb') as f:os.fsync(f.fileno())
 os.replace(tmp,path)
 fd=os.open(path.parent,os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)

def guard():
 if os.geteuid()!=0 or os.uname().nodename.split('.')[0].lower()=='veliq-swe-01':raise RuntimeError('ROOT_REQUIRED_OR_EXCLUDED_HOST')
 diagnostics.require_vps_identity('/etc/neexitlag/public/relay.env')

def disarm(directory,run):
 timer='veliq-activation-rollback-'+Path(directory).name+'.timer'
 if run(['systemctl','show','--value','--property=LoadState',timer]).strip()!='not-found':run(['systemctl','stop',timer])

def restore(directory,automatic=False,boot=False):
 directory=Path(directory);state=json.loads((directory/'state.json').read_text())
 if automatic and state['phase']!='pending':return
 engine=module('activation_rollback_upgrade',directory/'fresh-vps-upgrade.py')
 leaf=module('activation_rollback_leaf',directory/'renew-server-cert.py')
 run=leaf.command
 if Path(MANAGED['veliq-certificate-renewal.timer']).exists():
  run(['systemctl','disable','veliq-certificate-renewal.timer']) if boot else run(['systemctl','disable','--now','veliq-certificate-renewal.timer'])
 # A renewal's independent watchdog must finish before restoring the outer leaf.
 if boot:
  if leaf.BACKUPS.exists():
   for p in leaf.BACKUPS.glob('*/transaction.json'):
    prior=json.loads(p.read_text())
    if prior['phase']=='pending':
     if (p.parent/'probe.id').exists():run(['/opt/neexitlag/maintenance/veliq-fresh-helper','upgrade-cleanup','--vps-ip','2.56.177.4','--journal',str(p.parent/'probe.id')])
     prior['phase']='rolled-back';save(p,prior)
 else:
  with leaf.transaction_lock():leaf.Renewal().recover_pending(leaf.BACKUPS)
  run(['systemctl','stop','neexitlag-control-plane','neexitlag-relay'])
 if str(RECOVERY) in state['files'] and RECOVERY.exists():run(['systemctl','disable',RECOVERY.name])
 for path,meta in state['files'].items():
  dest=Path(path)
  if meta is None:
   if dest.exists():dest.unlink()
  else:
   data=(directory/'saved'/meta['name']).read_bytes()
   if hashlib.sha256(data).hexdigest()!=meta['sha256']:raise RuntimeError('BACKUP_HASH_MISMATCH')
   leaf.atomic(dest,data,meta)
 run(['systemctl','daemon-reload'])
 if state.get('recovery_enabled'):run(['systemctl','enable',RECOVERY.name])
 if state.get('binary_id'):
  with engine.transaction_lock():engine.LocalUpgrade(engine.e.Host()).rollback(state['binary_id'],boot=boot)
 elif not boot:
  run(['systemctl','start','neexitlag-control-plane']);run(['systemctl','start','neexitlag-relay'])
 if state['timer_active']:run(['systemctl','enable','veliq-certificate-renewal.timer'] if boot else ['systemctl','enable','--now','veliq-certificate-renewal.timer'])
 state['phase']='rolled-back';save(directory/'state.json',state);disarm(directory,run)
 # No SQL restore: nonce, revocations, new devices and additive tables survive.


# Never print arbitrary exception/command text: even a bare word can be a secret.
# Allowlisted stderr fragments retain operational meaning without disclosing args.
def safe_stderr(raw):
    text = raw.decode('utf-8','replace') if isinstance(raw,bytes) else str(raw)
    fragments = []
    for needle,label in [('Permission denied','PERMISSION_DENIED'),('No such file or directory','FILE_NOT_FOUND'),('not found','NOT_FOUND'),('Connection refused','CONNECTION_REFUSED'),('timed out','TIMED_OUT'),('certificate has expired','CERTIFICATE_EXPIRED'),('certificate verify failed','CERTIFICATE_VERIFY_FAILED'),('No space left on device','NO_SPACE_LEFT'),('Read-only file system','READ_ONLY_FILESYSTEM')]:
        if needle.lower() in text.lower(): fragments.append(label)
    return '|'.join(fragments) if fragments else ('REDACTED_UNRECOGNIZED_STDERR' if text else 'EMPTY')

ERROR_CODES = {
 'Required command failed; private transaction log retained':'REQUIRED_COMMAND_FAILED',
 'Configuration owner/write permissions unsafe':'UNSAFE_CONFIGURATION_PERMISSIONS',
 'Private deployment file absent or world-accessible':'UNSAFE_PRIVATE_FILE',
 'Unexpected service identity':'UNEXPECTED_SERVICE_IDENTITY',
 'Running binary differs from installed file':'RUNNING_BINARY_MISMATCH',
 'pg_dump/server major mismatch':'POSTGRES_DUMP_VERSION_MISMATCH',
 'PostgreSQL major outside validated 14..17 range':'UNSUPPORTED_POSTGRES_VERSION',
 'Insufficient free space for persistent backup/atomic staging':'INSUFFICIENT_BACKUP_SPACE',
 'Managed path owner/write permissions unsafe':'UNSAFE_MANAGED_PATH',
 'Required preinstalled dependency missing':'MISSING_DEPENDENCY',
 'Candidate must be exact clean Linux build':'INVALID_CANDIDATE_BUILD',
 'Unknown service drop-in requires review':'UNREVIEWED_SERVICE_DROPIN',
 'Custom credential layout requires review':'UNREVIEWED_CREDENTIAL_LAYOUT',
 'Unsupported control-plane argument syntax':'UNSUPPORTED_CP_ARGUMENT',
 'Required command unavailable or timed out':'COMMAND_UNAVAILABLE_OR_TIMEOUT',
}
KNOWN_CODES = {'CURRENT_PROTOCOL_3_BASELINE_REQUIRED','SYSTEMD_LOADCREDENTIAL_REQUIRES_247','EXISTING_ECHO_CREDENTIAL_REQUIRED','PRIOR_ACTIVATION_DEPLOYMENT_PENDING','UNSAFE_BACKUP_ROOT','ROOT_ONLY_CA_KEY_REQUIRED','CA_RUNTIME_CREDENTIAL_MISMATCH','UNREVIEWED_FRESH_CA_DROPIN','UNSAFE_FRESH_CA_DROPIN','UNREVIEWED_ACTIVATION_DROPIN','UNREVIEWED_CREDENTIAL_EXEC_DROPIN','EXPLICIT_DEPLOYMENT_CONFIRMATION_REQUIRED','ROOT_REQUIRED_OR_EXCLUDED_HOST','VPS_IDENTITY_MISMATCH','LEAF_RENEWAL_FAILED','ACTIVATION_POLICY_NOT_READY','REQUIRED_SAN_MISSING','TLS_COPIES_MISMATCH','CA_RENEWAL_REQUIRED','EXACT_RELEASE_COMMIT_REQUIRED','PRIOR_PRODUCTION_UPGRADE_PENDING','BACKUP_HASH_MISMATCH','BACKUP_MANIFEST_INVALID','MANAGED_PATH_SYMLINK_REFUSED','UNSUPPORTED_SAN','SAN_CHANGED','CP_TLS_HEALTH_FAILED','LOCAL_UPGRADE_PROOF_FAILED_ROLLED_BACK'}
PROGRAMS = {'systemctl','systemd-run','runuser','openssl','pg_dump','pg_dumpall','psql','curl','ss','tar','python3','fresh-pc','veliq-fresh-helper','relay','control-plane'}

class Progress:
    def __init__(self):
        self.stage='ENTRY';self.backup=None;self.modified='NO';self.rollback='NOT_NEEDED'
    def step(self,name):
        self.stage=name
        diagnostics.step(name)
        print('ACTIVATION_DEPLOYMENT_STEP '+name,file=sys.stderr,flush=True)
    def failure(self,exc):
        text=str(exc)
        code=ERROR_CODES.get(text,text if text in KNOWN_CODES else 'SAFE_DEPLOYMENT_FAILED')
        if isinstance(exc,OSError):code={2:'FILE_NOT_FOUND',13:'PERMISSION_DENIED',28:'NO_SPACE_LEFT'}.get(exc.errno,'OS_OPERATION_FAILED')
        command=getattr(exc,'command','')
        if command not in PROGRAMS:command='NOT_REPORTED'
        exit_code=getattr(exc,'exit_code',getattr(exc,'returncode',None))
        if not isinstance(exit_code,int):exit_code=None
        return {'code':code,'stage':self.stage,'step':self.stage,'exception':type(exc).__name__ if type(exc).__name__ in ('RuntimeError','UpgradeError','PermissionError','FileNotFoundError','ValueError','TimeoutExpired','OSError','CalledProcessError') else 'OPERATION_ERROR','command':command,'exit_code':exit_code,'stderr':safe_stderr(getattr(exc,'command_stderr','')),'vps_modified':self.modified,'backup':self.backup,'rollback':self.rollback,'diagnostics':diagnostics.failure(exc,self.stage)}

PROGRESS=Progress()

def apply(stage,commit,confirm):
 PROGRESS.modified='NO';PROGRESS.backup=None;PROGRESS.rollback='NOT_NEEDED'
 PROGRESS.step('IDENTITY_AND_CONFIRMATION')
 guard()
 if confirm!='ACTIVATE-CODES-2.56.177.4':raise RuntimeError('EXPLICIT_DEPLOYMENT_CONFIRMATION_REQUIRED')
 stage=Path(stage)
 engine=module('activation_upgrade',stage/'fresh-vps-upgrade.py');engine.e.PROCESS_OBSERVER=diagnostics.emit_process;leaf=module('activation_leaf',stage/'renew-server-cert.py')
 PROGRESS.step('CURRENT_READ_ONLY_PREFLIGHT')
 report=engine.report(engine.e.Host());print('ACTIVATION_PREFLIGHT='+json.dumps(report),file=sys.stderr,flush=True)
 if not engine.compatible(report['capabilities']['relay'],'relay') or not engine.compatible(report['capabilities']['control-plane'],'control-plane'):
  raise RuntimeError('CURRENT_PROTOCOL_3_BASELINE_REQUIRED')
 # Migration 4 is additive; current control-plane applies it on startup.
 # Keep rejecting unreviewed future schemas before any deployment mutation.
 if report['applied_schema_version'] not in (1,2,3,4):raise RuntimeError('UNSUPPORTED_SCHEMA_VERSION')
 if report['systemd_version']<247:raise RuntimeError('SYSTEMD_LOADCREDENTIAL_REQUIRES_247')
 if not Path('/etc/neexitlag/echo/echo.token').is_file():raise RuntimeError('EXISTING_ECHO_CREDENTIAL_REQUIRED')
 # Read-only preflight verifies same CA/SAN/root key before any upgrade writes.
 PROGRESS.step('LEAF_READ_ONLY_PREFLIGHT')
 leaf.Renewal().preflight(dt.datetime.now(dt.timezone.utc),'2.56.177.4')
 # Crucially validate *all* binary/layout prerequisites before backup/units/stops.
 PROGRESS.step('CANDIDATE_READ_ONLY_PREFLIGHT')
 engine.prepare(stage/'bundle',stage/'fresh-pc',commit,'UPGRADE-VPS-2.56.177.4',force_update=True,validate_only=True)
 PROGRESS.step('HELPER_READ_ONLY_PREFLIGHT')
 leaf.validate_helper(stage/'fresh-pc')
 PROGRESS.step('OUTER_BACKUP')
 PROGRESS.modified='BACKUP_ONLY'
 ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 if ROOT.is_symlink() or ROOT.stat().st_mode&0o077:raise RuntimeError('UNSAFE_BACKUP_ROOT')
 for prior in ROOT.glob('*/state.json'):
  if json.loads(prior.read_text())['phase']=='pending':raise RuntimeError('PRIOR_ACTIVATION_DEPLOYMENT_PENDING')
 directory=ROOT/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4));directory.mkdir(mode=0o700)
 PROGRESS.backup=str(directory)
 print('ACTIVATION_DEPLOYMENT_BACKUP '+str(directory),file=sys.stderr,flush=True)
 (directory/'saved').mkdir(mode=0o700)
 # Permanent full configuration backup. Binary transaction separately pg_dumps
 # and saves all binaries/units before replacing anything.
 shutil.copytree('/etc/neexitlag',directory/'config')
 for name in ('inspect-activation.py','activation-diagnostics.py','deploy-activation.py','fresh-vps-upgrade.py','renew-server-cert.py'):
  shutil.copy2(stage/name,directory/name)
 shutil.copy2(stage/'production-engine.py',directory/'production-engine.py')
 run=leaf.command
 active=engine.e.Host().systemctl('is-enabled','veliq-certificate-renewal.timer',check=False)=='enabled'
 state={'phase':'pending','binary_id':'','files':{},'database_before':{'schema_version':report['applied_schema_version']},'database_rollback':'SECURITY_MONOTONIC_ADDITIVE_SCHEMA_PRESERVED','timer_active':active,'recovery_enabled':engine.e.Host().systemctl('is-enabled',RECOVERY.name,check=False)=='enabled'}
 for index,path in enumerate([*MANAGED.values(),str(RECOVERY),*[str(Path('/etc/neexitlag')/x) for x in leaf.FILES]]):
  p=Path(path)
  if p.is_symlink():raise RuntimeError('MANAGED_PATH_SYMLINK_REFUSED')
  meta=None
  if p.exists():
   st=p.stat();data=p.read_bytes();name=str(index);(directory/'saved'/name).write_bytes(data)
   meta={'name':name,'mode':st.st_mode&0o777,'uid':st.st_uid,'gid':st.st_gid,'sha256':hashlib.sha256(data).hexdigest()}
  state['files'][path]=meta
 save(directory/'state.json',state)
 recovery='[Unit]\nDescription=VELIQ activation release recovery\nAfter=postgresql.service\nRequires=postgresql.service\nBefore=neexitlag-control-plane.service neexitlag-relay.service\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 '+str(directory/'deploy-activation.py')+' rollback --backup '+str(directory)+' --automatic --boot\n[Install]\nWantedBy=multi-user.target\n'
 PROGRESS.step('ARM_RECOVERY')
 PROGRESS.modified='POSSIBLY'
 try:
  leaf.atomic(RECOVERY,recovery.encode(),{'mode':0o644,'uid':0,'gid':0})
  PROGRESS.modified='YES'
  run(['systemctl','daemon-reload']);run(['systemctl','enable',RECOVERY.name])
  unit='veliq-activation-rollback-'+directory.name
  run(['systemd-run','--unit='+unit,'--on-active=480','--timer-property=AccuracySec=1s','/usr/bin/python3',str(directory/'deploy-activation.py'),'rollback','--backup',str(directory),'--automatic'])
  PROGRESS.step('QUIESCE_RENEWAL_TIMER')
  if active:run(['systemctl','disable','--now','veliq-certificate-renewal.timer'])
  if Path(MANAGED['veliq-certificate-renewal.service']).exists():run(['systemctl','stop','veliq-certificate-renewal.service'])
  leaf.Renewal().recover_pending(leaf.BACKUPS)
  def record(summary):
   state['binary_id']=summary['id'];save(directory/'state.json',state)
  # Force current release even when old binaries already support /3.
  PROGRESS.step('BINARY_UPGRADE')
  result=engine.prepare(stage/'bundle',stage/'fresh-pc',commit,'UPGRADE-VPS-2.56.177.4',force_update=True,before_commit=record)
  print('ACTIVATION_BINARY_RESULT='+json.dumps(result),flush=True)
  run(['systemctl','disable','--now','veliq-certificate-renewal.timer']) if active else None
  PROGRESS.step('INSTALL_MAINTENANCE')
  for name,path in MANAGED.items():
   p=Path(path);p.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
   leaf.atomic(p,(stage/name).read_bytes(),{'mode':0o700 if name in ('fresh-pc','codes','renew-server-cert.py') else 0o644,'uid':0,'gid':0})
  leaf.BACKUPS.mkdir(mode=0o700,parents=True,exist_ok=True)
  PROGRESS.step('RESTART_CONTROL_PLANE')
  run(['systemctl','daemon-reload']);run(['systemctl','restart','neexitlag-control-plane'])
  # Leaf operation has its own durable backup and independent watchdog/proof.
  PROGRESS.step('RENEW_SERVER_LEAF')
  p=diagnostics.run_process(['/usr/bin/python3',MANAGED['renew-server-cert.py'],'run','--force','--confirm','RENEW-SERVER-2.56.177.4'],timeout=165,check=False)
  if p.returncode:
   error=RuntimeError('LEAF_RENEWAL_FAILED');error.exit_code=p.returncode;error.command='python3';error.command_stdout=p.stdout;error.command_stderr=p.stderr;error.child=diagnostics.process_report(['python3'],p.returncode,p.stdout,p.stderr)
   raise error
  PROGRESS.step('ENROLLMENT_POLICY_PROOF')
  import ssl,urllib.request
  context=ssl.create_default_context(cafile='/etc/neexitlag/control/ca.pem')
  with urllib.request.urlopen('https://127.0.0.1:8443/api/v1/enroll/policy',context=context,timeout=5) as response:
   policy=json.loads(response.read(65537))
  if policy.get('enrollment_ready') is not True:raise RuntimeError('ACTIVATION_POLICY_NOT_READY')
  PROGRESS.step('RENEWAL_SERVICE_PROOF')
  run(['systemctl','start','veliq-certificate-renewal.service'])
  PROGRESS.step('COMMIT_RELEASE')
  run(['systemctl','enable','--now','veliq-certificate-renewal.timer'])
  state['phase']='committed';save(directory/'state.json',state)
  disarm(directory,run)
  PROGRESS.modified='YES'
  print('ACTIVATION_DEPLOYMENT_COMMITTED backup='+str(directory),flush=True)
 except BaseException as failure:
  # Preserve the original stage/error even if rollback itself fails.
  original=PROGRESS.failure(failure)
  original_stage=PROGRESS.stage
  PROGRESS.step('ROLLBACK')
  try:
   restore(directory);PROGRESS.rollback='COMPLETE_SECURITY_STATE_PRESERVED'
  except BaseException as recovery:
   PROGRESS.rollback='FAILED'
   print('ACTIVATION_ROLLBACK_FAILED '+json.dumps(PROGRESS.failure(recovery)),file=sys.stderr,flush=True)
  PROGRESS.stage=original_stage
  original['rollback']=PROGRESS.rollback
  print('ACTIVATION_DEPLOYMENT_FAILURE_DETAIL '+json.dumps(original),file=sys.stderr,flush=True)
  raise

def final_snapshot(directory=None):
    try:
        base=Path(directory) if directory else Path(__file__).parent
        engine=module('final_fresh_snapshot',base/'fresh-vps-upgrade.py')
        audit=module('final_snapshot',base/'inspect-activation.py')
        return audit.inspect(engine,engine.e)
    except BaseException as exc:
        return {'state_observed':False,'reason':'FINAL_SNAPSHOT_FAILED','diagnostics':diagnostics.failure(exc,'FINAL_SNAPSHOT')}


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('apply','rollback'));p.add_argument('--stage');p.add_argument('--commit');p.add_argument('--confirm',default='');p.add_argument('--backup');p.add_argument('--automatic',action='store_true');p.add_argument('--boot',action='store_true');p.add_argument('--result-file');a=p.parse_args();os.umask(0o077);guard()
 if a.mode=='rollback':
  if not a.backup or not re.fullmatch(r'/var/backups/neexitlag-activation/\d{8}T\d{6}Z-[a-f0-9]{8}',a.backup):raise RuntimeError('INVALID_BACKUP_PATH')
  restore(a.backup,a.automatic,a.boot)
 else:
  if not a.stage or not re.fullmatch('[a-f0-9]{40}',a.commit or ''):raise RuntimeError('EXACT_RELEASE_COMMIT_REQUIRED')
  failure=None
  try:
   apply(a.stage,a.commit,a.confirm)
  except BaseException as exc:
   failure=PROGRESS.failure(exc);raise
  finally:
   result={'vps_modified':PROGRESS.modified,'rollback':PROGRESS.rollback,'backup':PROGRESS.backup,'stage':PROGRESS.stage,'database_policy':'SECURITY_MONOTONIC_NO_PG_RESTORE','failure':failure,'state':final_snapshot(a.stage)}
   print('ACTIVATION_FINAL_STATE '+json.dumps(result),flush=True)
   if a.result_file:save(Path(a.result_file),result)

if __name__=='__main__':
 try:main()
 except BaseException as exc:
  if isinstance(exc,SystemExit):raise
  print('ACTIVATION_DEPLOYMENT_FAILED '+json.dumps(PROGRESS.failure(exc)),file=sys.stderr,flush=True);sys.exit(1)
