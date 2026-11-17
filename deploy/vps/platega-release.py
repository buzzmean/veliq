#!/usr/bin/env python3
"""Narrow payment release for the existing API host. No secret values are printed.

prepare verifies a fresh dump by restoring into an isolated local database.
apply installs the supplied binary/plans and appends only -plans-file; Platega
stays disabled until the owner installs credentials. rollback restores files,
never a live database. Run as root on the already identified API host.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import time
import urllib.parse
import urllib.request

UNIT='neexitlag-control-plane.service'
BINARY=Path('/opt/neexitlag/bin/control-plane')
PLANS=Path('/etc/neexitlag/control/plans.platega.json')
DROPIN=Path('/etc/systemd/system/neexitlag-control-plane.service.d/96-platega-plans.conf')
BACKUPS=Path('/var/backups/veliq-platega')
EXPECTED_BINARY='e7f7128431ad62d7570ca22a71344d661ab6fb5561ab95a1bcc9db8e5750008f'

def run(args,**kwargs):
    r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs)
    if r.returncode: raise RuntimeError('COMMAND_FAILED_'+Path(args[0]).name)
    return r.stdout.decode().strip()
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(path,data):
    path.write_text(json.dumps(data,indent=2));path.chmod(0o600)
def current():
    pid=run(['systemctl','show',UNIT,'-p','MainPID','--value'])
    if not pid.isdigit() or pid=='0':raise RuntimeError('CONTROL_PLANE_NOT_RUNNING')
    args=Path('/proc/'+pid+'/cmdline').read_bytes().decode().rstrip('\0').split('\0')
    env=dict(x.split('=',1) for x in Path('/proc/'+pid+'/environ').read_bytes().decode().split('\0') if '=' in x)
    url=urllib.parse.urlparse(env['DATABASE_URL'])
    if url.hostname not in ('localhost','127.0.0.1',None):raise RuntimeError('DATABASE_NOT_LOCAL')
    database=url.path.lstrip('/')
    if not re.fullmatch('[A-Za-z0-9_]+',database):raise RuntimeError('DATABASE_NAME_INVALID')
    return args,database,str(url.port or 5432)
def sql(db,port,query):return run(['runuser','-u','postgres','--','psql','-X','-A','-t','-p',port,'-d',db,'-v','ON_ERROR_STOP=1','-c',query])
def protected(db,port):
    result={}
    for table,fields in {
      'subscriptions':'id,account_id,plan_id,kind,seats,paid_until,auto_renew,lifetime',
      'activation_slots':'*','account_device_bindings':'*',
    }.items():
        # Private values never leave PostgreSQL; only a sorted-state digest.
        result[table]=sql(db,port,f"SELECT count(*)||':'||md5(coalesce(string_agg(row_to_json(t)::text,E'\\n' ORDER BY row_to_json(t)::text),'')) FROM (SELECT {fields} FROM {table}) t")
    return result
def health(args):
    ca=args[args.index('-ca')+1]
    context=ssl.create_default_context(cafile=ca)
    for attempt in range(15):
        try:
            with urllib.request.urlopen('https://146.0.77.98:8443/healthz',context=context,timeout=3) as r:
                if r.status==200:return
        except (OSError,urllib.error.URLError):pass
        time.sleep(1)
    raise RuntimeError('HEALTH_FAILED')
def backup_path(value):
    path=Path(value).resolve()
    if path.parent!=BACKUPS.resolve() or not re.fullmatch(r'\d{8}T\d{6}Z',path.name):raise RuntimeError('BACKUP_PATH_INVALID')
    return path
def prepare():
    args,db,port=current()
    if digest(BINARY)!=EXPECTED_BINARY:raise RuntimeError('BASELINE_BINARY_CHANGED')
    if any(x.startswith('-platega') or x.startswith('-plans-file') for x in args):raise RuntimeError('PAYMENT_CONFIGURATION_ALREADY_CHANGED')
    if sql(db,port,'SELECT max(version) FROM schema_migrations')!='6':raise RuntimeError('EXPECTED_SCHEMA_6')
    if sql(db,port,"SELECT count(*) FROM subscriptions WHERE NOT lifetime AND plan_id NOT IN ('player-month','club-month')")!='0':raise RuntimeError('UNKNOWN_FINITE_PLAN_IDS')
    if shutil.disk_usage('/var/backups').free<1024**3:raise RuntimeError('INSUFFICIENT_BACKUP_SPACE')
    health(args)
    BACKUPS.mkdir(mode=0o700,exist_ok=True)
    path=BACKUPS/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');path.mkdir(mode=0o700)
    files={}
    for target in [BINARY,PLANS,DROPIN]:
        if target.exists():
            name='before-'+target.name;shutil.copy2(target,path/name);files[str(target)]=dict(name=name,sha256=digest(path/name))
        else:files[str(target)]=None
    # Keep the full unit privately for review, but do not rewrite unrelated drop-ins.
    unit=run(['systemctl','cat',UNIT]);(path/'unit.before').write_text(unit);(path/'unit.before').chmod(0o600)
    dump=path/'database.dump'
    with dump.open('wb') as out:
        r=subprocess.run(['runuser','-u','postgres','--','pg_dump','-p',port,'-Fc',db],stdout=out,stderr=subprocess.PIPE)
    dump.chmod(0o600)
    if r.returncode:raise RuntimeError('BACKUP_FAILED')
    run(['pg_restore','--list',str(dump)])
    restore='veliq_payment_restore_'+path.name.lower()
    sql('postgres',port,'CREATE DATABASE '+restore)
    try:
        with dump.open('rb') as source:
            run(['runuser','-u','postgres','--','pg_restore','-p',port,'--exit-on-error','--no-owner','--no-privileges','-d',restore],stdin=source)
        if sql(restore,port,'SELECT max(version) FROM schema_migrations')!='6':raise RuntimeError('RESTORE_SCHEMA_MISMATCH')
        restored=protected(restore,port)
    finally:sql('postgres',port,'DROP DATABASE '+restore)
    state=dict(phase='prepared',args=args,database=db,port=port,files=files,binary_before=EXPECTED_BINARY,
               unit_sha256=hashlib.sha256(unit.encode()).hexdigest(),dump_sha256=digest(dump),restore_verified=True,protected=restored)
    save(path/'state.json',state)
    print(json.dumps(dict(backup=str(path),restore_verified=True,schema=6,binary_sha256=EXPECTED_BINARY)))
def rollback(path):
    state=json.loads((path/'state.json').read_text())
    for target,info in state['files'].items():
        dest=Path(target)
        if info:
            if digest(path/info['name'])!=info['sha256']:raise RuntimeError('BACKUP_HASH_MISMATCH')
            shutil.copy2(path/info['name'],dest)
        elif dest.exists():dest.unlink()
    run(['systemctl','daemon-reload']);run(['systemctl','restart',UNIT]);health(state['args'])
    state['phase']='rolled-back';save(path/'state.json',state)
    print(json.dumps(dict(status='rolled-back',database_restored=False)))
def quote(arg):
    if '\n' in arg or '\r' in arg:raise RuntimeError('INVALID_UNIT_ARGUMENT')
    return '"'+arg.replace('\\','\\\\').replace('"','\\"').replace('%','%%').replace('$','$$')+'"'
def apply(path,binary,plans,sha):
    state=json.loads((path/'state.json').read_text());args,db,port=current()
    if state['phase']!='prepared' or not state['restore_verified'] or digest(path/'database.dump')!=state['dump_sha256']:raise RuntimeError('BACKUP_NOT_READY')
    if digest(binary)!=sha or digest(BINARY)!=state['binary_before'] or args!=state['args']:raise RuntimeError('BINARY_OR_ARGUMENTS_CHANGED')
    if hashlib.sha256(run(['systemctl','cat',UNIT]).encode()).hexdigest()!=state['unit_sha256']:raise RuntimeError('UNIT_CHANGED')
    if protected(db,port)!=state['protected']:raise RuntimeError('SUBSCRIPTIONS_CHANGED_SINCE_BACKUP')
    expected=json.loads(plans.read_text())
    if {x['id']:(x['price_per_seat_rub'],x['period_days']) for x in expected}!={'player-month':(399,30),'club-month':(199,30)}:raise RuntimeError('PLAN_POLICY_MISMATCH')
    state['phase']='pending';save(path/'state.json',state)
    timer='veliq-platega-rollback-'+path.name.lower()
    run(['systemd-run','--quiet','--unit='+timer,'--on-active=5m','/usr/bin/python3',str(Path(__file__).resolve()),'recover','--backup',str(path)])
    try:
        shutil.copyfile(plans,PLANS);PLANS.chmod(0o644)
        DROPIN.parent.mkdir(exist_ok=True)
        DROPIN.write_text('[Service]\nExecStart=\nExecStart='+' '.join(quote(x) for x in args+['-plans-file',str(PLANS)])+'\n')
        DROPIN.chmod(0o644)
        staged=BINARY.with_name('control-plane.platega-new');shutil.copyfile(binary,staged);staged.chmod(0o755);os.replace(staged,BINARY)
        run(['systemctl','daemon-reload']);run(['systemctl','restart',UNIT]);health(args)
        if sql(db,port,'SELECT max(version) FROM schema_migrations')!='7':raise RuntimeError('SCHEMA_7_MISSING')
        if protected(db,port)!=state['protected']:raise RuntimeError('PROTECTED_STATE_CHANGED')
        state.update(phase='applied-disabled',binary_after=sha,protected_after=protected(db,port));save(path/'state.json',state)
        run(['systemctl','stop',timer+'.timer'])
        print(json.dumps(dict(status='applied-disabled',schema=7,protected_unchanged=True,binary_sha256=sha)))
    except BaseException:
        rollback(path)
        raise
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['prepare','apply','rollback','recover']);parser.add_argument('--backup');parser.add_argument('--binary',type=Path);parser.add_argument('--plans',type=Path);parser.add_argument('--sha256');a=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('ROOT_REQUIRED')
    if a.mode=='prepare':prepare()
    elif a.mode=='recover':
        path=backup_path(a.backup)
        if json.loads((path/'state.json').read_text())['phase']=='pending':rollback(path)
    elif a.mode=='rollback':rollback(backup_path(a.backup))
    else:apply(backup_path(a.backup),a.binary,a.plans,a.sha256)
