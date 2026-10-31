#!/usr/bin/env python3
"""Real activation/leaf acceptance, exclusively inside the disposable CI VM.
Never invoke as an owner operation. The shell fixture pins the VPS IP to lo;
all probes are kernel-local and no SSH/Internet calls are made.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import isolated_environment
isolated_environment.require()
root=Path('/var/tmp/neexitlag-upgrade-private')
if not root.is_dir() or not Path('/var/tmp/neexitlag-ci-bundle/server/ca.pem').is_file():raise SystemExit(91)
repo=Path.cwd()
def load(name):
    spec=importlib.util.spec_from_file_location(name,repo/'deploy/vps'/name)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
leaf=load('renew-server-cert.py');release=load('deploy-activation.py')
commit=isolated_environment.commit()
# All addresses remain loopback, including the public-only relay destination.
subprocess.run(['ip','addr','replace','2.56.177.4/32','dev','lo'],check=True)
Path('/etc/neexitlag/public/relay.env').write_text('VPS_PUBLIC_IP=2.56.177.4\n')
cert_stage=root/'fixture-cert';r=leaf.Renewal()
r.generate(cert_stage,tuple(sorted([('IP Address','127.0.0.1'),('IP Address','2.56.177.4')])))
for name in leaf.FILES:
    p=Path('/etc/neexitlag')/name;st=p.stat()
    leaf.atomic(p,(cert_stage/Path(name).name).read_bytes(),{'mode':st.st_mode&0o777,'uid':st.st_uid,'gid':st.st_gid})
leaf.command(['systemctl','restart','neexitlag-control-plane','neexitlag-relay'])
isolated_environment.wait_fixture_health(load('production-upgrade.py'))
# Apply from the owner's partially migrated schema 2, with all previous revoked
# fixtures and temporary rows intact. Exercise genuine cert backup/replace/probe.
stage=root/'activation';stage.mkdir()
for name in ('activation-diagnostics.py','inspect-activation.py','deploy-activation.py','fresh-vps-upgrade.py','renew-server-cert.py','veliq-certificate-renewal.service','veliq-certificate-renewal.timer','92-veliq-activation.conf'):
    shutil.copy2(repo/'deploy/vps'/name,stage/name)
shutil.copy2(repo/'deploy/vps/production-upgrade.py',stage/'production-engine.py')
for name in ('relay','control-plane','fresh-pc','codes'):
    shutil.copy2(repo/'dist/relay/bin'/name,stage/name)
(stage/'bundle/bin').mkdir(parents=True);(stage/'bundle/deploy/vps').mkdir(parents=True)
for name in ('relay','control-plane'):shutil.copy2(stage/name,stage/'bundle/bin'/name)
shutil.copy2(stage/'production-engine.py',stage/'bundle/deploy/vps/production-upgrade.py')
def sql(query):
    return subprocess.check_output(['runuser','-u','postgres','--','psql','-XAt','-d','neexitlag','-c',query],text=True).strip()
revoked_before=int(sql('SELECT count(*) FROM devices WHERE revoked'))
ca_before=Path('/etc/neexitlag/control/ca.pem').read_bytes()
# Inject a leaf verification failure AFTER the actual new leaf has been installed.
# The exception stays within this VM; no production failure-injection flag exists.
# The shipped subprocess path is tested
# by the normal apply below. Run actual leaf rollback separately, then full release.
leaf.BACKUPS.mkdir(mode=0o700,parents=True,exist_ok=True)
failed=leaf.BACKUPS/'20000101T000000Z-00000000'
generated=root/'failed-generated';r.generate(generated,leaf.certificate('/etc/neexitlag/control/server.pem')[1])
old_leaf=Path('/etc/neexitlag/control/server.pem').read_bytes()
try:r.apply(failed,generated,lambda:(_ for _ in ()).throw(RuntimeError('INJECTED_LEAF_PROOF_FAILURE')))
except RuntimeError as exc:assert str(exc)=='INJECTED_LEAF_PROOF_FAILURE'
else:raise AssertionError('injected leaf failure accepted')
assert Path('/etc/neexitlag/control/server.pem').read_bytes()==old_leaf
# Inject parent failure after a genuine leaf subprocess/proof succeeded; this
# exercises the FULL outer rollback, preserving new revoke/nonce/publications.
real_run=release.diagnostics.run_process
before_outer=Path('/etc/neexitlag/control/server.pem').read_bytes()
def fail_after_leaf(args,**kwargs):
    result=real_run(args,**kwargs)
    if len(args)>1 and str(args[1]).endswith('renew-server-cert.py'):
        assert result.returncode==0
        return SimpleNamespace(returncode=1,stdout=result.stdout,stderr=b'INJECTED_OUTER_FAILURE')
    return result
release.diagnostics.run_process=fail_after_leaf
try:
    try:release.apply(stage,commit,'ACTIVATE-CODES-2.56.177.4')
    except RuntimeError as exc:assert str(exc)=='LEAF_RENEWAL_FAILED'
    else:raise AssertionError('outer injection accepted')
finally:release.diagnostics.run_process=real_run
assert Path('/etc/neexitlag/control/server.pem').read_bytes()==before_outer
assert sql('SELECT max(version) FROM schema_migrations') in ('3','4')  # migration 4 is additive and may already be applied
assert sql("SELECT count(*) FROM devices WHERE name='CA rotation health probe' AND NOT revoked")=='0'
assert release.PROGRESS.rollback=='COMPLETE_SECURITY_STATE_PRESERVED'
release.apply(stage,commit,'ACTIVATE-CODES-2.56.177.4')
assert Path('/etc/neexitlag/control/ca.pem').read_bytes()==ca_before
assert int(sql('SELECT count(*) FROM devices WHERE revoked'))>=revoked_before+2
assert sql('SELECT max(version) FROM schema_migrations')=='4'
assert sql("SELECT count(*) FROM devices WHERE name='CA rotation health probe' AND NOT revoked")=='0'
for name in ('neexitlag-control-plane','neexitlag-relay','veliq-certificate-renewal.timer'):
    leaf.command(['systemctl','is-active','--quiet',name])
assert leaf.command(['systemctl','show','--value','--property=Result','veliq-certificate-renewal.service']).strip()=='success'
assert leaf.command(['systemctl','show','--value','--property=ExecMainStatus','veliq-certificate-renewal.service']).strip()=='0'
# Re-run from an already installed release (schema 3): idempotent preflight and
# real service due=false path, no forced user/device/certificate replacement.
leaf.command(['systemctl','start','veliq-certificate-renewal.service'])
leaf.validate_helper(stage/'fresh-pc')
assert sql("SELECT count(*) FROM devices WHERE name='CA rotation health probe' AND NOT revoked")=='0'
assert not leaf.command(['systemctl','list-units','--state=active','--no-legend','veliq-activation-rollback-*.timer','veliq-leaf-rollback-*.timer']).strip()
status=release.final_snapshot(stage)
assert status['certificates']['leaf_remaining_seconds']>29*86400
assert status['certificates']['leaf_matches_relay']
(root/'activation-proof.json').write_text(json.dumps({'pass':True,'schema':3,'renewal_service':'success','temporary_identities_revoked':True,'rollback_injection':True,'ca_unchanged':True}))
print('PASS isolated actual activation + leaf renewal + service sandbox + schema2 retry + revoked probes + no leftover active timers')
