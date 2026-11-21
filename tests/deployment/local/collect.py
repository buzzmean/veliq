"""Public local-acceptance report; no private logs/dumps/keys are exported."""
import json
from pathlib import Path
import re
import subprocess
import sys

def query(args):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
    return p.returncode,p.stdout.decode('utf-8','replace').strip()

commit,layout,exit_code=sys.argv[1:]
result={'commit':commit,'layout':layout,'exit_code':int(exit_code),'pass':exit_code=='0','runtime':'offline Docker, real systemd, Debian 13'}
result['systemd_version']=query(['systemctl','--version'])[1].splitlines()[:1]
result['postgres_version']=query(['pg_config','--version'])[1]
units={}
for unit in ('neexitlag-control-plane','neexitlag-relay','veliq-certificate-renewal','veliq-certificate-renewal.timer'):
    units[unit]=query(['systemctl','show',unit,'--property=ActiveState,LoadState,Result,ExecMainStatus'])[1].splitlines()
result['units']=units
result['database']={}
for key,sql in [('schema','SELECT coalesce(max(version),0) FROM schema_migrations'),('revoked','SELECT count(*) FROM devices WHERE revoked'),('active_probes',"SELECT count(*) FROM devices WHERE name='CA rotation health probe' AND NOT revoked")]:
    code,value=query(['runuser','-u','postgres','--','psql','-XAt','-d','neexitlag','-c',sql])
    result['database'][key]=int(value) if code==0 and value.isdigit() else 'UNAVAILABLE'
proof=Path('/var/tmp/neexitlag-upgrade-private/activation-proof.json')
if proof.exists():
    data=json.loads(proof.read_text());result['activation_proof']={key:data.get(key) for key in ('pass','schema','renewal_service','temporary_identities_revoked','rollback_injection','ca_unchanged')}
traces=[]
for file in ('/var/tmp/veliq-local-run.log','/var/tmp/neexitlag-upgrade-private/activation.log'):
    p=Path(file)
    if not p.exists():continue
    for line in p.read_text(errors='replace')[-65536:].splitlines():
        # File names/line numbers only; source lines and arbitrary exception text
        # may contain fixture secrets and deliberately never leave the container.
        match=re.search(r'File "[^\"]*/([A-Za-z0-9_-]+\.py)", line ([0-9]+)',line)
        if match:traces.append({'file':match[1],'line':int(match[2])})
        for name in ('RuntimeError','UpgradeError','AssertionError','PermissionError','FileNotFoundError','ImportError'):
            if line.startswith(name+':') or line==name:traces.append({'exception':name})
result['traces']=traces[-20:]
# Log messages stay private. Only reviewed error categories leave the container.
import importlib.util
spec=importlib.util.spec_from_file_location('safe_diagnostics',Path('/src/deploy/vps/activation-diagnostics.py'))
diag=importlib.util.module_from_spec(spec);spec.loader.exec_module(diag)
_,journal=query(['journalctl','-u','neexitlag-control-plane','-n','10','--no-pager','-o','cat'])
result['control_plane_log_summary']=diag.safe_stream(journal)

print(json.dumps(result,sort_keys=True,indent=2))
