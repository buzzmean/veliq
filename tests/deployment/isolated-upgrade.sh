#!/usr/bin/env bash
# Disposable GitHub VM or explicitly isolated offline Docker ONLY. Never a VPS command.
set -euo pipefail
python3 tests/deployment/isolated_environment.py || exit 90
[[ ! -e /etc/neexitlag && ! -e /opt/neexitlag && -f /var/tmp/neexitlag-ci-bundle/server/ca.pem ]] || exit 91
repo=$PWD
bundle=$repo/dist/relay
fixture=/var/tmp/neexitlag-ci-bundle
umask 077
commit=$(python3 tests/deployment/isolated_environment.py --commit)
mkdir -m 0700 /var/tmp/neexitlag-upgrade-private
private=/var/tmp/neexitlag-upgrade-private
# Everything below is local to this throw-away runner, including test identities.
# CI runner ancestors are not a production layout. Harden only this throw-away VM.
for path in /opt /etc/systemd/system /var/backups /var/lib; do chown root:root "$path"; chmod go-w "$path"; done
systemctl start postgresql
for role in relay control echo; do
 useradd --system --user-group --home /var/lib/neexitlag --shell /usr/sbin/nologin "neexitlag-$role"
done
install -d -m 0755 /etc/neexitlag /etc/neexitlag/public /opt/neexitlag/bin
for role in relay control echo; do install -d -m 0750 -o root -g "neexitlag-$role" "/etc/neexitlag/$role"; done
for name in ca.pem ca.key server.pem server.key signing.key admin.token database.password heartbeat.token control-plane.env; do
 install -m 0640 -o root -g neexitlag-control "$fixture/server/$name" /etc/neexitlag/control/
done
for name in ca.pem server.pem server.key trust.json heartbeat.token; do install -m 0640 -o root -g neexitlag-relay "$fixture/server/$name" /etc/neexitlag/relay/; done
install -m 0640 -o root -g neexitlag-echo "$fixture/server/echo.token" /etc/neexitlag/echo/
printf 'VPS_PUBLIC_IP=127.0.0.1\n' > /etc/neexitlag/public/relay.env
chmod 0644 /etc/neexitlag/public/relay.env
for name in relay control-plane remote-echo; do install -m 0755 "$bundle/bin/$name" /opt/neexitlag/bin/; done
install -m 0755 deploy/vps/relay-start.sh /opt/neexitlag/bin/relay-start
install -m 0644 deploy/vps/neexitlag-{relay,control-plane,echo}.service /etc/systemd/system/
python3 deploy/vps/database-sql.py /etc/neexitlag/control/database.password > "$private/provision.sql"
# Directory is deliberately not made readable to postgres; pass SQL via stdin.
runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 < "$private/provision.sql" > "$private/postgres.log" 2>&1
if [[ ${NEEXITLAG_ISOLATED_CA_LAYOUT:-legacy} == fresh-credential ]]; then
 # Match the owner's migrated layout using ONLY this VM's disposable test CA.
 install -d -m 0755 /etc/systemd/system/neexitlag-control-plane.service.d
 python3 - <<'PYFIXTURE'
import importlib.util,pathlib
spec=importlib.util.spec_from_file_location('fixture_rotation','deploy/vps/rotate-fresh-pc-ca.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
u=pathlib.Path('/etc/systemd/system/neexitlag-control-plane.service')
pathlib.Path('/etc/systemd/system/neexitlag-control-plane.service.d/91-veliq-fresh-ca.conf').write_bytes(m.credential_dropin(u.read_text()))
PYFIXTURE
 chmod 0600 /etc/neexitlag/control/ca.key
fi
systemctl daemon-reload
systemctl start neexitlag-control-plane neexitlag-relay neexitlag-echo
for n in $(seq 1 30); do
 if curl --noproxy '*' --fail --silent --cacert /etc/neexitlag/control/ca.pem https://127.0.0.1:8443/healthz > /dev/null && curl --noproxy '*' --fail --silent http://127.0.0.1:9090/healthz > /dev/null; then break; fi
 sleep 1
done
"$bundle/bin/enroll" -control-plane https://127.0.0.1:8443 -state "$fixture/windows/device" -ca "$fixture/windows/trust/cp-ca.pem" -admin-token-file "$fixture/windows/admin.token" > "$private/enroll.log" 2>&1
runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -d neexitlag -c "INSERT INTO devices(id,user_id,name,public_key,revoked) SELECT 'revoked-device-' || lpad(n::text,5,'0'),'owner','fixture','fixture-public-'||n,true FROM generate_series(1,5000) n;" > "$private/seed.log" 2>&1
python3 - "$commit" "$private/inventory.json" <<'PY'
import datetime,json,sys
open(sys.argv[2],'w').write(json.dumps({'validated_commit':sys.argv[1], 'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'all_config_consumers_support_1mib':True, 'inventory_reference':'isolated CI VM, only candidate clients/relay; 5000 revoked fixtures'}))
PY
script=deploy/vps/production-upgrade.py
python3 "$script" preflight --bundle "$bundle" --expected-commit "$commit" --compatibility "$private/inventory.json" > "$private/preflight.json"
python3 "$script" apply --bundle "$bundle" --expected-commit "$commit" --compatibility "$private/inventory.json" > "$private/apply.json"
id=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$private/apply.json")
"$bundle/bin/neexitlag-route-test-linux-amd64" --upgrade-check --relay 127.0.0.1:4433 --target 127.0.0.1:40000 --tcp-target 127.0.0.1:40000 --control-plane https://127.0.0.1:8443 --state "$fixture/windows/device" --trust "$fixture/windows/trust/trust.json" --ca "$fixture/windows/trust/ca.pem" --cp-ca "$fixture/windows/trust/cp-ca.pem" --echo-token-file "$fixture/windows/echo.token" --expected-egress 127.0.0.1 --report "$private/proof.json" > "$private/probe.log" 2>&1
python3 "$script" commit --backup-id "$id" --probe-report "$private/proof.json"
# Validate the real custom-format dump by restoring into a NEW isolated DB.
runuser -u postgres -- createdb neexitlag_backup_verify
runuser -u postgres -- pg_restore --no-owner --dbname neexitlag_backup_verify < "/var/backups/neexitlag-upgrades/$id/database.dump" > "$private/restore.log" 2>&1
count=$(runuser -u postgres -- psql -XAt -d neexitlag_backup_verify -c 'SELECT count(*) FROM devices WHERE revoked')
[[ $count == 5000 ]]
# Exercise the real atomic-install failure path: candidate ELF with wrong role.
# It passes file integrity but installed capability validation must fail closed.
cp "$bundle/bin/relay" "$private/candidate-relay"
cp "$bundle/UPGRADE_MANIFEST.json" "$private/manifest.json"
cp "$bundle/bin/control-plane" "$bundle/bin/relay"
python3 - "$bundle" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1]);m=json.loads((p/'UPGRADE_MANIFEST.json').read_text());m['files']['bin/relay']=hashlib.sha256((p/'bin/relay').read_bytes()).hexdigest();(p/'UPGRADE_MANIFEST.json').write_text(json.dumps(m))
PY
if python3 "$script" apply --bundle "$bundle" --expected-commit "$commit" --compatibility "$private/inventory.json" > "$private/injected-failure.json"; then echo 'FAIL: bad installed role accepted'; exit 1; fi
pending=$(python3 -c 'import json;print(json.load(open("/var/lib/neexitlag-upgrade/pending.json"))["id"])')
python3 "$script" status --backup-id "$pending" > "$private/rollback-status.json"
python3 - "$private/rollback-status.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))['phase']=='rolled_back'
PY
systemctl is-active --quiet neexitlag-relay neexitlag-control-plane
[[ $(runuser -u postgres -- psql -XAt -d neexitlag -c 'SELECT count(*) FROM devices WHERE revoked') == 5000 ]]
cp "$private/candidate-relay" "$bundle/bin/relay"
cp "$private/manifest.json" "$bundle/UPGRADE_MANIFEST.json"
if [[ ${NEEXITLAG_ISOLATED_CA_LAYOUT:-legacy} == fresh-credential ]]; then
 [[ $(stat -c %a /etc/neexitlag/control/ca.key) == 600 ]]
 if runuser -u neexitlag-control -- test -r /etc/neexitlag/control/ca.key; then echo 'FAIL: root CA readable directly'; exit 1; fi
 cmp -s /etc/neexitlag/control/ca.key /run/credentials/neexitlag-control-plane.service/veliq-device-ca-key
fi
echo 'PASS: isolated real systemd + PostgreSQL, permanent dump restored into a separate DB, 5000 revocations >64 KiB, real /3 TCP/UDP two renewals, injected bad binary rolled back without reverting DB/replay.'

if [[ ${NEEXITLAG_ISOLATED_CA_LAYOUT:-legacy} == fresh-credential ]]; then
 python3 tests/deployment/isolated-activation.py > "$private/activation.log" 2>&1
fi
