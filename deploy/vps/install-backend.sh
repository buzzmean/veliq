#!/usr/bin/env bash
# Invoked on the chosen VPS by setup-e2e.ps1; installs only a dedicated service user/db.
set -euo pipefail
bundle_dir=${1:?private upload directory required}
vps_public_ip=${2:?actual public IPv4 required}
[[ $EUID == 0 ]] || { echo 'Run with root or sudo.' >&2; exit 1; }
[[ $vps_public_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
[[ ! -e /etc/neexitlag ]] || { echo 'Existing deployment detected; refusing to overwrite identities.' >&2; exit 1; }
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql ca-certificates curl python3
systemctl enable --now postgresql
for role in relay control echo; do
 id "neexitlag-$role" >/dev/null 2>&1 || useradd --system --user-group --home /var/lib/neexitlag --shell /usr/sbin/nologin "neexitlag-$role"
done
install -d -m 0755 /etc/neexitlag /etc/neexitlag/public /opt/neexitlag/bin
for role in relay control echo; do
 install -d -m 0750 -o root -g "neexitlag-$role" "/etc/neexitlag/$role"
done
install -m 0755 "$bundle_dir"/bin/* /opt/neexitlag/bin/
install -m 0755 "$bundle_dir/units/relay-start.sh" /opt/neexitlag/bin/relay-start
for name in ca.pem ca.key server.pem server.key signing.key admin.token database.password heartbeat.token control-plane.env; do
 install -m 0640 -o root -g neexitlag-control "$bundle_dir/server/$name" /etc/neexitlag/control/
done
for name in ca.pem server.pem server.key trust.json heartbeat.token; do
 install -m 0640 -o root -g neexitlag-relay "$bundle_dir/server/$name" /etc/neexitlag/relay/
done
install -m 0640 -o root -g neexitlag-echo "$bundle_dir/server/echo.token" /etc/neexitlag/echo/
printf 'VPS_PUBLIC_IP=%s\n' "$vps_public_ip" > /etc/neexitlag/public/relay.env
chmod 0644 /etc/neexitlag/public/relay.env
# Password is supplied to psql through a private temporary file, never argv/stdout.
db_sql=$(mktemp /tmp/neexitlag-db.XXXXXX)
trap 'rm -f "$db_sql"' EXIT
python3 "$bundle_dir/units/database-sql.py" /etc/neexitlag/control/database.password > "$db_sql"
chown postgres:postgres "$db_sql"
chmod 0600 "$db_sql"
runuser -u postgres -- psql -X -v ON_ERROR_STOP=1 -f "$db_sql" >/dev/null 2>&1 || { echo 'Database provisioning failed (private SQL suppressed).' >&2; exit 1; }
install -m 0644 "$bundle_dir"/units/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now neexitlag-control-plane neexitlag-echo neexitlag-relay
for attempt in $(seq 1 30); do
 if curl --fail --silent --cacert /etc/neexitlag/control/ca.pem https://127.0.0.1:8443/healthz >/dev/null && curl --fail --silent http://127.0.0.1:9090/healthz >/dev/null && curl --fail --silent http://127.0.0.1:9092/healthz >/dev/null; then
  echo 'Backend healthy locally. Permit TCP8443 / UDP4433 / UDP40000 in provider and host firewalls; no public acceptance claimed.'
  exit 0
 fi
 sleep 1
done
echo 'Backend health failed; inspect journalctl for the three neexitlag services.' >&2
exit 1
