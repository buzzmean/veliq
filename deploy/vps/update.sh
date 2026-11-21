#!/usr/bin/env bash
# Atomic binary/unit update; rollback previous files if restart/health fails.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
binary=${1:?Linux amd64 release relay binary required}
[[ $EUID == 0 && -f $binary && ! -L $binary ]] || exit 1
[[ -d /etc/neexitlag/relay && -s /etc/neexitlag/relay/trust.json ]] || { echo 'Install real relay credentials first.' >&2; exit 1; }
# Verify ELF class/machine, without executing the uploaded binary as root.
python3 - "$binary" <<'PY'
import sys
b=open(sys.argv[1],'rb').read(20)
if len(b)!=20 or b[:6]!=b'\x7fELF\x02\x01' or b[18:20]!=b'\x3e\x00':
 sys.exit('Expected Linux amd64 ELF release binary.')
PY
health=http://127.0.0.1:9090/healthz
if [[ -f /etc/neexitlag/relay/relay.env ]]; then
 health=$(python3 "$here/validate-env.py" /etc/neexitlag/relay/relay.env --health-url)
fi
[[ ! -L /opt/neexitlag/bin && ! -L /etc/neexitlag/relay && ! -L /var/lib/neexitlag ]] || exit 1
install -d -m 0755 /opt/neexitlag/bin
backup=$(mktemp -d /opt/neexitlag/bin/.relay-update.XXXXXX)
trap 'rm -rf -- "$backup"' EXIT
paths=(/opt/neexitlag/bin/relay /opt/neexitlag/bin/relay-start /etc/systemd/system/neexitlag-relay.service)
for i in "${!paths[@]}"; do
 [[ ! -L ${paths[$i]} ]] || exit 1
 if [[ -f ${paths[$i]} ]]; then cp -p -- "${paths[$i]}" "$backup/$i"; fi
done
install -m 0755 "$binary" "$backup/new-relay"
install -m 0755 "$here/relay-start.sh" "$backup/new-start"
install -m 0644 "$here/neexitlag-relay.service" "$backup/new-unit"
mv -f -- "$backup/new-relay" "${paths[0]}"
mv -f -- "$backup/new-start" "${paths[1]}"
# /etc and /opt can be different filesystems: stage unit on its own filesystem.
unit_tmp=$(mktemp /etc/systemd/system/.neexitlag-relay.XXXXXX)
install -m 0644 "$backup/new-unit" "$unit_tmp"
mv -f -- "$unit_tmp" "${paths[2]}"
healthy() {
 for ((attempt=0; attempt<20; attempt++)); do
  if systemctl is-active --quiet neexitlag-relay && curl --fail --silent --max-time 2 "$health" >/dev/null && curl --fail --silent --max-time 2 "${health%/healthz}/metrics" | grep -qx 'neexitlag_relay_health 1'; then return 0; fi
  sleep 1
 done
 return 1
}
systemctl daemon-reload
if systemctl restart neexitlag-relay && healthy; then
 echo 'Relay updated and locally healthy; active sessions reconnect after restart.'
 exit 0
fi
echo 'New relay failed restart/health; restoring previous binary and unit (credentials/state preserved).' >&2
for i in "${!paths[@]}"; do
 if [[ -f $backup/$i ]]; then
  restore=$(mktemp "$(dirname "${paths[$i]}")/.relay-restore.XXXXXX")
  cp -p -- "$backup/$i" "$restore"
  mv -f -- "$restore" "${paths[$i]}"
 else rm -f -- "${paths[$i]}"; fi
done
systemctl daemon-reload
if [[ -f ${paths[0]} ]]; then systemctl restart neexitlag-relay && healthy || echo 'Rollback health also failed; inspect journalctl.' >&2; else systemctl stop neexitlag-relay || true; fi
exit 1
