#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ $# == 0 || ( $# == 1 && $1 == --purge-relay-data ) ]] || { echo 'Usage: uninstall.sh [--purge-relay-data]' >&2; exit 1; }
if systemctl cat neexitlag-relay >/dev/null 2>&1; then systemctl disable --now neexitlag-relay; fi
rm -f /etc/systemd/system/neexitlag-relay.service /opt/neexitlag/bin/relay /opt/neexitlag/bin/relay-start
systemctl daemon-reload
if [[ ${1:-} == --purge-relay-data ]]; then
 [[ ! -L /etc/neexitlag/relay && ! -L /var/lib/neexitlag ]] || { echo 'Refusing purge through a symlink.' >&2; exit 1; }
 rm -rf /etc/neexitlag/relay
 # Preserve any unrelated state; remove only relay replay/config data.
 rm -f /var/lib/neexitlag/replay.json /var/lib/neexitlag/signed-config.json
 rmdir /var/lib/neexitlag 2>/dev/null || true
 if id neexitlag-relay >/dev/null 2>&1; then
  [[ $(id -u neexitlag-relay) -gt 0 && $(id -u neexitlag-relay) -lt 1000 ]] || exit 1
  userdel neexitlag-relay
 fi
 echo 'Relay files and explicitly selected relay credentials removed. Control plane/echo/firewall unchanged.'
else echo 'Relay removed; credentials/replay state preserved. Use --purge-relay-data for explicit cleanup.'; fi
