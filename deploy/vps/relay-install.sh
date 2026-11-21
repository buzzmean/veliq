#!/usr/bin/env bash
# Usage: install.sh --relay-only RELAY_BINARY PRIVATE_RELAY_CREDENTIAL_DIR ENV_FILE
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
binary=${1:?Linux amd64 relay binary required}
credentials=${2:?private directory with ca.pem/server.pem/server.key/trust.json/heartbeat.token required}
env_file=${3:?operator-edited example.env required}
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
command -v systemctl >/dev/null
command -v curl >/dev/null
python3 "$here/validate-env.py" "$env_file"
[[ -f $binary && ! -L $binary ]] || exit 1
names=(ca.pem server.pem server.key trust.json heartbeat.token)
[[ ! -f "$credentials/cp-ca.pem" ]] || names+=(cp-ca.pem)
for name in "${names[@]}"; do
 [[ -s "$credentials/$name" && ! -L "$credentials/$name" ]] || { echo "Missing real relay credential: $name" >&2; exit 1; }
 [[ ! -L /etc/neexitlag/relay/$name ]] || exit 1
 if [[ -e /etc/neexitlag/relay/$name ]]; then
  cmp -s "$credentials/$name" "/etc/neexitlag/relay/$name" || { echo "Existing $name differs; refusing credential replacement." >&2; exit 1; }
 fi
done
[[ ! -L /etc/neexitlag && ! -L /etc/neexitlag/relay && ! -L /opt/neexitlag && ! -L /opt/neexitlag/bin && ! -L /var/lib/neexitlag ]] || exit 1
[[ ! -L /etc/neexitlag/relay/relay.env ]] || exit 1
if [[ -e /etc/neexitlag/relay/relay.env ]]; then
 cmp -s "$env_file" /etc/neexitlag/relay/relay.env || { echo 'Existing env differs; edit root-owned settings explicitly instead of overwriting.' >&2; exit 1; }
fi
if id neexitlag-relay >/dev/null 2>&1; then
 [[ $(id -u neexitlag-relay) -gt 0 && $(id -u neexitlag-relay) -lt 1000 && $(id -gn neexitlag-relay) == neexitlag-relay ]] || { echo 'Existing relay account is not the expected system account.' >&2; exit 1; }
else
 useradd --system --user-group --home /var/lib/neexitlag --shell /usr/sbin/nologin neexitlag-relay
fi
install -d -m 0755 /etc/neexitlag /opt/neexitlag/bin
install -d -m 0750 -o root -g neexitlag-relay /etc/neexitlag/relay
for name in "${names[@]}"; do
 [[ -e /etc/neexitlag/relay/$name ]] || install -m 0640 -o root -g neexitlag-relay "$credentials/$name" "/etc/neexitlag/relay/$name"
 chmod 0640 "/etc/neexitlag/relay/$name"
 chown root:neexitlag-relay "/etc/neexitlag/relay/$name"
done
if [[ ! -e /etc/neexitlag/relay/relay.env ]]; then
 install -m 0640 -o root -g neexitlag-relay "$env_file" /etc/neexitlag/relay/relay.env
fi
chmod 0640 /etc/neexitlag/relay/relay.env
chown root:neexitlag-relay /etc/neexitlag/relay/relay.env
# Use the same atomic, health-checked lifecycle for first install and repeat install.
bash "$here/update.sh" "$binary"
systemctl enable neexitlag-relay
printf '%s\n' 'Relay installed. Local health does not prove Internet relay traffic. No firewall was changed.'
