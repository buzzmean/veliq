#!/usr/bin/env bash
# Preserve the existing private full-backend workflow; opt into relay-only lifecycle.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ${1:-} == --relay-only ]]; then
 shift
 exec bash "$here/relay-install.sh" "$@"
fi
exec bash "$here/install-backend.sh" "$@"
