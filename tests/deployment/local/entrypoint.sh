#!/bin/sh
set -eu
# /run is a NEW container tmpfs, never a bind of host /run. systemd credentials
# are prepared in a child mount namespace and must propagate back to PID1.
mount --make-rshared /run
exec /sbin/init
