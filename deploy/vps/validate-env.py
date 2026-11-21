#!/usr/bin/env python3
"""Validate non-secret relay settings without evaluating a shell EnvironmentFile."""
import ipaddress
import pathlib
import re
import sys
import urllib.parse

KEYS = {'RELAY_LISTEN', 'RELAY_METRICS', 'RELAY_ID', 'RELAY_ALLOW_CIDRS',
        'RELAY_CONTROL_PLANE', 'RELAY_CONTROL_PLANE_CA_FILE', 'RELAY_DESTINATION_POLICY'}

def validate(path):
    settings = {}
    for line in pathlib.Path(path).read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        name, sep, value = line.partition('=')
        if not sep or name not in KEYS or name in settings or not value or re.search(r'[\s\x00\"\'`$\\]', value):
            raise ValueError('expected unique supported KEY=value settings without shell expansion')
        settings[name] = value
    for key in ('RELAY_LISTEN', 'RELAY_METRICS', 'RELAY_ID', 'RELAY_CONTROL_PLANE'):
        if key not in settings:
            raise ValueError('missing required setting: ' + key)
    for key in ('RELAY_LISTEN', 'RELAY_METRICS'):
        host, port = settings[key].rsplit(':', 1)
        ip = ipaddress.IPv4Address(host)
        if not 1024 <= int(port) <= 65535:
            raise ValueError('listeners require unprivileged ports 1024..65535')
        if key == 'RELAY_METRICS' and not ip.is_loopback:
            raise ValueError('health/metrics must bind loopback')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', settings['RELAY_ID']):
        raise ValueError('invalid ticket audience')
    policy = settings.get('RELAY_DESTINATION_POLICY', 'cidrs')
    if policy == 'public-only':
        if 'RELAY_ALLOW_CIDRS' in settings:
            raise ValueError('public-only cannot be combined with destination CIDRs')
    elif policy == 'cidrs':
        if 'RELAY_ALLOW_CIDRS' not in settings:
            raise ValueError('controlled test requires explicit destination CIDRs')
        for value in settings['RELAY_ALLOW_CIDRS'].split(','):
            network = ipaddress.ip_network(value, strict=True)
            if network.prefixlen == 0 or network.is_multicast or network.is_unspecified:
                raise ValueError('controlled test requires an explicit limited destination allowlist')
    else:
        raise ValueError('unknown destination policy')
    url = urllib.parse.urlsplit(settings['RELAY_CONTROL_PLANE'])
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('control plane must be an explicit HTTPS endpoint')
    ca = settings.get('RELAY_CONTROL_PLANE_CA_FILE', '/etc/neexitlag/relay/ca.pem')
    if not pathlib.PurePosixPath(ca).is_absolute():
        raise ValueError('control-plane CA path must be absolute')
    return settings

if __name__ == '__main__':
    try:
        config = validate(sys.argv[1])
        if len(sys.argv) > 2 and sys.argv[2] == '--health-url':
            print('http://' + config['RELAY_METRICS'] + '/healthz')
    except (ValueError, OSError, IndexError):
        sys.exit('Invalid relay env: use complete example.env settings, HTTPS, loopback metrics and explicit destination CIDRs.')
