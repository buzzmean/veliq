#!/usr/bin/env python3
"""Create a commit-pinned manifest on the trusted Linux CI build worker."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def create(bundle, commit):
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('full commit required')
    files = ['bin/relay', 'bin/control-plane', 'deploy/vps/production-upgrade.py']
    caps = {}
    for role in ['relay', 'control-plane']:
        caps[role] = json.loads(subprocess.check_output([str(bundle.resolve() / 'bin' / role), '-version-json']))
        if caps[role]['commit'] != commit or caps[role]['modified']:
            raise ValueError('binary must come from exact clean commit')
    manifest = {'format': 1, 'commit': commit, 'files': {name: hashlib.sha256((bundle / name).read_bytes()).hexdigest() for name in files}, 'capabilities': caps}
    (bundle / 'UPGRADE_MANIFEST.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('bundle', type=Path)
    p.add_argument('commit')
    a = p.parse_args()
    create(a.bundle, a.commit)
