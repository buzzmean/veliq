"""Validate recorded owner acceptance before expanding to 5-6 PCs. No deployment."""
import argparse
import hashlib
import json
from pathlib import Path
import re

GLOBAL = ('go_linux', 'go_windows', 'filters', 'desktop', 'origin_isolation',
          'relay_fail_closed', 'listener_capture_fail_closed', 'installer_vm',
          'artifact_integrity', 'server_readiness', 'activation_capacity',
          'certificates', 'code_hygiene', 'pubg_match', 'valorant_match', 'faceit_match')
PER_PC = ('install', 'standard_user', 'browser_sites', 'ordinary_direct',
          'youtube_2160p', 'discord_voice_local', 'freeze_reboot',
          'identity_stable', 'rollback', 'network_recovery', 'owner_proxy_lifecycle')


def validate(report, root, commit, service_hash, gui_hash):
    errors = []
    for field, expected in (('source_commit', commit), ('service_sha256', service_hash),
                            ('gui_sha256', gui_hash)):
        if report.get(field) != expected:
            errors.append(field + ': mismatch')
    def checks(rows, required, prefix):
        if not isinstance(rows, dict):
            errors.append(prefix + ': missing checks')
            return
        for name in required:
            row = rows.get(name, {})
            if not isinstance(row, dict) or row.get('status') != 'PASS':
                errors.append(prefix + '/' + name + ': not PASS')
                continue
            proof = row.get('evidence', '')
            digest = row.get('sha256', '')
            if not isinstance(proof, str) or not proof or not isinstance(digest, str):
                errors.append(prefix + '/' + name + ': missing evidence')
                continue
            path = (root / proof).resolve()
            if not path.is_relative_to(root.resolve()) or not path.is_file():
                errors.append(prefix + '/' + name + ': invalid evidence path')
                continue
            raw = path.read_bytes()
            if not raw or not re.fullmatch('[a-f0-9]{64}', digest) or hashlib.sha256(raw).hexdigest() != digest:
                errors.append(prefix + '/' + name + ': evidence hash mismatch')
    checks(report.get('global'), GLOBAL, 'global')
    pcs = report.get('pcs', [])
    if not isinstance(pcs, list) or not 2 <= len(pcs) <= 3:
        errors.append('acceptance requires 2-3 distinct PCs before expansion')
        pcs = []
    names = set()
    for pc in pcs:
        if not isinstance(pc, dict):
            errors.append('invalid PC record')
            continue
        name = pc.get('id', '')
        if not isinstance(name, str) or not re.fullmatch(r'PC[0-9]{2}', name) or name in names:
            errors.append('invalid or duplicate PC alias')
        else:
            names.add(name)
        label = name if isinstance(name, str) and re.fullmatch(r'PC[0-9]{2}', name) else 'INVALID_PC'
        for field, expected in (('source_commit', commit), ('service_sha256', service_hash), ('gui_sha256', gui_hash)):
            if pc.get(field) != expected:
                errors.append('pc/' + label + '/' + field + ': mismatch')
        checks(pc.get('checks'), PER_PC, 'pc/' + label)
    if report.get('pilot_size') not in (5, 6):
        errors.append('pilot_size must be 5 or 6')
    if report.get('owner_reviewed') is not True:
        errors.append('owner review required')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--service-sha256', required=True)
    parser.add_argument('--gui-sha256', required=True)
    args = parser.parse_args()
    for value, size in ((args.commit, 40), (args.service_sha256, 64), (args.gui_sha256, 64)):
        if not re.fullmatch('[a-f0-9]{%d}' % size, value):
            parser.error('expected lowercase full commit/hash')
    try:
        report = json.loads(args.report.read_text(encoding='utf-8'))
        if not isinstance(report, dict):
            raise ValueError('report must be an object')
        errors = validate(report, args.report.resolve().parent, args.commit, args.service_sha256, args.gui_sha256)
    except (OSError, ValueError, TypeError):
        print('NO_GO: report/evidence unreadable or malformed')
        return 1
    if errors:
        print('NO_GO')
        print('\n'.join(errors))
        return 1
    print('READY_FOR_OWNER_DECISION: recorded checks complete; no deployment performed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
