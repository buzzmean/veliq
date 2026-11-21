"""Bounded diagnostics: no exception text, arguments, source lines or locals escape."""
import errno
from pathlib import Path
import re
import shlex

STEP = 'ENTRY'
PROGRAMS = {'systemctl', 'systemd-run', 'runuser', 'openssl', 'pg_dump', 'pg_dumpall', 'psql', 'curl', 'ss', 'ip', 'tar', 'python3', 'fresh-pc', 'veliq-fresh-helper', 'relay', 'control-plane'}
CODES = {'ROOT_REQUIRED_OR_EXCLUDED_HOST', 'VPS_IDENTITY_MISMATCH', 'INVALID_BASELINE_COMMIT', 'READ_ONLY_OUTPUT_FILE_FORBIDDEN', 'READ_ONLY_RESPONSE_TOO_LARGE', 'READ_ONLY_COMMAND_FAILED', 'READ_ONLY_TIMER_LIST_TOO_LARGE', 'READ_ONLY_BACKUP_LIST_TOO_LARGE', 'READ_ONLY_BACKUP_METADATA_TOO_LARGE', 'READ_ONLY_PROBE_REPORT_TOO_LARGE', 'BOUNDED_REQUEST_EXCEEDED', 'RELEASE_MANIFEST_INVALID', 'EXPLICIT_DEPLOYMENT_CONFIRMATION_REQUIRED', 'ARTIFACT_HASH_OR_SIZE_MISMATCH', 'ACTIVATION_RELEASE_FAILED_SEE_SAFE_CODE'}
MESSAGES = {'Unsupported EnvironmentFile syntax':'ENVIRONMENT_FILE_SYNTAX_UNSUPPORTED', 'Required EnvironmentFile setting absent/duplicated':'ENVIRONMENT_FILE_SETTING_ABSENT_OR_DUPLICATED', 'UNSUPPORTED_LOCAL_DATABASE':'UNSUPPORTED_LOCAL_DATABASE'}
FILES = {'renew-server-cert.py', 'activation-diagnostics.py', 'inspect-activation.py', 'fresh-vps-upgrade.py', 'production-upgrade.py', 'production-engine.py', 'activation-release-ssh.py', 'deploy-activation.py', '<readonly-engine>', '<readonly-fresh>', '<readonly-activation>', '<string>'}

def step(name):
    global STEP
    STEP = name

def safe_stderr(raw):
    text = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else str(raw)
    labels = [(r'Permission denied', 'PERMISSION_DENIED'), (r'No such file or directory', 'FILE_NOT_FOUND'), (r'not found', 'NOT_FOUND'), (r'Connection refused', 'CONNECTION_REFUSED'), (r'timed out', 'TIMED_OUT'), (r'certificate has expired', 'CERTIFICATE_EXPIRED'), (r'certificate verify failed', 'CERTIFICATE_VERIFY_FAILED'), (r'No space left on device', 'NO_SPACE_LEFT'), (r'Read-only file system', 'READ_ONLY_FILESYSTEM'), (r'relation .* does not exist', 'SQL_RELATION_MISSING'), (r'column .* does not exist', 'SQL_COLUMN_MISSING'), (r'authentication failed', 'SQL_AUTHENTICATION_FAILED'), (r'could not connect|connection .* failed', 'CONNECTION_FAILED'), (r'syntax error', 'SYNTAX_ERROR'), (r'must be owner|permission denied for', 'SQL_PERMISSION_DENIED')]
    found = [label for pattern, label in labels if re.search(pattern, text[:8192], re.I)]
    return '|'.join(found) if found else ('REDACTED_UNRECOGNIZED_STDERR' if text else 'EMPTY')

def failure(exc, stage=None):
    code = MESSAGES.get(str(exc), str(exc) if str(exc) in CODES else 'SAFE_OPERATION_FAILED')
    if isinstance(exc, OSError):
        code = {errno.ENOENT:'FILE_NOT_FOUND', errno.EACCES:'PERMISSION_DENIED', errno.ENOSPC:'NO_SPACE_LEFT'}.get(exc.errno, 'OS_OPERATION_FAILED')
    command = getattr(exc, 'command', '')
    exit_code = getattr(exc, 'exit_code', getattr(exc, 'returncode', None))
    frames = []
    tb = exc.__traceback__
    while tb is not None:
        frame = tb.tb_frame
        name = Path(frame.f_code.co_filename).name
        if name in FILES:
            frames.append({'file':name, 'line':tb.tb_lineno})
        tb = tb.tb_next
    return {'code':code, 'step':stage or STEP, 'exception':type(exc).__name__ if type(exc).__name__ in ('RuntimeError','UpgradeError','PermissionError','FileNotFoundError','ValueError','TimeoutExpired','OSError','CalledProcessError','SyntaxError','JSONDecodeError','UnicodeDecodeError') else 'OPERATION_ERROR', 'exit_code':exit_code if isinstance(exit_code,int) else None, 'command':command if command in PROGRAMS else 'NOT_REPORTED', 'stderr':safe_stderr(getattr(exc,'command_stderr',getattr(exc,'stderr',b''))), 'traceback':frames[-12:], 'stdout':safe_stream(getattr(exc,'command_stdout',b'')), 'child':getattr(exc,'child',None)}

def require_vps_identity(path, expected='2.56.177.4'):
    # EnvironmentFile syntax, never source/eval shell input. BOM/CRLF are text
    # encodings, not evidence of a different server. Duplicate values fail closed.
    values = []
    for line in Path(path).read_text(encoding='utf-8-sig').splitlines():
        if line.strip().startswith('VPS_PUBLIC_IP='):
            fields = shlex.split(line.strip().partition('=')[2], comments=False)
            if len(fields) != 1:
                raise RuntimeError('VPS_IDENTITY_MISMATCH')
            values.extend(fields)
    if values != [expected]:
        raise RuntimeError('VPS_IDENTITY_MISMATCH')

# Only fixed, reviewed status words escape child output. Never arbitrary JSON,
# command arguments, psql rows, config bytes, PEM or an exception's free text.
CODES.update({'UPGRADE_PROBE_JOURNAL_REQUIRED','INVALID_PROBE_CLEANUP','UNSAFE_PROBE_JOURNAL','PROBE_JOURNAL_INVALID','PROBE_STAGE_FAILED','PROBE_REGISTER_FAILED','PROBE_LOOKUP_FAILED','PROBE_REVOKE_FAILED','PROBE_REVOCATION_PUBLICATION_FAILED','PROBE_STATE_CLEANUP_FAILED','CP_TLS_HEALTH_FAILED','ROOT_ONLY_CA_KEY_REQUIRED','TRUSTED_LOCAL_HELPER_REQUIRED','REQUIRED_SAN_MISSING','TLS_COPIES_MISMATCH','SAN_CHANGED','CA_RENEWAL_REQUIRED','LEAF_RENEWAL_FAILED','SERVER_CERT_RENEWAL_COMMITTED','COMMAND_FAILED','COMMAND_TIMEOUT','COMMAND_UNAVAILABLE','INVALID_BACKUP_PATH','UNSUPPORTED_SCHEMA_VERSION','SYMLINK_REFUSED','BACKUP_HASH_MISMATCH','BACKUP_MANIFEST_INVALID','EXPLICIT_RENEWAL_CONFIRMATION_REQUIRED','ROOT_VPS_PREFLIGHT_FAILED','SYSCALL_FAILED'})

def safe_stream(raw):
    text=raw.decode('utf-8','replace') if isinstance(raw,bytes) else str(raw)
    tokens=set(re.findall(r'\b[A-Z][A-Z0-9_]+\b',text[:65536]))
    return {'classification':safe_stderr(text), 'codes':sorted(tokens & CODES), 'bytes':len(raw.encode() if isinstance(raw,str) else raw)}

def process_report(args, returncode, stdout=b'', stderr=b''):
    program=Path(args[0]).name
    return {'command':program if program in PROGRAMS else 'OTHER', 'exit_code':returncode,
            'stdout':safe_stream(stdout), 'stderr':safe_stream(stderr)}

def run_process(args, check=True, timeout=60):
    import json,subprocess,sys
    try:
        p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired) as cause:
        code='COMMAND_TIMEOUT' if isinstance(cause,subprocess.TimeoutExpired) else 'COMMAND_UNAVAILABLE'
        report=process_report(args,None,getattr(cause,'stdout',None) or b'',getattr(cause,'stderr',None) or b'')
        print('ACTIVATION_SUBPROCESS '+json.dumps(dict(report,code=code)),file=sys.stderr,flush=True)
        error=RuntimeError(code);error.command=Path(args[0]).name;error.child=report;raise error from None
    report=process_report(args,p.returncode,p.stdout,p.stderr)
    print('ACTIVATION_SUBPROCESS '+json.dumps(report),file=sys.stderr,flush=True)
    if check and p.returncode:
        error=RuntimeError('COMMAND_FAILED');error.command=Path(args[0]).name;error.exit_code=p.returncode
        error.command_stdout=p.stdout;error.command_stderr=p.stderr;error.child=report;raise error
    return p


def emit_process(args, returncode, stdout=b'', stderr=b''):
    import json,sys
    print('ACTIVATION_SUBPROCESS '+json.dumps(process_report(args,returncode,stdout,stderr)),file=sys.stderr,flush=True)
