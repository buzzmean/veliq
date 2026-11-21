#!/usr/bin/env python3
"""Read-only public origin probes. No service/config/identity/package mutation.
Run by the owner on the VPS, never automatically from install/bootstrap.
Only finite metadata is printed; raw TLS traces and HTTP bodies stay private.
"""
import argparse
import ipaddress
import json
import os
import re
import selectors
import shutil
import subprocess
import time

HOST = 'web.telegram.org'
MAX_OUTPUT = 262144


def command(args, request=b'', timeout=10):
    """Bound subprocess time and combined output, never persist raw TLS traces."""
    env = os.environ.copy()
    env['LC_ALL'] = 'C'
    # Respect the system trust store; do not import caller-specific TLS/debug settings.
    for name in ('SSLKEYLOGFILE', 'OPENSSL_CONF', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
                 'CURL_CA_BUNDLE', 'LD_PRELOAD', 'LD_LIBRARY_PATH'):
        env.pop(name, None)
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, env=env)
    data = bytearray()
    cutoff = False
    try:
        try:
            p.stdin.write(request)
        except BrokenPipeError:
            pass
        finally:
            try:
                p.stdin.close()
            except BrokenPipeError:
                pass
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    cutoff = True
                    break
                for key, _ in selector.select(min(left, 0.2)):
                    block = os.read(key.fileobj.fileno(), 8192)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    if len(data) + len(block) > MAX_OUTPUT:
                        cutoff = True
                        break
                    data.extend(block)
                if cutoff:
                    break
    finally:
        if not cutoff:
            try:
                p.wait(timeout=0.3)
            except subprocess.TimeoutExpired:
                cutoff = True
        if p.poll() is None:
            p.kill()
        p.wait()
        p.stdout.close()
    return p.returncode, bytes(data), cutoff


def tls_summary(raw, code, cutoff):
    # No arbitrary error/body/trace text escapes: allowlisted fields only.
    text = raw.decode('ascii', 'replace')
    unsupported = code != 0 and bool(re.search(r'(?i)(cannot be set|unknown group|invalid group|unrecognized flag|unknown option)', text))
    hellos = [int(n, 16) for n in re.findall(r'>>>[^\r\n]*Handshake \[length ([0-9a-fA-F]{1,6})\], ClientHello', text)][:2]
    headers = []
    # OpenSSL -msg supplies TLS framing without needing a payload logger in VELIQ.
    for direction, line in re.findall(r'(>>>|<<<)[^\r\n]*RecordHeader \[length 0005\]\r?\n([^\r\n]+)', text):
        values = re.findall(r'\b[0-9a-fA-F]{2}\b', line)
        if len(values) != 5:
            continue
        h = bytes.fromhex(''.join(values))
        if 20 <= h[0] <= 23 and h[1] == 3 and h[2] <= 4:
            headers.append({'direction': 'client' if direction == '>>>' else 'origin',
                            'type': h[0], 'length': int.from_bytes(h[3:], 'big'),
                            'header_hex': h.hex()})
        if len(headers) >= 8:
            break
    status = re.search(rb'HTTP/1\.[01] ([0-9]{3})\b', raw)
    alerts = re.findall(r'(?i)alert (?:number )?([0-9]{1,3})\b', text)[:2]
    failure = 'NONE' if code == 0 and not cutoff else 'TLS_OR_IO_FAILED'
    if cutoff:
        failure = 'BOUNDED_TIMEOUT_OR_OUTPUT'
    elif unsupported:
        failure = 'UNSUPPORTED_OPENSSL_FEATURE'
    elif alerts:
        failure = 'REMOTE_TLS_ALERT'
    elif re.search(r'(?i)(wrong version number|invalid.*record|record layer failure|packet length too long)', text):
        failure = 'INVALID_TLS_RECORD'
    elif re.search(r'(?i)(certificate verify failed|hostname mismatch|verification error)', text):
        failure = 'CERTIFICATE_VERIFICATION_FAILED'
    elif re.search(r'(?i)(unexpected eof|no peer certificate)', text):
        failure = 'TLS_EOF_OR_NO_CERTIFICATE'
    return {'failure_class': failure, 'state': 'SKIP_UNSUPPORTED_GROUP' if unsupported else ('BOUNDED_TIMEOUT_OR_OUTPUT' if cutoff else 'COMPLETED'),
            'exit_code': code, 'certificate_verified': bool(re.search(r'Verification: OK|Verify return code: 0 \(ok\)', text)),
            'client_hello_handshake_bytes': hellos, 'first_records': headers,
            'http_status': int(status[1]) if status else None,
            'tls_alert_numbers': [int(v) for v in alerts],
            'scope': 'OpenSSL generated ClientHello; not Chrome/ECH or complete-page PASS'}


def curl_summary(raw, code, cutoff):
    m = re.search(rb'VELIQ_RESULT:([0-9]{3}):([0-9]+):([0-9]+)(?::([0-9.]{1,5}))?', raw)
    result = {'exit_code': code, 'bounded': cutoff, 'http_status': None,
              'failure_class': 'BOUNDED_TIMEOUT_OR_OUTPUT' if cutoff else {0: 'NONE', 7: 'CONNECT_FAILED', 18: 'TRUNCATED_BODY', 28: 'NETWORK_TIMEOUT', 35: 'TLS_FAILED', 52: 'EMPTY_REPLY', 56: 'RECEIVE_FAILED', 60: 'CERTIFICATE_VERIFICATION_FAILED', 63: 'BODY_LIMIT'}.get(code, 'CURL_FAILED'),
              'certificate_verified': False, 'body_bytes': 0, 'http_version': None, 'verified_get': False, 'state': 'BOUNDED_TIMEOUT_OR_OUTPUT' if cutoff else ('BODY_LIMIT' if code == 63 else 'COMPLETED')}
    if m:
        status, size, verify = (int(v) for v in m.groups()[:3])
        if m[4]:
            result['http_version'] = m[4].decode('ascii')
        result.update(http_status=status, body_bytes=size,
                      certificate_verified=verify == 0 and status != 0,
                      verified_get=code == 0 and not cutoff and verify == 0 and 200 <= status < 400 and size > 0)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-read-only', action='store_true', required=True)
    parser.add_argument('--candidates', nargs='+', default=['149.154.167.40', '149.154.167.99'])
    args = parser.parse_args()
    if len(args.candidates) > 3:
        parser.error('at most three public IPv4 diagnostic candidates')
    addresses = []
    for value in args.candidates:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            parser.error('invalid public IPv4 candidate')
        if ip.version != 4 or not ip.is_global:
            parser.error('public IPv4 candidates only')
        addresses.append(str(ip))
    print(json.dumps({'read_only': True, 'sni': HOST, 'candidates': addresses,
                      'note': 'IPs are diagnostic candidates only; no permanent pin, no relay/service/CA/config changes'}), flush=True)
    if not shutil.which('openssl') or not shutil.which('curl'):
        print(json.dumps({'error': 'MISSING_OPENSSL_OR_CURL_NO_PACKAGES_INSTALLED'}))
        return 2
    # GET a public root page, no redirects, browser cookies, tokens or raw output.
    for ip in addresses:
        for mode, extra in [('legacy-keyshare', ['-groups', 'X25519:P-256']),
                            ('large-mlkem', ['-tls1_3', '-groups', 'X25519MLKEM768:X25519']),
                            ('large-opaque-extensions', ['-serverinfo', ','.join(str(n) for n in range(60000, 60400))])]:
            argv = ['openssl', 's_client', '-connect', ip + ':443', '-servername', HOST,
                    '-verify_hostname', HOST, '-verify_return_error', '-alpn', 'http/1.1',
                    '-brief', '-msg', '-ign_eof'] + extra
            request = ('GET / HTTP/1.1\r\nHost: ' + HOST + '\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n').encode('ascii')
            code, raw, cutoff = command(argv, request)
            print(json.dumps({'ip': ip, 'tool': 'openssl', 'mode': mode,
                              **tls_summary(raw, code, cutoff)}), flush=True)
        for mode in ('--http1.1', '--http2'):
            argv = ['curl', '-q', '--noproxy', '*', '--proxy', '', '--silent', '--show-error',
                    '--connect-timeout', '3', '--max-time', '8', '--max-filesize', '131072', '--limit-rate', '128K',
                    '--max-redirs', '0', mode, '--resolve', HOST + ':443:' + ip,
                    '--output', os.devnull, '--write-out', 'VELIQ_RESULT:%{http_code}:%{size_download}:%{ssl_verify_result}:%{http_version}',
                    'https://' + HOST + '/']
            code, raw, cutoff = command(argv)
            result = curl_summary(raw, code, cutoff)
            if code == 2 and b'not support' in raw.lower():
                result['state'] = 'SKIP_CURL_HTTP2_UNSUPPORTED'
            print(json.dumps({'ip': ip, 'tool': 'curl', 'mode': mode, **result}), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
