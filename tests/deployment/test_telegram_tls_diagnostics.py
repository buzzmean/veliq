"""Isolated parsing/process tests only. No VPS/Internet calls."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import socket
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('telegram_diagnostics', ROOT / 'deploy/vps/diagnose-telegram-tls.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class TelegramDiagnosticsTests(unittest.TestCase):
    def test_large_clienthello_only_metadata_escapes(self):
        raw = b'''>>> TLS 1.0, RecordHeader [length 0005]
    16 03 01 06 00
>>> TLS 1.3, Handshake [length 0600], ClientHello
    secret_client_random_session_id_ECH
<<< TLS 1.2, RecordHeader [length 0005]
    15 03 03 00 02
Verification: OK
HTTP/1.1 200 OK\r
Set-Cookie: NEVER_LOG\r
\r
private body
'''
        result = d.tls_summary(raw, 0, False)
        self.assertEqual(result['client_hello_handshake_bytes'], [1536])
        self.assertTrue(result['certificate_verified'])
        self.assertEqual(result['http_status'], 200)
        self.assertEqual(result['first_records'][1]['header_hex'], '1503030002')
        self.assertNotIn('NEVER_LOG', json.dumps(result))
        self.assertNotIn('secret_client', json.dumps(result))
        self.assertNotIn('private body', json.dumps(result))

    def test_fixed_tls_failure_class_does_not_export_arbitrary_error(self):
        r = d.tls_summary(b'error:ssl:wrong version number secret_NEVER_LOG', 1, False)
        self.assertEqual(r['failure_class'], 'INVALID_TLS_RECORD')
        self.assertNotIn('secret_NEVER_LOG', json.dumps(r))

    def test_unsupported_hybrid_cannot_be_pass(self):
        r = d.tls_summary(b'SSL_CONF_cmd: groups cannot be set\n', 1, False)
        self.assertEqual(r['state'], 'SKIP_UNSUPPORTED_GROUP')
        self.assertFalse(r['certificate_verified'])
        self.assertIsNone(r['http_status'])

    def test_get_requires_verified_nonempty_body_and_successful_transfer(self):
        self.assertTrue(d.curl_summary(b'VELIQ_RESULT:200:123:0', 0, False)['verified_get'])
        self.assertEqual(d.curl_summary(b'VELIQ_RESULT:200:123:0:2', 0, False)['http_version'], '2')
        for raw, code, bounded in [(b'VELIQ_RESULT:200:0:0', 0, False),
                                    (b'VELIQ_RESULT:200:123:20', 60, False),
                                    (b'VELIQ_RESULT:200:123:0', 18, False),
                                    (b'VELIQ_RESULT:200:123:0', 0, True),
                                    (b'VELIQ_RESULT:000:0:0', 35, False)]:
            self.assertFalse(d.curl_summary(raw, code, bounded)['verified_get'])

    def test_local_process_output_and_deadline_bounded(self):
        code, raw, cutoff = d.command([sys.executable, '-c', "print('safe')"])
        self.assertEqual(code, 0)
        self.assertIn(b'safe', raw)
        self.assertFalse(cutoff)
        _, raw, cutoff = d.command([sys.executable, '-c', "import time; time.sleep(2)"], timeout=0.05)
        self.assertTrue(cutoff)
        _, raw, cutoff = d.command([sys.executable, '-c', "print('x'*500000)"])
        self.assertTrue(cutoff)
        self.assertLessEqual(len(raw), d.MAX_OUTPUT)

    @unittest.skipUnless(d.shutil.which('openssl'), 'OpenSSL CLI not installed')
    def test_real_openssl_large_hello_metadata_against_local_socket(self):
        # Local framing fixture only; peer deliberately sends no certificate.
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.settimeout(3)
        observed = []
        def peer():
            try:
                c, _ = listener.accept()
                with c:
                    c.settimeout(3)
                    header = b''
                    while len(header) < 5:
                        part = c.recv(5 - len(header))
                        if not part:
                            break
                        header += part
                    if len(header) == 5:
                        left = int.from_bytes(header[3:], 'big')
                        observed.append(left)
                        while left:
                            part = c.recv(left)
                            if not part:
                                break
                            left -= len(part)
            except (OSError, TimeoutError):
                pass
        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        try:
            argv = ['openssl', 's_client', '-connect', '127.0.0.1:' + str(listener.getsockname()[1]),
                    '-servername', d.HOST, '-verify_return_error', '-verify_hostname', d.HOST,
                    '-brief', '-msg', '-ign_eof', '-serverinfo', ','.join(str(n) for n in range(60000, 60400)),
                    '-alpn', ','.join(['h2', 'http/1.1'] + ['fixture-' + str(n) + '-' + 'x' * 180 for n in range(8)])]
            code, raw, cutoff = d.command(argv, timeout=5)
            summary = d.tls_summary(raw, code, cutoff)
            # -ign_eof matches production. OpenSSL versions cap the number of
            # custom serverinfo extensions differently (CI produced 713 bytes).
            # Bounded fixture-only ALPN names guarantee a truly large hello on
            # both old and new OpenSSL. Keep size/framing assertions strict.
            self.assertTrue(observed and observed[0] >= 1500, summary)
            self.assertTrue(summary['client_hello_handshake_bytes'][0] >= 1500)
            self.assertEqual(summary['first_records'][0]['length'], observed[0])
            self.assertFalse(summary['certificate_verified'])
            self.assertIsNone(summary['http_status'])
        finally:
            listener.close()
            thread.join(timeout=1)

    def test_one_script_probes_readonly_without_credentials_or_service_access(self):
        commands = []
        def run(argv, request=b'', **_):
            commands.append((argv, request))
            return 0, b'VELIQ_RESULT:200:123:0', False
        out = io.StringIO()
        with patch.object(sys, 'argv', ['diagnose', '--confirm-read-only']), patch.object(d.shutil, 'which', return_value='/usr/bin/fixture'), patch.object(d, 'command', side_effect=run), contextlib.redirect_stdout(out):
            self.assertEqual(d.main(), 0)
        self.assertEqual(len(commands), 10)
        for argv, request in commands:
            self.assertIn(argv[0], ('openssl', 'curl'))
            text = ' '.join(argv)
            self.assertNotIn('/etc/neexitlag', text)
            self.assertNotIn('--insecure', text)
            if argv[0] == 'openssl':
                self.assertIn('-verify_return_error', argv)
                self.assertIn('-verify_hostname', argv)
                self.assertIn('Host: web.telegram.org', request.decode())
                self.assertNotIn('HEAD ', request.decode())
                if '-serverinfo' in argv:
                    self.assertEqual(len(argv[argv.index('-serverinfo') + 1].split(',')), 400)
            else:
                self.assertEqual(argv[1], '-q')  # do not inherit ~/.curlrc secrets
                self.assertNotIn('--location', argv)
        for line in out.getvalue().splitlines():
            json.loads(line)

    def test_private_and_unbounded_candidates_rejected_before_network(self):
        for ips in [('127.0.0.1',), ('10.0.0.1',), ('149.154.167.40',)*4]:
            with patch.object(sys, 'argv', ['diagnose', '--confirm-read-only', '--candidates', *ips]), patch.object(d, 'command', side_effect=AssertionError('network not expected')), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    d.main()
