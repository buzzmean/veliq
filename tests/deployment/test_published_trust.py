import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import io

SPEC = importlib.util.spec_from_file_location('trust', Path(__file__).resolve().parents[2]/'tools/extract_published_trust.py')
trust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trust)


class PublishedTrustTests(unittest.TestCase):
    def test_hash_and_size_are_required_before_extraction(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(trust.urllib.request, 'urlopen', return_value=io.BytesIO(b'wrong source')):
                with self.assertRaises(ValueError):
                    trust.download('https://example.test', Path(d)/'source', '0'*64, 100)
            with patch.object(trust.urllib.request, 'urlopen', return_value=io.BytesIO(b'too large')):
                with self.assertRaises(ValueError):
                    trust.download('https://example.test', Path(d)/'large', '0'*64, 2)

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required')
    def test_only_pinned_public_ca_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ca, key, metadata = root/'ca.pem', root/'private.key', root/'release.json'
            subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-subj','/CN=fixture-public-ca','-days','30','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(key),'-out',str(ca)], check=True, capture_output=True)
            der = ssl.PEM_cert_to_DER_cert(ca.read_text())
            pin = hashlib.sha256(der).hexdigest()
            metadata.write_text(json.dumps(dict(ca_der_sha256=pin, fixture=False)))
            self.assertEqual(trust.validate_ca(ca, metadata, pin), der)
            with self.assertRaises(ValueError):
                trust.validate_ca(ca, metadata, '0'*64)
            metadata.write_text(json.dumps(dict(ca_der_sha256=pin, fixture=True)))
            with self.assertRaises(ValueError):
                trust.validate_ca(ca, metadata, pin)
            metadata.write_text(json.dumps(dict(ca_der_sha256=pin, fixture=False)))
            ca.write_text(ca.read_text()+key.read_text())
            with self.assertRaises(ValueError):
                trust.validate_ca(ca, metadata, pin)
