"""Recover only the public CA from an immutable published Setup, without running it."""
import argparse
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import tarfile
import tempfile
import urllib.request

SETUP_URL = 'https://github.com/buzzmean/veliq/releases/download/v0.3.577/VELIQ-Setup.exe'
SETUP_HASH = 'd3b98904f1f0360607fae3479a0bc7de34861131fe933363015433f79f8556c8'
PARSER_COMMIT = '93ea8b13553797aab0103108ba0bf59b988d2dbc'
PARSER_URL = f'https://github.com/dscharrer/innoextract/archive/{PARSER_COMMIT}.tar.gz'
PARSER_HASH = 'ec2c66a2f3082ddc61073a4203e33d13a001419b1e17253e23d0f91ff7a76202'
CA_PIN = '622db56fba69041b108fc31b5b3cf81a5ed722faa3110ef2b896b8fac42abd85'


def download(url, path, expected, limit):
    digest = hashlib.sha256()
    count = 0
    with urllib.request.urlopen(url, timeout=90) as response, path.open('xb') as out:
        while chunk := response.read(1024*1024):
            count += len(chunk)
            if count > limit:
                raise ValueError('PUBLIC_SOURCE_SIZE_LIMIT')
            digest.update(chunk)
            out.write(chunk)
    if digest.hexdigest() != expected:
        raise ValueError('PUBLIC_SOURCE_HASH_MISMATCH')


def validate_ca(certificate, metadata, expected_pin=CA_PIN):
    text = certificate.read_text(encoding='ascii')
    if text.count('-----BEGIN CERTIFICATE-----') != 1 or 'PRIVATE KEY' in text:
        raise ValueError('PUBLIC_CA_ONLY_REQUIRED')
    der = ssl.PEM_cert_to_DER_cert(text)
    pin = hashlib.sha256(der).hexdigest()
    release = json.loads(metadata.read_text(encoding='utf-8-sig'))
    if pin != expected_pin or release.get('ca_der_sha256') != pin or release.get('fixture') is not False:
        raise ValueError('PUBLISHED_CA_PIN_MISMATCH')
    result = subprocess.run(['openssl', 'x509', '-in', str(certificate), '-noout', '-text'], capture_output=True, check=True)
    if b'CA:TRUE' not in result.stdout or b'Certificate Sign' not in result.stdout:
        raise ValueError('PUBLIC_CA_CONSTRAINT_REQUIRED')
    subprocess.run(['openssl', 'x509', '-in', str(certificate), '-noout', '-checkend', '1209600'], capture_output=True, check=True)
    subprocess.run(['openssl', 'verify', '-check_ss_sig', '-CAfile', str(certificate), str(certificate)], capture_output=True, check=True)
    return der


def recover(output):
    if output.exists():
        raise ValueError('TRUST_OUTPUT_EXISTS')
    with tempfile.TemporaryDirectory(prefix='veliq-public-trust-') as directory:
        work = Path(directory)
        installer, archive = work/'published.exe', work/'parser.tar.gz'
        download(SETUP_URL, installer, SETUP_HASH, 64*1024*1024)
        download(PARSER_URL, archive, PARSER_HASH, 4*1024*1024)
        source = work/'source'
        source.mkdir()
        with tarfile.open(archive) as tar:
            tar.extractall(source, filter='data')
        children = list(source.iterdir())
        if len(children) != 1 or not children[0].is_dir():
            raise ValueError('PARSER_SOURCE_LAYOUT_INVALID')
        build = work/'build'
        # Build-only parser: reviewed upstream PR197 adds the 6.4.3 data layout.
        # No parser code or runtime dependency is linked into VELIQ.
        subprocess.run(['cmake', '-S', str(children[0]), '-B', str(build), '-DCMAKE_BUILD_TYPE=Release'], check=True)
        subprocess.run(['cmake', '--build', str(build), '-j', '2'], check=True)
        extracted = work/'extracted'
        subprocess.run([str(build/'innoextract'), '--include', 'app/public/ca.pem', '--include', 'app/public/release.json', '--output-dir', str(extracted), str(installer)], check=True)
        der = validate_ca(extracted/'app/public/ca.pem', extracted/'app/public/release.json')
        output.mkdir(parents=True, exist_ok=False)
        (output/'ca.der').write_bytes(der)
        (output/'provenance.json').write_text(json.dumps(dict(schema_version=1, source_release='v0.3.577', setup_sha256=SETUP_HASH, parser_commit=PARSER_COMMIT, parser_archive_sha256=PARSER_HASH, ca_der_sha256=CA_PIN), indent=2)+'\n', encoding='utf-8')
    print('PUBLISHED_PUBLIC_TRUST_VERIFIED source=v0.3.577 ca_der_sha256='+CA_PIN)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        recover(args.output)
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError):
        # No certificate/key material or arbitrary downstream exception text.
        print('PUBLIC_TRUST_RECOVERY_FAILED; source pin, parser and CA checks required')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
