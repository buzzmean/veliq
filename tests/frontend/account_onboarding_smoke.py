"""Real account browser + HTTPS + isolated PostgreSQL + client-service fixture.

Only the Go test starts this fixture. The SMTP inbox and synthetic credit endpoints
exist in that test process, require its private test token, and never ship.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import urllib.request
import uuid

from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser()
parser.add_argument('--fixture', required=True, type=Path)
args = parser.parse_args()
fixture = json.loads(args.fixture.read_text())
tls = ssl.create_default_context(cafile=fixture['ca_path'])

def call(path, body=None):
    raw = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(fixture['origin'] + '/_fixture/' + path, data=raw,
        headers={'Content-Type': 'application/json', 'X-Veliq-Fixture': fixture['token']})
    with urllib.request.urlopen(request, context=tls, timeout=5) as response:
        return json.load(response)

certutil = shutil.which('certutil')
if not certutil:
    raise RuntimeError('certutil required for ephemeral browser trust; certificate checks stay enabled')
db = Path.home() / '.pki/nssdb'
db.mkdir(parents=True, exist_ok=True)
if not (db / 'cert9.db').exists():
    subprocess.run([certutil, '-N', '-d', 'sql:' + str(db), '--empty-password'], check=True,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
nickname = 'VELIQ-account-fixture-' + uuid.uuid4().hex
subprocess.run([certutil, '-A', '-d', 'sql:' + str(db), '-n', nickname, '-t', 'C,,',
                '-i', fixture['ca_path']], check=True, stdin=subprocess.DEVNULL,
               capture_output=True, timeout=10)
try:
    with sync_playwright() as p, tempfile.TemporaryDirectory(prefix='veliq-account-browser-') as profile:
        browser = p.chromium.launch_persistent_context(profile,
            executable_path=os.environ.get('VELIQ_ACCOUNT_BROWSER_EXECUTABLE') or shutil.which('chromium') or shutil.which('google-chrome') or None, headless=True,
            args=['--no-sandbox', '--disable-background-networking', '--no-first-run'])
        page = browser.new_page()
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto(fixture['url'])
        email = 'browser-' + uuid.uuid4().hex[:12] + '@example.test'
        page.locator('[data-email-form] input[name=email]').fill(email)
        page.locator('[data-email-form] button[type=submit]').click()
        page.locator('[data-code-form]').wait_for(state='visible')
        code_input = page.locator('[data-code-form] input[name=code]')
        for width in (390, 1280):
            page.set_viewport_size({'width': width, 'height': 844})
            box = code_input.bounding_box()
            if not box or box['width'] < 200 or box['height'] < 48:
                raise RuntimeError('OTP input is too small')
            if page.evaluate('document.documentElement.scrollWidth > document.documentElement.clientWidth'):
                raise RuntimeError('account page overflows horizontally')
        code = call('inbox')['code']
        if not code:
            raise RuntimeError('fixture mail did not arrive')
        page.locator('[data-code-form] input[name=code]').fill(code)
        page.locator('[data-code-form] button[type=submit]').click()
        page.locator('[data-profile-form]').wait_for(state='visible')
        if page.locator('[data-profile-name-field]').is_visible():
            raise RuntimeError('profile name appears before account type is selected')
        if page.locator('[data-profile-continue]').is_enabled():
            raise RuntimeError('profile submit enabled before account type selection')
        page.locator('[data-profile-form] select[name=kind]').select_option(fixture['kind'])
        expected_label = 'Название клуба' if fixture['kind'] == 'club' else 'Ваше имя'
        if page.locator('[data-profile-name-label]').inner_text() != expected_label:
            raise RuntimeError('profile label does not match account type')
        page.locator('[data-profile-form] input[name=name]').fill('Browser Test Club' if fixture['kind'] == 'club' else 'Browser Test Player')
        page.locator('[data-profile-form] button').click()
        page.locator('[data-step=cabinet]').wait_for(state='visible')
        if page.locator('[data-images-section]').is_visible() != (fixture['kind'] == 'club'):
            raise RuntimeError('club images section shown for the wrong account type')
        expected = 'Клуб' if fixture['kind'] == 'club' else 'Пользователь'
        if expected not in page.locator('[data-account-kind]').inner_text():
            raise RuntimeError('account type is not shown')
        with page.expect_response(lambda response: response.request.method == 'POST' and
                                  response.url.endswith('/api/v1/account/subscriptions')) as created:
            page.locator('[data-plans] button[type=submit]').first.click()
        response = created.value
        if response.status != 201:
            raise RuntimeError('subscription creation rejected')
        subscription = response.json()['id']
        call('credit', {'subscription_id': subscription})
        page.reload()
        page.locator('[data-link-subscription] option').first.wait_for(state='attached')
        page.locator('[data-link-subscription]').select_option(subscription)
        page.locator('[data-link-approve]').click()
        page.wait_for_function("() => document.querySelector('[data-link-message]').textContent.includes('Разрешение отправлено')")
        for _ in range(30):
            result = call('client')
            if result['linked']:
                break
            page.wait_for_timeout(500)
        else:
            raise RuntimeError('client did not persist verified device identity')
        if not result['has_identity'] or result['manual_code'] or result['kind'] != fixture['kind']:
            raise RuntimeError('client did not finish code-free account binding')
        page.reload()
        page.locator('[data-subs] .acc-devices li').first.wait_for(state='visible')
        if page.get_by_role('button', name='Получить код активации', exact=True).count():
            raise RuntimeError('main cabinet still requires manual activation codes')
        if errors:
            raise RuntimeError('browser JavaScript errors (details suppressed)')
        page.locator('[data-logout]').click()
        page.locator('[data-email-form]').wait_for(state='visible')
        check = page.evaluate("fetch('/api/v1/account', {credentials:'same-origin'}).then(r=>r.status)")
        if check != 401:
            raise RuntimeError('logout did not revoke the session')
        browser.close()
    print('ACCOUNT_BROWSER_HTTPS_PASS kind=' + fixture['kind'] + '; register/login/profile/subscription/approve/client identity/PC list/logout; no activation code; TLS verified')
finally:
    subprocess.run([certutil, '-D', '-d', 'sql:' + str(db), '-n', nickname], check=True,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
