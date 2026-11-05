"""Real widget + HTTP service + isolated SQL + simulated Telegram, no production calls."""
import argparse
import json
import os
import shutil
import urllib.request
from playwright.sync_api import sync_playwright, expect

parser = argparse.ArgumentParser()
parser.add_argument('--origin', required=True)
args = parser.parse_args()
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.environ.get('VELIQ_SUPPORT_BROWSER_EXECUTABLE') or shutil.which('chromium') or shutil.which('google-chrome'), headless=True, args=['--no-sandbox'])
    context = browser.new_context(viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    # Avoid unrelated website release metadata and availability probes.
    page.route('**/*', lambda route: route.continue_() if route.request.url.startswith(args.origin) else route.abort())
    errors = []
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.goto(args.origin + '/support.html')
    page.locator('.vs-launch').click()
    expect(page.locator('.vs-status')).to_have_text('Напишите нам')
    page.locator('#vs-input').fill('Не могу войти на сервер <img src=x onerror=alert(1)>')
    # Lose the HTTP response AFTER the backend committed, then retry the same message.
    dropped = [False]
    def lose_response(route):
        if not dropped[0]:
            dropped[0] = True
            route.fetch()
            route.abort('failed')
        else:
            route.continue_()
    page.route('**/api/v1/support/message', lose_response)
    page.locator('.vs-form button').click()
    expect(page.locator('.vs-error')).to_be_visible()
    expect(page.locator('.vs-message--visitor')).to_have_count(1)
    page.locator('.vs-form button').click()
    expect(page.locator('#vs-input')).to_have_value('')
    expect(page.locator('.vs-message--visitor')).to_have_count(1)
    page.unroute('**/api/v1/support/message', lose_response)
    expect(page.locator('.vs-status')).to_have_text('Обращение в очереди')
    expect(page.locator('.vs-message--visitor')).to_have_count(1)
    page.reload()
    expect(page.locator('.vs-panel')).to_be_visible()
    expect(page.locator('.vs-message--visitor')).to_have_count(1)
    page.locator('.vs-close').click()
    expect(page.locator('.vs-confirm')).to_be_visible()
    page.locator('[data-answer=no]').click()
    expect(page.locator('.vs-confirm')).to_be_hidden()
    expect(page.locator('.vs-status')).to_have_text('Обращение в очереди')
    req = urllib.request.Request(args.origin + '/_fixture/reply', data=b'', headers={'X-Fixture': os.environ['VELIQ_SUPPORT_FIXTURE_KEY']})
    with urllib.request.urlopen(req, timeout=5) as response:
        assert response.status == 204
    expect(page.locator('.vs-message--operator')).to_have_count(1, timeout=12000)
    expect(page.locator('.vs-message--operator p')).to_have_text('Ответ специалиста <script>alert(1)</script>')
    assert page.locator('.vs-messages script, .vs-messages img').count() == 0
    # A separate browser cannot read this visitor's ticket.
    other = browser.new_context()
    response = other.request.get(args.origin + '/api/v1/support/state')
    assert response.json()['ticket'] is None
    other.close()
    # Two tabs restore the same authoritative ticket.
    tab = context.new_page()
    tab.goto(args.origin + '/support.html')
    tab.locator('.vs-launch').click()
    expect(tab.locator('.vs-message--operator')).to_have_count(1)
    page.locator('.vs-close').click()
    page.locator('[data-answer=yes]').click()
    expect(page.locator('.vs-panel')).to_be_hidden()
    page.reload()
    page.locator('.vs-launch').click()
    expect(page.locator('.vs-resolved')).to_be_visible()
    expect(tab.locator('.vs-resolved')).to_be_visible(timeout=12000)
    page.locator('.vs-new').click()
    page.locator('#vs-input').fill('Второй вопрос')
    page.locator('.vs-form button').click()
    expect(page.locator('.vs-status')).to_have_text('Обращение в очереди')
    expect(page.locator('.vs-message--visitor')).to_have_count(1)
    page.set_viewport_size({'width': 360, 'height': 740})
    box = page.locator('.vs-panel').bounding_box()
    assert box['x'] >= 0 and box['x'] + box['width'] <= 360 and box['y'] >= 0
    page.screenshot(path=os.environ.get('VELIQ_SUPPORT_SCREENSHOT', '/tmp/veliq-support-mobile.png'))
    page.on('dialog', lambda d: d.accept())
    page.locator('.vs-forget').click()
    expect(page.locator('.vs-message')).to_have_count(0)
    page.reload()
    expect(page.locator('.vs-message')).to_have_count(0)
    assert not errors, errors
    browser.close()
print('SUPPORT_BROWSER_PASS: reload, two tabs, Telegram reply, XSS, resolve, new ticket, mobile, forget')
