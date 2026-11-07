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
    page.route('**/api/v1/account/support/message', lose_response)
    page.locator('.vs-form button').click()
    expect(page.locator('.vs-error')).to_be_visible()
    expect(page.locator('.vs-message--visitor')).to_have_count(1)
    page.locator('.vs-form button').click()
    expect(page.locator('#vs-input')).to_have_value('')
    expect(page.locator('.vs-message--visitor')).to_have_count(1)
    page.unroute('**/api/v1/account/support/message', lose_response)
    expect(page.locator('.vs-status')).to_have_text('Обращение в очереди')
    expect(page.locator('.vs-message--visitor')).to_have_count(1)
    page.reload()
    expect(page.locator('.vs-panel')).to_be_visible()
    expect(page.locator('.vs-message--visitor')).to_have_count(1)
    page.locator('.vs-close').click()
    expect(page.locator('.vs-confirm')).to_be_visible()
    expect(page.locator('[data-answer=later]')).to_have_text('Свернуть')
    page.locator('[data-answer=later]').click()
    expect(page.locator('.vs-panel')).to_be_hidden()
    page.locator('.vs-launch').click()
    expect(page.locator('.vs-status')).to_have_text('Обращение в очереди')
    page.locator('.vs-close').click()
    page.keyboard.press('Escape')
    expect(page.locator('.vs-panel')).to_be_visible()
    expect(page.locator('.vs-confirm')).to_be_hidden()
    page.locator('.vs-close').click()
    page.locator('[data-answer=no]').click()
    expect(page.locator('.vs-confirm')).to_be_hidden()
    expect(page.locator('.vs-status')).to_have_text('Обращение в очереди')
    req = urllib.request.Request(args.origin + '/_fixture/reply', data=b'', headers={'X-Fixture': os.environ['VELIQ_SUPPORT_FIXTURE_KEY']})
    with urllib.request.urlopen(req, timeout=5) as response:
        assert response.status == 204
    expect(page.locator('.vs-message--operator')).to_have_count(1, timeout=12000)
    expect(page.locator('.vs-answer-check')).to_be_visible()
    page.locator('.vs-answer-no').click()
    expect(page.locator('.vs-answer-check')).to_be_hidden()
    expect(page.locator('#vs-input')).to_be_focused()
    expect(page.locator('.vs-message--operator p')).to_have_text('Ответ специалиста <script>alert(1)</script>')
    assert page.locator('.vs-messages script, .vs-messages img').count() == 0
    # A separate browser cannot read this visitor's ticket.
    other = browser.new_context()
    response = other.request.get(args.origin + '/api/v1/account/support/state')
    assert response.json()['ticket'] is None
    other.close()
    # Two tabs restore the same authoritative ticket.
    tab = context.new_page()
    tab.goto(args.origin + '/support.html')
    tab.locator('.vs-launch').click()
    expect(tab.locator('.vs-message--operator')).to_have_count(1)
    page.locator('.vs-close').click()
    # A reply that arrives while the close choice is visible must invalidate it.
    with urllib.request.urlopen(req, timeout=5) as response:
        assert response.status == 204
    expect(page.locator('.vs-message--operator')).to_have_count(2, timeout=12000)
    page.locator('[data-answer=yes]').click()
    expect(page.locator('.vs-error')).to_contain_text('Прочитайте новые сообщения')
    expect(page.locator('.vs-confirm')).to_be_hidden()
    expect(page.locator('.vs-status')).to_have_text('Обращение у специалиста')
    page.locator('.vs-answer-yes').click()
    page.screenshot(path=os.environ.get('VELIQ_SUPPORT_DESKTOP_CLOSE_SCREENSHOT','/tmp/veliq-support-close-desktop.png'))
    page.set_viewport_size({'width':360,'height':740})
    choice=page.locator('.vs-confirm').bounding_box()
    assert choice['x']>=0 and choice['y']>=0 and choice['x']+choice['width']<=360 and choice['y']+choice['height']<=740, choice
    page.screenshot(path=os.environ.get('VELIQ_SUPPORT_MOBILE_CLOSE_SCREENSHOT','/tmp/veliq-support-close-mobile.png'))
    page.set_viewport_size({'width':1280,'height':900})
    # An unconfirmed close keeps the same idempotency key for transport retry.
    resolve_bodies=[]
    def lose_close(route):
        resolve_bodies.append(route.request.post_data_json)
        if len(resolve_bodies)==1:
            route.abort('failed')
        else:
            route.continue_()
    page.route('**/api/v1/account/support/resolve',lose_close)
    page.locator('[data-answer=yes]').click()
    expect(page.locator('.vs-close-error')).to_contain_text('Завершение не подтверждено')
    expect(page.locator('.vs-panel')).to_be_visible()
    expect(page.locator('.vs-confirm')).to_be_visible()
    page.locator('[data-answer=yes]').evaluate('(button) => { button.click(); button.click(); }')
    expect(page.locator('.vs-panel')).to_be_hidden()
    assert len(resolve_bodies)==2 and resolve_bodies[0]==resolve_bodies[1], resolve_bodies
    page.unroute('**/api/v1/account/support/resolve',lose_close)
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
    # If closure committed but its HTTP response was lost, authoritative state
    # must confirm closure without leaving a contradictory transport error.
    def lose_committed_close(route):
        route.fetch()
        route.abort('failed')
    page.route('**/api/v1/account/support/resolve',lose_committed_close)
    page.locator('.vs-close').click()
    page.locator('[data-answer=yes]').click()
    expect(page.locator('.vs-resolved')).to_be_visible()
    expect(page.locator('.vs-confirm')).to_be_hidden()
    expect(page.locator('.vs-error')).to_be_hidden()
    page.unroute('**/api/v1/account/support/resolve',lose_committed_close)
    page.on('dialog', lambda d: d.accept())
    page.locator('.vs-info-toggle').click()
    page.locator('.vs-forget').click()
    page.locator('.vs-forget-yes').click()
    expect(page.locator('.vs-message')).to_have_count(0)
    page.reload()
    expect(page.locator('.vs-message')).to_have_count(0)
    # Real path-scoped account cookie: the old support path cannot receive it.
    def login(target, who):
        assert target.evaluate("""async who => (await fetch('/api/v1/account/login/verify', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:who+'@example.test',code:'fixture'})})).ok""", who)
    def logout(target):
        assert target.evaluate("""async () => (await fetch('/api/v1/account/logout', {method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})).ok""")
    login(page,'alice')
    expect(page.locator('#vs-input')).to_be_enabled()
    page.locator('#vs-input').fill('ACCOUNT ALICE PRIVATE')
    page.locator('.vs-form button').click()
    expect(page.locator('.vs-message--visitor p')).to_have_text('ACCOUNT ALICE PRIVATE')
    tab.reload()
    expect(tab.locator('.vs-message--visitor p')).to_have_text('ACCOUNT ALICE PRIVATE')
    page.locator('#vs-input').fill('UNSENT ALICE DRAFT')
    captured=[]
    def hold_old_account(route):
        response=route.fetch()
        if response.ok and 'ACCOUNT ALICE PRIVATE' in response.text():
            captured.append((route,response))
        else: route.fulfill(response=response)
    page.route('**/api/v1/account/support/state',hold_old_account)
    page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
    page.wait_for_function("document.querySelector('.vs-status').textContent==='Проверяем сессию…'")
    for _ in range(40):
        if captured: break
        page.wait_for_timeout(100)
    assert captured, 'old response not captured'
    logout(tab)
    login(tab,'bob')
    expect(tab.locator('.vs-message')).to_have_count(0)
    for route,response in captured: route.fulfill(response=response)
    page.unroute('**/api/v1/account/support/state',hold_old_account)
    expect(page.locator('.vs-message')).to_have_count(0)
    expect(page.locator('#vs-input')).to_have_value('')
    expect(tab.locator('#vs-input')).to_be_enabled()
    tab.locator('#vs-input').fill('ACCOUNT BOB PRIVATE')
    tab.locator('.vs-form button').click()
    expect(tab.locator('.vs-message--visitor p')).to_have_text('ACCOUNT BOB PRIVATE')
    tab.reload()
    expect(tab.locator('.vs-message--visitor p')).to_have_text('ACCOUNT BOB PRIVATE')
    logout(tab)
    expect(tab.locator('.vs-message')).to_have_count(0)
    login(tab,'alice')
    expect(tab.locator('.vs-message--visitor p')).to_have_text('ACCOUNT ALICE PRIVATE')
    # Guest history is never automatically attached during sign-in.
    logout(tab)
    expect(tab.locator('#vs-input')).to_be_enabled()
    tab.locator('#vs-input').fill('GUEST BEFORE LOGIN')
    tab.locator('.vs-form button').click()
    expect(tab.locator('.vs-message--visitor p')).to_have_text('GUEST BEFORE LOGIN')
    login(tab,'carol')
    expect(tab.locator('.vs-message')).to_have_count(0)
    logout(tab)
    expect(tab.locator('.vs-message')).to_have_count(0)
    assert not errors, errors
    browser.close()
print('SUPPORT_BROWSER_PASS: reload, two tabs, Telegram reply, XSS, resolve, new ticket, mobile, forget, account switch, stale response, logout, guest isolation')
