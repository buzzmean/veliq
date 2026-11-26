"""Club invitation/credit checkout against synthetic same-origin API; no production I/O."""
import functools
import http.server
from pathlib import Path
import os
from threading import Thread

from playwright.sync_api import expect, sync_playwright


class StaticFiles(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


site = Path(__file__).resolve().parents[2] / 'website'
handler = functools.partial(StaticFiles, directory=site)
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
Thread(target=server.serve_forever, daemon=True).start()
origin = f'http://127.0.0.1:{server.server_port}'
invite = 'vi-' + 'a' * 32
credit = 'vr-' + 'b' * 32
club = {
    'email': 'synthetic-club@example.test',
    'kind': 'club',
    'name': 'Тестовый клуб',
    'payments_enabled': True,
    'payment_terms': [{'months': 1, 'days': 30, 'discount': 0}],
    'plans': [{'id': 'club-month', 'title': 'Клуб', 'kind': 'club', 'price_per_seat_rub': 299, 'period_days': 30, 'max_seats': 500}],
    'subscriptions': [],
    'club_referrals': {'can_claim': True, 'can_invite': False, 'claimed': False, 'claim_earned': False, 'credits': []},
}
seen = []
page_errors = []


def route(request):
    assert request.request.url.startswith(origin + '/api/v1/account')
    path = request.request.url.removeprefix(origin + '/api/v1/account')
    method = request.request.method
    if path == '':
        return request.fulfill(json=club)
    if path == '/club-images':
        return request.fulfill(json={'images': []})
    if (method, path) == ('POST', '/club-invitations/claim'):
        seen.append((path, request.request.post_data_json))
        club['club_referrals'].update(can_claim=False, claimed=True)
        return request.fulfill(json={'claimed': True})
    if (method, path) == ('POST', '/club-invitations/link'):
        seen.append((path, request.request.post_data_json))
        club['club_referrals']['invitation_code'] = invite
        return request.fulfill(json={'invitation_code': invite})
    if (method, path) == ('POST', '/subscriptions/' + 'c' * 32 + '/quote'):
        seen.append((path, request.request.post_data_json))
        return request.fulfill(json={'base_amount_kopecks': 59800, 'amount_kopecks': 41860, 'days': 30, 'seats': 2,
                                     'eligible_seconds': 0, 'referral_discount': True, 'operation': 'renewal'})
    request.fulfill(status=404, json={})


try:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH'), headless=True,
                                            args=['--disable-background-networking'])
        context = browser.new_context(viewport={'width': int(os.environ.get('VELIQ_TEST_WIDTH', '390')), 'height': 1000}, color_scheme=os.environ.get('VELIQ_TEST_COLOR_SCHEME', 'dark'))
        context.route('**/*', lambda request: request.continue_() if request.request.url.startswith(origin + '/') else request.abort())
        context.route(origin + '/api/v1/account**', route)
        page = context.new_page()
        page.on('pageerror', lambda error: page_errors.append(str(error)))
        page.goto(origin + '/account.html')
        panel = page.locator('[data-club-referrals]')
        expect(panel).to_be_visible()
        panel.get_by_label('Код приглашения от другого клуба').fill(invite)
        panel.get_by_role('button', name='Принять приглашение').click()
        expect(panel.get_by_text('Приглашение принято.')).to_be_visible()

        club['club_referrals'].update(can_invite=True, claim_earned=True,
                                      credits=[{'code': credit, 'state': 'available'}, {'code': 'vr-' + 'd' * 32, 'state': 'reserved'}])
        club['subscriptions'] = [{'id': 'c' * 32, 'plan_id': 'club-month', 'kind': 'club', 'seats': 2, 'used_seats': 1,
                                  'active': True, 'paid_until': '2030-01-01T00:00:00Z', 'devices': []}]
        page.reload()
        panel.get_by_role('button', name='Получить код приглашения').click()
        expect(panel.get_by_text(invite, exact=True)).to_be_visible()
        expect(panel.get_by_text(credit, exact=True)).to_be_visible()
        expect(panel.get_by_text('Скидка закреплена за заказом')).to_be_visible()
        assert not page.evaluate('document.documentElement.scrollWidth > document.documentElement.clientWidth')
        page.get_by_text('У меня есть промокод').click()
        page.get_by_label('Промокод', exact=True).fill(credit)
        page.get_by_role('button', name='Применить', exact=True).click()
        expect(page.get_by_text('Расчёт получен.', exact=False)).to_be_visible()
        page.get_by_role('button', name='Продлить', exact=True).click()
        dialog = page.get_by_role('dialog')
        expect(dialog.get_by_text('Клубное приглашение даёт скидку 30% на это продление на 30 дней.')).to_be_visible()
        expect(dialog.get_by_text('К оплате:', exact=False)).to_contain_text('418,60')
        assert seen[0][1] == {'code': invite}
        assert all(data.get('promo_code') == credit and data['months'] == 1 for path, data in seen[2:])
        assert not page_errors, 'browser reported JavaScript errors'
        browser.close()
    print('CLUB_REFERRAL_CHROMIUM_PASS mobile layout, invitation, credit states, one-month quote (mocked API)')
finally:
    server.shutdown()
    server.server_close()
