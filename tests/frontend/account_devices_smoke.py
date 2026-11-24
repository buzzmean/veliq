"""Кабинет: синтетические данные, все запросы перехвачены, без оплаты и отправки сообщений."""
import json
import os
import shutil
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
with sync_playwright() as pw:
    browser = pw.chromium.launch(executable_path=os.environ.get('CHROMIUM_PATH') or shutil.which('chromium') or shutil.which('google-chrome') or None, headless=True)
    for kind in ('club', 'player'):
        for width in (390, 1440):
            page = browser.new_page(viewport={'width': width, 'height': 950})
            errors = []
            page.on('pageerror', lambda e: errors.append(str(e)))
            calls = []
            device = dict(name='PC13', machine='a'*12, label='VIP <место 13>', version='0.3.735', connection_state='online', last_seen='2026-11-24T20:10:00Z')
            sub = dict(id='1'*32, plan_id='plan', kind=kind, seats=36 if kind=='club' else 1, active=True, can_connect=True, lifetime=True, used_seats=2, devices=[device, dict(name='VELIQ device', machine='b'*12)])
            if kind == 'club': sub['club_verification'] = 'verified'
            data = dict(server_time='2026-11-24T20:11:00Z', email='fixture@example.invalid', kind=kind, name='Фикстура', subscriptions=[sub, dict(sub, id='2'*32, active=False, lifetime=False, devices=[], used_seats=0)], plans=[], payments_enabled=False, payments=[dict(id='p', subscription_id=sub['id'], provider='platega', status='canceled', created_at='2026-01-01T00:00:00Z', amount_kopecks=399, period_days=30)])
            def route(r):
                path = r.request.url.split('https://fixture.test', 1)[-1].split('?', 1)[0]
                if r.request.method == 'POST':
                    calls.append((path, r.request.post_data_json))
                if path == '/api/v1/account': r.fulfill(json=data)
                elif path.endswith('/code'): r.fulfill(json={'code':'VELIQ-FIXTURE-ONLY'})
                elif path.endswith('/label'):
                    device['label'] = r.request.post_data_json['label']; r.fulfill(json={'ok':True})
                elif path == '/api/v1/account/club-images': r.fulfill(json={'images':[]})
                elif path.startswith('/api/'): r.fulfill(status=404, json={})
                else:
                    f=ROOT/'website'/path.lstrip('/')
                    if f.is_file(): r.fulfill(path=str(f))
                    else: r.fulfill(status=404, body='')
            page.route('**/*', route)
            page.goto('https://fixture.test/account.html')
            page.locator('[data-step="cabinet"]').wait_for(state='visible')
            card = page.locator('#subscription-'+sub['id'])
            assert 'PC13' in card.inner_text() and '0.3.735' in card.inner_text()
            assert 'Имя ПК ещё не получено' in card.inner_text()
            assert not page.locator('[data-subs] script').count()
            assert not page.get_by_role('button', name='Проверить оплату', exact=True).count()
            assert page.locator('[data-payments] details').count()==1 and not page.locator('[data-payments] details').evaluate('(e)=>e.open')
            assert '3,99' not in page.locator('[data-payments]').inner_text()
            search=card.get_by_role('searchbox'); search.fill('PC13')
            assert card.locator('.acc-devices > li:visible').count()==1
            search.fill('')
            card.get_by_role('button', name='Добавить ПК', exact=True).click()
            card.get_by_role('button', name='Сгенерировать код', exact=True).click()
            card.locator('output').wait_for(state='visible')
            assert len(calls)==1 and calls[0][0].endswith('/code')
            row=card.locator('[data-device="'+'a'*12+'"]')
            row.get_by_role('button', name='Подписать место').click()
            row.get_by_label('Название места').fill('У окна')
            row.get_by_role('button', name='Сохранить', exact=True).click()
            page.wait_for_function("() => document.querySelector('[data-device] .acc-device__info').textContent.includes('У окна')")
            support=page.locator('[data-device]').first.get_by_role('link', name='Сообщить о проблеме')
            assert 'PC13' in support.get_attribute('data-support-draft')
            assert not any('/support' in p for p,_ in calls)
            if kind=='player': assert page.locator('[data-subs] > .acc-sub').count()==1 and page.locator('.acc-subscription-history').count()==1
            assert not page.evaluate('document.documentElement.scrollWidth > innerWidth'), (kind,width)
            assert not errors, errors
            if kind=='club' and width==1440 and os.environ.get('VELIQ_UI_OUTPUT'):
                out=Path(os.environ['VELIQ_UI_OUTPUT']);out.mkdir(parents=True,exist_ok=True);page.screenshot(path=str(out/'cabinet-club.png'),full_page=True)
            page.close()
    browser.close()
print('PASS: клуб/игрок, 390/1440, имена/поиск/код/подпись/история, без отправки сообщений')
