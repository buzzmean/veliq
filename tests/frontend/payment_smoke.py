"""Cabinet UI contract against synthetic API responses; no provider or production I/O."""
import json
import os
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
terms = [dict(months=m, days=m*30, discount=d) for m,d in [(1,0),(3,5),(6,10),(12,20)]]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, executable_path=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH'))
    cases = 0
    hosted_redirects = 0
    for width in [390, 1440]:
        for kind in ['player','club']:
            page = browser.new_page(viewport=dict(width=width, height=1000))
            errors = []
            page.on('pageerror', lambda e: errors.append(str(e)))
            seats = 3 if kind == 'club' else 1
            base = 299 if kind == 'club' else 399
            account_terms = [dict(t,discount=0) if kind=='club' else t for t in terms]
            sub = dict(id='a'*32, plan_id=kind+'-month',kind=kind,seats=seats,active=False,paid_until=None,lifetime=False,used_seats=0,devices=[])
            data = dict(email='fixture@example.test',kind=kind,name='',subscriptions=[sub],plans=[dict(id=kind+'-month',kind=kind,title='Клуб' if kind=='club' else 'Пользователь',price_per_seat_rub=base,period_days=30,max_seats=500 if kind=='club' else 1)],payments_enabled=True,auto_renew_available=False,payment_terms=account_terms,payments=[dict(id='b'*32,provider='platega',amount_kopecks=113715,period_days=90,status='pending',created_at='2026-11-17T12:00:00Z',review_required=False)])
            requests = []
            result = dict(status='pending',review_required=False)
            create_success = dict(enabled=False)
            hosted_url = 'https://pay.platega.io/?id=synthetic-hosted-choice'
            def route(r):
                if r.request.url == hosted_url:
                    r.fulfill(content_type='text/html',body='<title>Synthetic hosted choice</title>')
                    return
                path = r.request.url.split('https://cabinet.test',1)[-1].split('?',1)[0]
                if path == '/api/v1/account':
                    r.fulfill(json=data)
                elif path.endswith('/quote'):
                    q=r.request.post_data_json
                    term=next(t for t in account_terms if t['months']==q['months'])
                    amount=base*seats*q['months']*(100-term['discount'])
                    r.fulfill(json=dict(subscription_id=sub['id'],seats=seats,months=q['months'],days=term['days'],
                        base_amount_kopecks=base*seats*q['months']*100,amount_kopecks=amount,quote_version='fixture-quote',
                        operation='renewal' if sub['paid_until'] else 'purchase'))
                elif path.endswith('/pay'):
                    requests.append(r.request.post_data_json)
                    # Keep this browser in the cabinet for assertions and retry UX.
                    if create_success['enabled']:r.fulfill(json=dict(redirect=hosted_url))
                    else:r.fulfill(status=502,json=dict(error='PAYMENT_UNAVAILABLE'))
                elif path.endswith('/refresh'):
                    data['payments'][0].update(result)
                    if result['status']=='succeeded':
                        sub.update(active=True,paid_until='2027-02-15T12:00:00Z')
                    r.fulfill(json=result)
                elif path == '/api/v1/account/club-images':
                    r.fulfill(json=dict(images=[]))
                elif path.startswith('/api/'):
                    r.fulfill(status=404,json={})
                else:
                    f=ROOT/'website'/path.lstrip('/')
                    if f.is_file():r.fulfill(path=str(f))
                    else:r.fulfill(status=404,body='')
            page.route('**/*', route)
            page.goto('https://cabinet.test/account.html?payment=return')
            page.locator('[data-step="cabinet"]').wait_for(state='visible')
            assert page.get_by_text('У меня есть промокод',exact=True).count()==1
            select=page.get_by_label('Срок продления')
            assert select.locator('option').count()==4
            for term in account_terms:
                select.select_option(str(term['months']))
                expected=base*seats*term['months']*(100-term['discount'])
                assert str(term['days'])+' дней' in page.locator('.acc-sub [aria-live]').inner_text()
                page.locator('.acc-sub').get_by_role('button',name='Оплатить',exact=True).click()
                dialog=page.get_by_role('dialog');dialog.wait_for()
                dialog.get_by_role('button',name='Подтвердить и перейти к оплате').click()
                page.get_by_text('Не удалось создать оплату.',exact=False).wait_for()
                sent=dict(requests[-1])
                assert sent.pop('idempotency_key'), 'Every checkout needs a durable order key'
                if kind=='club':
                    assert sent.pop('quote_version')=='fixture-quote'
                assert sent==dict(auto_renew=False,months=term['months'],expected_amount_kopecks=expected),requests
                # A lost/ambiguous response must retry the same order, including
                # for personal access. A second click must not create a new key.
                previous=dict(requests[-1]);before=len(requests)
                dialog.get_by_role('button',name='Подтвердить и перейти к оплате').click()
                page.wait_for_function('!document.querySelector("dialog button").disabled')
                assert len(requests)==before+1 and requests[-1]==previous, requests
                dialog.get_by_role('button',name='Вернуться к выбору').click()
                cases+=1
            assert '1\xa0137,15' in page.locator('[data-payments]').inner_text()
            page.get_by_role('button',name='Проверить оплату',exact=True).click()
            page.get_by_text('Подтверждение ещё не получено.',exact=False).wait_for()
            result['status']='succeeded'
            page.get_by_role('button',name='Проверить оплату',exact=True).click()
            page.get_by_text('Оплата подтверждена. Срок доступа обновлён.',exact=True).wait_for()
            assert 'Оплачено до' in page.locator('.acc-sub__head').inner_text()
            # A lifetime subscription must never offer another purchase.
            sub['lifetime']=True
            page.reload();page.locator('[data-step="cabinet"]').wait_for(state='visible')
            assert page.locator('.acc-sub').get_by_role('button',name='Продлить',exact=True).count()==0
            sub['lifetime']=False;data['payments_enabled']=False
            page.reload();page.locator('[data-step="cabinet"]').wait_for(state='visible')
            before=len(requests)
            page.locator('.acc-sub').get_by_role('button',name='Продлить',exact=True).click()
            assert len(requests)==before
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'horizontal overflow'
            assert not errors,errors
            # VELIQ sends the term/amount only, then navigates to the provider's
            # method chooser. All navigation is intercepted; no provider I/O.
            data['payments_enabled']=True
            sub['active']=False
            create_success['enabled']=True
            page.reload();page.locator('[data-step="cabinet"]').wait_for(state='visible')
            page.locator('.acc-sub').get_by_role('button',name='Продлить',exact=True).click()
            page.get_by_role('dialog').get_by_role('button',name='Подтвердить и перейти к оплате').click()
            page.wait_for_url(hosted_url)
            assert page.title()=='Synthetic hosted choice'
            assert 'paymentMethod' not in requests[-1] and 'payment_method' not in requests[-1]
            hosted_redirects+=1
            page.close()
    browser.close()
print(json.dumps(dict(result='PASS',purchase_cases=cases,hosted_redirects=hosted_redirects,viewports=[390,1440],provider='mock',production_payment=False)))
