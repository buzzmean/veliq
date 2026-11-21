"""Promo UI against synthetic responses only. No live accounts or provider calls."""
import json, os
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[2]
OUT=Path(os.environ.get('VELIQ_UI_OUTPUT',str(ROOT/'test-results')))
OUT.mkdir(parents=True,exist_ok=True)
with sync_playwright() as pw:
 browser=pw.chromium.launch(headless=True)
 cases=0
 for width in [390,1440]:
  for kind in ['player','club']:
   page=browser.new_page(viewport={'width':width,'height':1000})
   errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
   base=399 if kind=='player' else 299;seats=1 if kind=='player' else 3
   terms=[dict(months=m,days=m*30,discount=d if kind=='player' else 0) for m,d in [(1,0),(3,5),(6,10),(12,20)]]
   data=dict(email='redacted-person@example.invalid',kind=kind,name='Тест',payments_enabled=True,auto_renew_available=False,payment_terms=terms,
    plans=[dict(id=kind+'-month',kind=kind,title='Пользователь' if kind=='player' else 'Клуб',price_per_seat_rub=base,period_days=30,max_seats=seats)],
    subscriptions=[dict(id='a'*32,plan_id=kind+'-month',kind=kind,seats=seats,used_seats=0,active=False,lifetime=False,devices=[])],payments=[])
   calls=[];quotes=[];held=[];mode={'error':None,'hold':False}
   def route(r):
    path=r.request.url.split('https://promo.test',1)[-1].split('?',1)[0]
    if path=='/api/v1/account':r.fulfill(json=data)
    elif path.endswith('/quote'):
     q=r.request.post_data_json;quotes.append(q)
     if mode['hold']:held.append(r);return
     if mode['error']:r.fulfill(status=409,json={'error':mode['error']});return
     m=q['months'];discount=99 if kind=='player' else 30
     r.fulfill(json=dict(base_amount_kopecks=base*seats*m*100,amount_kopecks=base*seats*(m*100-min(m,3)*discount if kind=='club' else m*(100-discount)),discount=discount,days=m*30,months=m,quote_version='fixture-version',eligible_seats=seats,eligible_seconds=min(m,3)*2592000))
    elif path.endswith('/pay'):
     calls.append(r.request.post_data_json);r.fulfill(status=409,json={'error':'PROMO_RECONCILIATION_REQUIRED'})
    elif path=='/api/v1/account/club-images':r.fulfill(json={'images':[]})
    elif path.startswith('/api/'):r.fulfill(status=404,json={})
    else:
     f=ROOT/'website'/path.lstrip('/')
     if f.is_file():r.fulfill(path=str(f))
     else:r.fulfill(status=404,body='')
   page.route('**/*',route);page.goto('https://promo.test/account.html')
   page.locator('[data-step="cabinet"]').wait_for(state='visible')
   summary=page.get_by_text('У меня есть промокод',exact=True);summary.focus();summary.press('Enter')
   field=page.get_by_label('Промокод',exact=True);field.wait_for(state='visible')
   assert 'Комиссия для вас: 0' in page.locator('.acc-sub > [aria-live]').inner_text()
   for code,message in [('PROMO_INVALID','Промокод не подходит'),('PROMO_USED','Промокод уже использован'),('PROMO_RESERVED','уже создан заказ'),('PROMO_EXHAUSTED','Все места в акции'),('PROMO_FIRST_PURCHASE_ONLY','только для первой оплаченной покупки')]:
    mode['error']=code;field.fill('f'*64);field.press('Enter');page.locator('.acc-promo [role="status"]').filter(has_text=message).wait_for();cases+=1
   mode['error']=None;field.fill('a'*64);field.press('Enter');page.get_by_text('Расчёт получен.',exact=False).wait_for()
   quote=page.locator('.acc-sub > [aria-live]')
   expected=base*seats*(1 if kind=='player' else 70)
   assert ('3,99' if kind=='player' else '627,90') in quote.inner_text()
   page.screenshot(path=str(OUT/f'promo-{kind}-{width}.png'),full_page=True)
   page.get_by_role('button',name='Убрать промокод').click();assert page.get_by_role('button',name='Убрать промокод').is_hidden()
   assert ('399,00' if kind=='player' else '897,00') in quote.inner_text()
   # A response for an obsolete term must not apply after the selection changes.
   mode['hold']=True;field.fill('a'*64);field.press('Enter');page.wait_for_function('document.querySelector(".acc-promo button").disabled')
   before=len(quotes);page.locator('.acc-promo button[type=submit]').evaluate('(b)=>b.click()');assert len(quotes)==before
   page.get_by_label('Срок продления').select_option('3')
   assert held
   held.pop().fulfill(json=dict(amount_kopecks=399,base_amount_kopecks=39900,discount=99,days=30,months=1))
   mode['hold']=False
   assert ('1\xa0137,15' if kind=='player' else '2\xa0691,00') in quote.inner_text()
   page.get_by_label('Срок продления').select_option('1');field.fill('a'*64);field.press('Enter');page.get_by_text('Расчёт получен.',exact=False).wait_for()
   page.get_by_role('button',name='Оплатить',exact=True).click();page.get_by_role('dialog').get_by_role('button',name='Подтвердить и перейти к оплате').click();page.get_by_text('Предыдущий заказ ещё проверяется.',exact=False).wait_for()
   assert len(calls)==1 and 'amount_kopecks' not in calls[0]
   assert calls[0]['expected_amount_kopecks']==expected and calls[0]['promo_code']=='a'*64 and calls[0]['months']==1
   assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
   assert not errors,errors
   cases+=4;page.close()
 browser.close()
print(json.dumps(dict(status='PASS',cases=cases,viewports=[390,1440],provider='synthetic',production_requests=0)))
