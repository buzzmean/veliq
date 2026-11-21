"""Synthetic browser fixtures only. Every request is intercepted; no provider/production."""
import json, os
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[2]
OUT=Path(os.environ['VELIQ_UI_OUTPUT'])
OUT.mkdir(parents=True,exist_ok=True)
cases=0
with sync_playwright() as pw:
 browser=pw.chromium.launch(headless=True)
 for width in [390,1440]:
  page=browser.new_page(viewport={'width':width,'height':1000})
  errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
  def subscription(id,paid=None):
   return dict(id=id,plan_id='club-month',kind='club',seats=1,paid_until=paid,used_seats=0,active=False,lifetime=False,devices=[])
  data=dict(email='fixture@example.invalid',kind='club',name='Клуб Фикстура',payments_enabled=True,auto_renew_available=False,
   payment_terms=[dict(months=m,days=m*30,discount=0) for m in [1,3,6,12]],
   plans=[dict(id='club-month',kind='club',title='Клуб',price_per_seat_rub=299,period_days=30,max_seats=500)],
   subscriptions=[subscription('a'*32),subscription('b'*32,'2026-01-01T00:00:00Z')],
   payments=[dict(id='d'*32,subscription_id='b'*32,provider='fixture',amount_kopecks=20930,period_days=30,status='canceled',created_at='2026-01-01T00:00:00Z')],club_orders=[])
  calls=[];quotes=[];mode={'error':None}
  def route(r):
   path=r.request.url.split('https://fixture.test',1)[-1].split('?',1)[0]
   if path=='/api/v1/account':r.fulfill(json=data)
   elif path=='/api/v1/account/subscriptions':
    data['subscriptions'].append(subscription('c'*32));r.fulfill(status=201,json={'id':'c'*32})
   elif path.endswith('/quote'):
    q=r.request.post_data_json;quotes.append(q)
    if mode['error']:r.fulfill(status=409,json={'error':mode['error']});return
    m=q['months'];base=29900*m;discount=8970*min(m,3) if q.get('promo_code') else 0
    r.fulfill(json=dict(base_amount_kopecks=base,amount_kopecks=base-discount,discount=30 if discount else 0,days=m*30,months=m,
     subscription_id=path.split('/')[-2],seats=1,eligible_seats=1 if discount else 0,eligible_seconds=min(m,3)*2592000 if discount else 0,
     discount_kopecks=discount,fee_kopecks=0,quote_version='fixture-version',operation='renewal' if path.split('/')[-2]=='b'*32 else 'purchase',
     expected_start='2026-11-19T00:00:00Z',expected_end='2027-02-17T00:00:00Z',club_reference='club_fixture'))
   elif path.endswith('/pay'):
    calls.append(r.request.post_data_json);r.fulfill(status=409,json={'error':'PROMO_RECONCILIATION_REQUIRED'})
   elif path=='/api/v1/account/club-images':r.fulfill(json={'images':[]})
   elif path.startswith('/api/'):r.fulfill(status=404,json={})
   else:
    f=ROOT/'website'/path.lstrip('/')
    if f.is_file():r.fulfill(path=str(f))
    else:r.fulfill(status=404,body='')
  page.route('**/*',route);page.goto('https://fixture.test/account.html')
  page.locator('[data-step="cabinet"]').wait_for(state='visible')
  # Existing expired subscription is a renewal, never an implicit first card.
  expired=page.locator('#subscription-'+('b'*32));expired.get_by_role('button',name='Продлить',exact=True).click()
  dialog=page.get_by_role('dialog');dialog.wait_for();assert 'Продление' in dialog.inner_text() and 'b'*32 in dialog.inner_text()
  dialog.press('Escape');assert page.get_by_role('dialog').count()==0;assert not calls;cases+=1
  # Creating a subscription follows its returned ID and focuses it.
  page.locator('.acc-plan input[type=number]').fill('1');page.locator('.acc-plan').get_by_role('button',name='Оформить',exact=True).click()
  card=page.locator('#subscription-'+('c'*32));card.get_by_text('Выбрана эта подписка',exact=True).wait_for()
  assert page.evaluate('document.activeElement.id')=='subscription-'+('c'*32);cases+=1
  card.get_by_text('У меня есть промокод',exact=True).click();field=card.get_by_label('Промокод',exact=True)
  for error in ['PROMO_REVIEW_REQUIRED','PROMO_RECONCILIATION_REQUIRED']:
   mode['error']=error;field.fill('f'*64);field.press('Enter');card.locator('[role=status]').filter(has_text='поддерж').wait_for();cases+=1
  mode['error']=None;card.get_by_label('Срок продления').select_option('3');field.fill('a'*64);field.press('Enter');card.get_by_text('Расчёт получен.',exact=False).wait_for()
  assert '627,90' in card.locator('[aria-live]').inner_text()
  card.get_by_role('button',name='Оплатить',exact=True).click();dialog=page.get_by_role('dialog');dialog.wait_for()
  text=dialog.inner_text();assert 'c'*32 in text and 'Клуб Фикстура' in text and '90 дней' in text and '627,90' in text and 'Комиссия для вас: 0' in text
  assert not calls;page.screenshot(path=str(OUT/f'confirmation-{width}.png'),full_page=True)
  # Keyboard confirmation sends exactly one frozen order, retry retains its key.
  button=dialog.get_by_role('button',name='Подтвердить и перейти к оплате');button.focus();button.press('Enter')
  dialog.locator('[data-confirm-error]').wait_for();assert len(calls)==1
  assert calls[0]['expected_amount_kopecks']==62790 and calls[0]['quote_version']=='fixture-version' and calls[0]['months']==3
  button.click();page.wait_for_function('!document.querySelector("dialog button").disabled');assert len(calls)==2 and calls[0]['idempotency_key']==calls[1]['idempotency_key'];cases+=2
  dialog.get_by_role('button',name='Вернуться к выбору').click();page.get_by_role('button',name='Показать подписку').click()
  assert page.evaluate('document.activeElement.id')=='subscription-'+('b'*32);assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth');assert not errors,errors;cases+=1
  page.close()
 browser.close()
print(json.dumps(dict(status='PASS',cases=cases,viewports=[390,1440],production_requests=0,provider='intercepted synthetic fixtures')))
