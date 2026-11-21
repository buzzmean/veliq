"""Public prices, generated policy and responsive price table, entirely local."""
import json,re,os
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[2]
policy=json.loads((ROOT/'website/assets/pricing-policy.json').read_text(encoding='utf-8'))
plans=json.loads((ROOT/'deploy/vps/plans.platega.json').read_text(encoding='utf-8'))
assert policy['prices']=={'player':399,'club':299}
for p in plans:assert p['price_per_seat_rub']==policy['prices'][p['kind']]
assert [(x['months'],x['discount']) for x in policy['club_terms']]==[(1,0),(3,0),(6,0),(12,0)]
for p in (ROOT/'website').glob('*.html'):
 text=p.read_text(encoding='utf-8')
 assert not re.search(r'(?<!\d)199\s*₽',text),p.name
 assert 'Скидки одинаковы' not in text,p.name
for name in ['design/tools/build-site.py','tools/promotion-admin.py']:
 compile((ROOT/name).read_text(encoding='utf-8'),name,'exec')
with sync_playwright() as pw:
 b=pw.chromium.launch(headless=True)
 for width in [390,1440]:
  page=b.new_page(viewport=dict(width=width,height=1000))
  def route(r):
   name=r.request.url.split('https://prices.test/',1)[-1].split('?',1)[0]
   f=ROOT/'website'/name
   if f.is_file():r.fulfill(path=str(f))
   else:r.fulfill(status=404,body='')
  page.route('**/*',route);page.goto('https://prices.test/pricing.html')
  rows=page.locator('.pricing-table tbody tr')
  for i,(personal,club) in enumerate([('399,00','299,00'),('1137,15','897,00'),('2154,60','1794,00'),('3830,40','3588,00')]):
   cells=rows.nth(i).locator('td').all_text_contents();assert personal in cells[2] and club in cells[3],cells
  assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),width
  assert 'только для личного тарифа' in page.locator('main').inner_text()
  if os.environ.get('VELIQ_UI_OUTPUT'):page.screenshot(path=str(Path(os.environ['VELIQ_UI_OUTPUT'])/f'pricing-{width}.png'),full_page=True)
  page.close()
 b.close()
print(json.dumps(dict(status='PASS',public_prices=True,viewports=[390,1440],production_requests=0)))
