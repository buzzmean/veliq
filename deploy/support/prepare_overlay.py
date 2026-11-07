"""Build an isolated overlay from the current site; does not deploy or restart."""
import argparse
import hashlib
import json
import pathlib
import re

p = argparse.ArgumentParser()
p.add_argument('--live-root', type=pathlib.Path, required=True)
p.add_argument('--assets', type=pathlib.Path, required=True)
p.add_argument('--output', type=pathlib.Path, required=True)
a = p.parse_args()
if a.output.exists():
    raise SystemExit('output must be a new directory')
site = (a.live_root/'assets/site.js').read_bytes()
marker = b'/* Shared support widget:'
if site.count(marker) != 1 or b'/* BEGIN SUPPORT AUTH HOOK */' in site:
    raise SystemExit('unknown or already patched support loader; review current baseline')
hook = (a.assets/'support-auth.js').read_bytes()
widget = (a.assets/'support-chat.js').read_bytes()
patched = site.replace(marker, b'/* BEGIN SUPPORT AUTH HOOK */\n'+hook+b'/* END SUPPORT AUTH HOOK */\n'+marker, 1)
patched, count = re.subn(rb"/assets/support-chat\.js\?v=[^'\"\s]+", b'/assets/support-chat.js?v=20261107-close-choice1', patched)
if count != 1:
    raise SystemExit('unknown widget URL; review current baseline')
patched, css_count = re.subn(rb"/assets/support-chat\.css\?v=[^'\"\s]+", b'/assets/support-chat.css?v=20261107-close-choice1', patched)
if css_count != 1:
    raise SystemExit('unknown support stylesheet URL; review current baseline')
privacy = (a.live_root/'privacy.html').read_text()
old = 'Доступ к диалогу в этом браузере определяется отдельной защищённой cookie; вход в личный кабинет для обращения не требуется.'
new = 'Без входа доступ к гостевому диалогу определяется защищённой cookie этого браузера. После входа новые обращения связаны с вашим аккаунтом и доступны только после его проверки. Гостевые обращения автоматически к аккаунту не привязываются; выход скрывает переписку на этом компьютере.'
if privacy.count(old)!=1:
    raise SystemExit('unknown privacy baseline; review before applying')
changes = {'assets/site.js': patched, 'assets/support-chat.js': widget, 'assets/support-chat.css': (a.assets/'support-chat.css').read_bytes(), 'privacy.html':privacy.replace(old,new).encode()}

manifest = []
for name, after in changes.items():
    before = (a.live_root/name).read_bytes()
    target = a.output/name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(after)
    manifest.append({'path': name, 'before_sha256': hashlib.sha256(before).hexdigest(),
                     'after_sha256': hashlib.sha256(after).hexdigest(), 'bytes':len(after)})
(a.output/'manifest.json').write_text(json.dumps({'status':'NOT_DEPLOYED','files':manifest}, indent=2)+'\n')
print('Prepared four-file overlay; validate baseline before deployment.')
