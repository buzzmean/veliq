#!/usr/bin/env python3
"""Read bot/group/operator IDs using hidden input. Does not save the token or acknowledge updates."""
import getpass
import json
import re
import sys
import urllib.error
import urllib.request

if not sys.stdin.isatty():
    raise SystemExit('Run in an interactive trusted terminal; do not pass the token in arguments.')
token = getpass.getpass('Telegram bot token (hidden): ').strip()
if not re.fullmatch(r'[0-9]+:[A-Za-z0-9_-]{20,}', token):
    raise SystemExit('Invalid token format.')

def call(method, payload):
    data = json.dumps(payload).encode()
    request = urllib.request.Request('https://api.telegram.org/bot' + token + '/' + method,
                                     data=data, headers={'Content-Type': 'application/json'})
    # Disable redirects so the token path cannot be sent to another destination.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as response:
            result = json.load(response)
    except Exception:
        raise SystemExit('Telegram request failed; token and URL omitted.') from None
    if not result.get('ok'):
        raise SystemExit('Telegram rejected the request; details omitted.')
    return result['result']

me = call('getMe', {})
print('Bot: @' + me.get('username', '') + ' (ID ' + str(me['id']) + ')')
webhook = call('getWebhookInfo', {})
if webhook.get('url'):
    raise SystemExit('An existing webhook is configured. Inspect its ownership before changing anything.')
updates = call('getUpdates', {'timeout': 0, 'limit': 100, 'allowed_updates': ['message', 'callback_query']})
seen = set()
for update in updates:
    message = update.get('message') or {}
    chat = message.get('chat') or {}
    user = message.get('from') or {}
    if chat.get('type') not in ('group', 'supergroup') or user.get('is_bot') or message.get('sender_chat'):
        continue
    if not message.get('text', '').startswith('/start'):
        continue
    pair = (chat['id'], user['id'])
    if pair in seen:
        continue
    seen.add(pair)
    print('Group ID:', pair[0], '| operator ID:', pair[1], '| @' + user.get('username', '(no username)'))
if not seen:
    print('No group /start commands found. Send /start@' + me.get('username', '') + ' in the private support group and inspect again.')
print('Verify each ID with the owner. No token saved, no messages sent, no updates acknowledged.')
