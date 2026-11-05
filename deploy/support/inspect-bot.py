#!/usr/bin/env python3
"""Inspect or configure the support bot. Hidden token input; no token in arguments/logs."""
import argparse
import getpass
import json
import os
import re
import sys
import urllib.request


class AdminError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class BotAPI:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def __call__(self, method, payload):
        request = urllib.request.Request('https://api.telegram.org/bot' + self.token + '/' + method,
                                         data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=15) as response:
                result = json.load(response)
        except Exception:
            raise AdminError('Telegram request failed; token and URL omitted.') from None
        if not result.get('ok'):
            raise AdminError('Telegram rejected the request; details omitted.')
        return result['result']


def inspect(api):
    me = api('getMe', {})
    print('Bot: @' + me.get('username', '') + ' (ID ' + str(me['id']) + ')')
    if api('getWebhookInfo', {}).get('url'):
        raise AdminError('Existing webhook: inspect ownership before changing anything.')
    updates = api('getUpdates', {'timeout': 0, 'limit': 100, 'allowed_updates': ['message', 'callback_query']})
    seen = set()
    for update in updates:
        message = update.get('message') or {}
        chat, user = message.get('chat') or {}, message.get('from') or {}
        if chat.get('type') not in ('group', 'supergroup') or user.get('is_bot') or message.get('sender_chat'):
            continue
        if not message.get('text', '').startswith('/start'):
            continue
        pair = (chat['id'], user['id'])
        if pair not in seen:
            seen.add(pair)
            print('Group ID:', pair[0], '| operator ID:', pair[1], '| @' + user.get('username', '(no username)'))
    if not seen:
        print('No group /start commands found. Send /start@' + me.get('username', '') + ' in the private support group.')
    return me


DESCRIPTION = 'Поддержка VELIQ. Пользователи обращаются через чат на veliqapp.ru; специалисты отвечают в закрытой группе поддержки.'
SHORT = 'Техническая поддержка VELIQ · veliqapp.ru'


def configure(api, expected_username, group_id, operators):
    """All authorization checks precede mutations. No message is sent by this function."""
    me = api('getMe', {})
    if me.get('username', '').lower() != expected_username.lstrip('@').lower():
        raise AdminError('Wrong bot: username differs from the expected support bot.')
    if not me.get('is_bot') or me.get('can_read_all_group_messages'):
        raise AdminError('Privacy Mode must be enabled in BotFather before setup.')
    if api('getWebhookInfo', {}).get('url'):
        raise AdminError('Existing webhook must be reviewed separately; it was not removed.')
    chat = api('getChat', {'chat_id': group_id})
    if group_id >= 0 or chat.get('id') != group_id or chat.get('type') not in ('group', 'supergroup') or chat.get('username'):
        raise AdminError('A verified private group is required.')
    if not operators or any(i <= 0 for i in operators):
        raise AdminError('Explicit numeric operator allowlist is required.')
    for uid in [me['id']] + sorted(set(operators)):
        member = api('getChatMember', {'chat_id': group_id, 'user_id': uid})
        if member.get('status') not in ('member', 'administrator', 'creator', 'restricted'):
            raise AdminError('Bot/operator is not a member of the support group.')
        if member.get('status') == 'restricted' and not member.get('is_member'):
            raise AdminError('Restricted user is not an active group member.')
        if uid != me['id'] and member.get('user', {}).get('is_bot'):
            raise AdminError('An operator must be a person, not another bot.')
        if uid == me['id']:
            rights = member if member.get('status') == 'restricted' else chat.get('permissions', {})
            if member.get('status') not in ('administrator', 'creator') and rights.get('can_send_messages') is False:
                raise AdminError('Bot cannot send messages to this group.')
    # Set the default locale; other clients also see the Russian support description.
    api('setMyName', {'name': 'VELIQ · Поддержка'})
    api('setMyDescription', {'description': DESCRIPTION})
    api('setMyShortDescription', {'short_description': SHORT})
    # Keep an honest, empty command menu: ticket actions are inline buttons and replies.
    # /start used during discovery does not pretend to open a separate private support channel.
    api('setMyCommands', {'commands': [], 'scope': {'type': 'default'}})
    if api('getMyName', {}).get('name') != 'VELIQ · Поддержка':
        raise AdminError('Bot name readback mismatch.')
    if api('getMyDescription', {}).get('description') != DESCRIPTION:
        raise AdminError('Description readback mismatch.')
    if api('getMyShortDescription', {}).get('short_description') != SHORT:
        raise AdminError('Short description readback mismatch.')
    if api('getMyCommands', {'scope': {'type': 'default'}}) != []:
        raise AdminError('Command menu readback mismatch.')
    return {'schema': 1, 'bot_username': me['username'], 'bot_id': me['id'], 'group_id': group_id,
            'operator_ids': sorted(set(operators)), 'profile_readback': 'PASS',
            'privacy_mode': 'ENABLED', 'webhook': 'ABSENT', 'live_ticket': 'NOT_RUN'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configure', action='store_true')
    parser.add_argument('--expected-username', default='veliqsupbot')
    parser.add_argument('--group-id', type=int)
    parser.add_argument('--operators', default='')
    parser.add_argument('--save-token', help='optional NEW root-owned Linux credential file; never stdout')
    args = parser.parse_args()
    if not sys.stdin.isatty():
        raise AdminError('Use a trusted interactive terminal; never pass a token in arguments.')
    if args.save_token and (not args.configure or os.name != 'posix' or os.geteuid() != 0):
        raise AdminError('Credential creation requires --configure and a trusted root Linux terminal.')
    token = getpass.getpass('Telegram bot token (hidden): ').strip()
    if not re.fullmatch(r'[0-9]+:[A-Za-z0-9_-]{20,}', token):
        raise AdminError('Invalid token format.')
    api = BotAPI(token)
    if args.configure:
        try:
            operators = [int(v) for v in args.operators.split(',') if v]
        except ValueError:
            raise AdminError('Invalid operator IDs.') from None
        if args.group_id is None:
            raise AdminError('Explicit group ID required.')
        result = configure(api, args.expected_username, args.group_id, operators)
        if args.save_token:
            # Refuse symlinks, existing files, and group/world-writable parent directories.
            path = os.path.abspath(args.save_token)
            parent = os.path.dirname(path)
            stat = os.stat(parent)
            if os.path.realpath(parent) != parent or stat.st_uid != 0 or stat.st_mode & 0o022:
                raise AdminError('Credential parent must be a root-owned protected directory without symlinks.')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(token + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            result['credential_created'] = True
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        inspect(api)
        print('No token saved, no messages sent, no updates acknowledged.')


if __name__ == '__main__':
    try:
        main()
    except (AdminError, OSError) as error:
        # OSError here is a local credential-file error, never an API URL.
        print(str(error) if isinstance(error, AdminError) else 'Credential file creation failed; existing files were not replaced.', file=sys.stderr)
        raise SystemExit(1)
