import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[2] / 'deploy/support/inspect-bot.py'
spec = importlib.util.spec_from_file_location('support_bot_admin', path)
admin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admin)


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.username = 'veliqsupbot'
        self.webhook = ''
        self.privacy_disabled = False
        self.public = False
        self.absent = False
        self.members_bot = False
        self.values = {}

    def __call__(self, method, payload):
        self.calls.append(method)
        if method == 'getMe':
            return {'id': 1, 'username': self.username, 'is_bot': True, 'can_read_all_group_messages': self.privacy_disabled}
        if method == 'getWebhookInfo':
            return {'url': self.webhook}
        if method == 'getChat':
            return {'id': -123, 'type': 'supergroup', 'username': 'public' if self.public else '', 'permissions': {'can_send_messages': True}}
        if method == 'getChatMember':
            return {'status': 'left' if self.absent else 'member', 'user': {'is_bot': self.members_bot}}
        if method.startswith('set'):
            self.values[method.replace('set', 'get', 1)] = payload
            return True
        if method == 'getMyCommands':
            return self.values[method]['commands']
        return self.values[method]


class SupportBotAdminTests(unittest.TestCase):
    def test_configures_and_reads_back(self):
        api = FakeAPI()
        result = admin.configure(api, 'veliqsupbot', -123, [22, 11, 22])
        self.assertEqual(result['operator_ids'], [11, 22])
        self.assertEqual(result['profile_readback'], 'PASS')
        self.assertNotIn('sendMessage', api.calls)
        self.assertNotIn('deleteWebhook', api.calls)

    def test_checks_before_mutations(self):
        for field, value in [('username', 'otherbot'), ('webhook', 'exists'), ('privacy_disabled', True), ('public', True), ('absent', True), ('members_bot', True)]:
            with self.subTest(field=field):
                api = FakeAPI()
                setattr(api, field, value)
                with self.assertRaises(admin.AdminError):
                    admin.configure(api, 'veliqsupbot', -123, [11])
                self.assertFalse(any(c.startswith('set') for c in api.calls))

    def test_requires_explicit_allowlist(self):
        api = FakeAPI()
        with self.assertRaises(admin.AdminError):
            admin.configure(api, 'veliqsupbot', -123, [])
        self.assertFalse(any(c.startswith('set') for c in api.calls))


if __name__ == '__main__':
    unittest.main()
