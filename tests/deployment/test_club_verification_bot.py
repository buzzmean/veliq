import importlib.util
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[2] / "deploy/vps/club-verification-bot.py"
SPEC = importlib.util.spec_from_file_location("club_verification_bot", SOURCE)
BOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOT)


class ClubVerificationBotTests(unittest.TestCase):
    def setUp(self):
        self.subscription = "a" * 32
        self.calls = []

    def control(self, path, body=None):
        self.calls.append(("control", path, body))
        if path == BOT.QUEUE:
            row = {"subscription_id": self.subscription, "seats": 2, "email": "private@example.test"}
            return {"requests": [row]}
        return {"verified": True}

    def telegram(self, method, body):
        self.calls.append(("telegram", method, body))
        return {"message_id": 17}

    def callback(self, operator=42, chat=-100, subscription=None):
        return {"callback_query": {
            "id": "fixture-callback",
            "data": BOT.APPROVE_PREFIX + (subscription or self.subscription),
            "from": {"id": operator},
            "message": {"chat": {"id": chat}},
        }}

    def test_acknowledges_only_confirmed_delivery(self):
        BOT.notify_clubs(self.control, self.telegram, -100)
        self.assertEqual([call[1] for call in self.calls], [BOT.QUEUE, "sendMessage", f"{BOT.QUEUE}/{self.subscription}/notified"])
        notification = self.calls[1][2]
        self.assertNotIn("private@example.test", str(notification))
        self.assertEqual(notification["reply_markup"]["inline_keyboard"][0][0]["callback_data"], BOT.APPROVE_PREFIX + self.subscription)
        self.calls.clear()
        with self.assertRaisesRegex(BOT.RequestFailure, "Telegram"):
            BOT.notify_clubs(self.control, lambda *_: {}, -100)
        self.assertEqual([call[1] for call in self.calls], [BOT.QUEUE])

    def test_scopes_callbacks_to_bound_chat_and_operator(self):
        for update in (self.callback(operator=7), self.callback(chat=-123), self.callback(subscription="../foreign")):
            BOT.handle_update(self.control, self.telegram, -100, {42}, update)
        self.assertFalse(self.calls)
        BOT.handle_update(self.control, self.telegram, -100, {42}, self.callback())
        self.assertEqual(self.calls[0], ("control", f"{BOT.QUEUE}/{self.subscription}/approve", {"operator_id": 42}))
        self.assertEqual(self.calls[1][1], "answerCallbackQuery")


if __name__ == "__main__":
    unittest.main()
