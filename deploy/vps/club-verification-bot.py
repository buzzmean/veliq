#!/usr/bin/env python3
"""Telegram approval worker for club subscriptions. Runs next to control-plane."""
import argparse
import json
import re
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = build_opener(ProxyHandler({}), NoRedirect())
QUEUE = "/api/v1/club-verifications"
SUBSCRIPTION = re.compile(r"[a-f0-9]{32}")
APPROVE_PREFIX = "club:approve:"


class RequestFailure(RuntimeError):
    def __init__(self, service, status=None):
        super().__init__(f"{service} request failed" + (f" ({status})" if status else ""))
        self.status = status


def request_json(service, url, payload=None, token=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    raw = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        raw = json.dumps(payload).encode("utf-8")
    try:
        with OPENER.open(Request(url, data=raw, headers=headers), timeout=22) as response:
            data = response.read(1_048_577)
        if len(data) > 1_048_576:
            raise RequestFailure(service)
        result = json.loads(data)
    except HTTPError as error:
        error.close()
        raise RequestFailure(service, error.code) from None
    except (URLError, TimeoutError, ValueError, OSError):
        raise RequestFailure(service) from None
    if not isinstance(result, dict):
        raise RequestFailure(service)
    return result


def notify_clubs(control, telegram, chat_id):
    requests = control(QUEUE).get("requests")
    if not isinstance(requests, list):
        raise RequestFailure("control-plane")
    for row in requests[:10]:
        subscription, seats = row["subscription_id"], row["seats"]
        if not SUBSCRIPTION.fullmatch(subscription) or not isinstance(seats, int) or not 1 <= seats <= 10000:
            raise RequestFailure("control-plane")
        delivered = telegram("sendMessage", {
            "chat_id": chat_id,
            "text": f"Клубный заказ оплачен. Номер {subscription}. Мест: {seats}. Подтвердите клуб после проверки заявки.",
            "reply_markup": {"inline_keyboard": [[{
                "text": "Клуб проверен",
                "callback_data": APPROVE_PREFIX + subscription,
            }]]},
        })
        if not isinstance(delivered, dict) or not isinstance(delivered.get("message_id"), int):
            raise RequestFailure("Telegram")
        try:
            control(f"{QUEUE}/{subscription}/notified", {})
        except RequestFailure as error:
            if error.status != 409:
                raise


def handle_update(control, telegram, chat_id, operators, update):
    callback = update.get("callback_query", {})
    message_chat = callback.get("message", {}).get("chat", {}).get("id")
    operator = callback.get("from", {}).get("id")
    text = callback.get("data", "")
    if message_chat != chat_id or operator not in operators or not isinstance(text, str):
        return
    if not text.startswith(APPROVE_PREFIX):
        return
    subscription = text[len(APPROVE_PREFIX):]
    callback_id = callback.get("id")
    if not SUBSCRIPTION.fullmatch(subscription) or not isinstance(callback_id, str) or len(callback_id) > 256:
        return
    try:
        result = control(f"{QUEUE}/{subscription}/approve", {"operator_id": operator})
        if result.get("verified") is not True:
            raise RequestFailure("control-plane")
        answer = "Клуб подтверждён. Код доступен в кабинете."
    except RequestFailure as error:
        if error.status not in (404, 409):
            raise
        answer = "Эта подписка уже недоступна для проверки."
    try:
        telegram("answerCallbackQuery", {"callback_query_id": callback_id, "text": answer})
    except RequestFailure as error:
        if error.status != 400:
            raise


def read_credential(path, pattern):
    with Path(path).open("rb") as source:
        value = source.read(1025).decode("ascii").strip()
    if not re.fullmatch(pattern, value):
        raise ValueError("malformed credential")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-origin", default="http://127.0.0.1:8080")
    parser.add_argument("--telegram-token-file", required=True)
    parser.add_argument("--verification-token-file", required=True)
    parser.add_argument("--chat-id", type=int, required=True)
    parser.add_argument("--operator-id", type=int, action="append", required=True)
    args = parser.parse_args()
    try:
        origin = urlsplit(args.control_origin)
        if (origin.scheme != "http" or origin.hostname != "127.0.0.1" or origin.port is None
                or origin.username or origin.path or origin.query or origin.fragment):
            raise ValueError("loopback origin required")
        if args.chat_id == 0 or min(args.operator_id) <= 0:
            raise ValueError("chat and operator IDs required")
        verification_token = read_credential(args.verification_token_file, r"[0-9A-Za-z_-]{32,128}")
        telegram_token = read_credential(args.telegram_token_file, r"[0-9]{5,20}:[0-9A-Za-z_-]{20,128}")
    except (ValueError, OSError):
        parser.exit(2, "Invalid loopback address or Telegram verification configuration.\n")

    def control(path, payload=None):
        return request_json("control-plane", args.control_origin + path, payload, verification_token)

    def telegram(method, payload):
        data = request_json("Telegram", f"https://api.telegram.org/bot{telegram_token}/{method}", payload)
        if data.get("ok") is not True or "result" not in data:
            raise RequestFailure("Telegram")
        return data["result"]

    operators = set(args.operator_id)
    offset = 0
    while True:
        try:
            notify_clubs(control, telegram, args.chat_id)
            for update in telegram("getUpdates", {"offset": offset, "allowed_updates": ["callback_query"], "timeout": 15}):
                handle_update(control, telegram, args.chat_id, operators, update)
                offset = update["update_id"] + 1
        except RequestFailure as error:
            print(str(error), file=sys.stderr, flush=True)
            time.sleep(5)
        except (KeyError, TypeError, ValueError):
            print("Unexpected approval response", file=sys.stderr, flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
