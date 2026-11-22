"""Browser regression for the club verification and activation actions."""
from pathlib import Path
import mimetypes
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright


SITE = Path(__file__).resolve().parents[2] / "website"
API = "/api/v1/account"
SUBSCRIPTION = "a" * 32


def test_cabinet(browser):
    account = {
        "email": "club@example.invalid", "name": "Test Club", "kind": "club",
        "payments_enabled": True, "payments": [], "club_orders": [],
        "payment_terms": [{"months": 1, "days": 30, "discount": 0}],
        "plans": [{"id": "club", "kind": "club", "title": "Клуб", "price_per_seat_rub": 299}],
        "subscriptions": [{
            "id": SUBSCRIPTION, "plan_id": "club", "kind": "club", "seats": 2,
            "used_seats": 0, "active": True, "can_connect": False,
            "paid_until": "2031-11-21T12:00:00Z", "devices": [], "club_verification": "pending",
        }],
    }
    issued = []
    errors = []

    def respond(route):
        request = route.request
        url = urlsplit(request.url)
        if url.hostname == "127.0.0.1":
            if request.method == "GET" and url.path == API:
                route.fulfill(json=account)
                return
            if request.method == "POST" and url.path == f"{API}/subscriptions/{SUBSCRIPTION}/code":
                issued.append(account["subscriptions"][0]["club_verification"])
                route.fulfill(json={"code": "fixture-activation-code"})
                return
            if request.method == "GET":
                content = (SITE / url.path.lstrip("/")).resolve()
                if content.is_relative_to(SITE) and content.is_file():
                    route.fulfill(body=content.read_bytes(), content_type=mimetypes.guess_type(content.name)[0] or "application/octet-stream")
                    return
        route.fulfill(status=404, body="")

    page = browser.new_page(viewport={"width": 390, "height": 900})
    page.route("**/*", respond)
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto("http://127.0.0.1:17328/account.html")
    expect(page.get_by_text("Оплата подтверждена. Клубная подписка ожидает проверки.")).to_be_visible()
    button = page.get_by_role("button", name="Получить код активации", exact=True)
    expect(button).to_have_count(0)
    assert not issued
    account["subscriptions"][0].update(club_verification="verified", can_connect=True)
    page.reload()
    expect(button).to_be_visible()
    assert not issued
    button.click()
    expect(page.get_by_text("Код для 2 ПК: fixture-activation-code")).to_be_visible()
    assert issued == ["verified"] and not errors, (issued, errors)
    page.close()


if __name__ == "__main__":
    with sync_playwright() as playwright:
        with playwright.chromium.launch(executable_path="/usr/bin/chromium") as browser:
            test_cabinet(browser)
    print("PASS club verification cabinet")
