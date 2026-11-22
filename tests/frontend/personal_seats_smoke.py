"""Browser check for the seat selector before the personal payment step."""
from pathlib import Path
import mimetypes
import re
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright


SITE = Path(__file__).resolve().parents[2] / "website"
API = "/api/v1/account"
SUBSCRIPTION = "b" * 32


def test_checkout(browser):
    account = {
        "email": "personal@example.invalid", "name": "Owner", "kind": "player",
        "payments_enabled": True, "payments": [], "club_orders": [], "subscriptions": [],
        "payment_terms": [{"months": 1, "days": 30, "discount": 0}],
        "plans": [{"id": "player-month", "kind": "player", "title": "Игрок", "price_per_seat_rub": 399, "max_seats": 3}],
    }
    created = []
    errors = []

    def respond(route):
        request = route.request
        url = urlsplit(request.url)
        if url.hostname == "127.0.0.1":
            if request.method == "GET" and url.path == API:
                route.fulfill(json=account)
                return
            if request.method == "POST" and url.path == f"{API}/subscriptions":
                submitted = request.post_data_json
                created.append(submitted)
                account["subscriptions"] = [{
                    "id": SUBSCRIPTION, "plan_id": submitted["plan_id"], "kind": "player",
                    "seats": submitted["seats"], "used_seats": 0, "active": False, "devices": [],
                }]
                route.fulfill(status=201, json={"id": SUBSCRIPTION})
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
    plan = page.locator("[data-plans]")
    selector = plan.get_by_label("Сколько компьютеров")
    expect(selector.locator("option")).to_have_text(["1 ПК", "2 ПК", "3 ПК"])
    total = plan.locator("[aria-live=polite]")
    expect(total).to_contain_text("399,00")
    selector.select_option("2")
    expect(total).to_contain_text("798,00")
    selector.select_option("3")
    expect(total).to_contain_text(re.compile(r"1\s197,00"))
    assert not created
    plan.get_by_role("button", name="Оформить", exact=True).click()
    expect(page.get_by_role("heading", name="Игрок · 3 ПК")).to_be_visible()
    assert created == [{"plan_id": "player-month", "seats": 3}] and not errors, (created, errors)
    page.close()


if __name__ == "__main__":
    with sync_playwright() as playwright:
        with playwright.chromium.launch(executable_path="/usr/bin/chromium") as browser:
            test_checkout(browser)
    print("PASS personal seat selector and total")
