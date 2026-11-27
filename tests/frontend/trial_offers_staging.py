"""Real Chromium + isolated HTTPS/PG staging; no application API response mocks.

Run only against TestStagingBrowserAcceptanceServer. OTP, flags and provider
confirmation endpoints are test-process fixtures, never production features.
"""
import argparse
from datetime import datetime, timedelta
import hashlib
import json
import uuid
from pathlib import Path
from zoneinfo import ZoneInfo

from playwright.sync_api import sync_playwright, expect


def run(origin, output):
    assert origin.startswith("https://127.0.0.1:"), "isolated loopback fixture required"
    output.mkdir(parents=True, exist_ok=True)
    repo = Path(__file__).resolve().parents[2]
    owned = ["website/account.html", "website/assets/account.js", "website/assets/offers.js", "website/assets/offers.css", "website/pricing.html", "website/download.html", "website/clubs.html"]
    results = {"origin": origin, "evidence": "REAL_BROWSER_REAL_ACCOUNT_API_ISOLATED_POSTGRESQL", "api_response_mocks": False,
               "frontend_bytes_sha256": {name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in owned},
               "tls": "Only this loopback test certificate accepted in disposable browser context; production TLS unchanged", "viewports": []}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/usr/bin/chromium", headless=True, args=["--no-sandbox"])
        for width, height in [(1440, 900), (390, 844), (360, 800)]:
            context = browser.new_context(ignore_https_errors=True, viewport={"width": width, "height": height}, timezone_id="Europe/Moscow", locale="ru-RU")
            page = context.new_page()
            errors, activation_requests, pay_requests = [], [], []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("request", lambda r: activation_requests.append(r.url) if r.method == "POST" and r.url.endswith("/trial/activate") else None)
            page.on("request", lambda r: pay_requests.append(r.url) if r.method == "POST" and r.url.endswith("/pay") else None)
            email = "offers-browser-" + uuid.uuid4().hex[:12] + "@example.test"
            context.request.post(origin + "/__fixture/config", data={"enabled": True})
            page.goto(origin + "/account")
            page.locator("[data-email-form] input").fill(email)
            page.locator("[data-email-form] button[type=submit]").click()
            page.locator("[data-code-form]").wait_for(state="visible")
            code = context.request.get(origin + "/__fixture/code", params={"email": email}).json()["code"]
            page.locator("[data-code-form] input").fill(code)
            page.locator("[data-code-form] button[type=submit]").click()
            page.locator("[data-profile-form]").wait_for(state="visible")
            page.locator("[data-profile-form] select").select_option("player")
            page.locator("[data-profile-form] input").fill("Тестовый пользователь")
            page.locator("[data-profile-continue]").click()
            page.locator("[data-trial-panel]").wait_for(state="visible")
            before = context.request.get(origin + "/__fixture/state", params={"email": email}).json()
            assert before == {"subscriptions": 0, "activated_trials": 0, "paid_subscriptions": 0}, before
            assert not activation_requests
            for selector in ["[data-trial-panel]", "[data-trial-activate]", "[data-personal-offer]"]:
                box = page.locator(selector).bounding_box()
                assert box and box["y"] >= 0 and box["y"] + box["height"] <= height, (width, selector, box)
            assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
            page.screenshot(path=str(output / f"account-eligible-{width}.png"))
            trial = context.request.get(origin + "/api/v1/account/offers").json()["trial"]
            page.reload()
            page.locator("[data-trial-activate]").wait_for(state="visible")
            assert not activation_requests, "login/view/reload activated trial"
            before_server_time = context.request.get(origin + "/api/v1/account").json()["server_time"]
            with page.expect_response(lambda r: r.request.method == "POST" and r.url.endswith("/trial/activate")) as response:
                page.locator("[data-trial-activate]").click()
            assert response.value.ok
            page.locator("[data-trial-until]").wait_for(state="visible")
            active = context.request.get(origin + "/api/v1/account/offers").json()["trial"]
            assert active["active"] and active["trial_until"]
            until = datetime.fromisoformat(active["trial_until"].replace("Z", "+00:00"))
            expected_until = until.astimezone(ZoneInfo("Europe/Moscow")).strftime("%d.%m.%Y, %H:%M")
            expect(page.locator("[data-trial-until]")).to_have_text("Доступ до " + expected_until + ". Без автопродления и списаний.")
            after_server_time = context.request.get(origin + "/api/v1/account").json()["server_time"]
            before_instant = datetime.fromisoformat(before_server_time.replace("Z", "+00:00"))
            after_instant = datetime.fromisoformat(after_server_time.replace("Z", "+00:00"))
            assert before_instant + timedelta(hours=24, seconds=-1) <= until <= after_instant + timedelta(hours=24, seconds=1)
            repeated = context.request.post(origin + "/api/v1/account/trial/activate", data={"code": trial["code"]}, headers={"Origin": origin})
            if repeated.ok:
                assert datetime.fromisoformat(repeated.json()["trial_until"].replace("Z", "+00:00")) == datetime.fromisoformat(active["trial_until"].replace("Z", "+00:00"))
            else:
                assert repeated.status == 409 and repeated.json()["error"] == "TRIAL_UNAVAILABLE", (repeated.status, repeated.json())
            assert context.request.get(origin + "/api/v1/account/offers").json()["trial"]["trial_until"] == active["trial_until"]
            assert len(activation_requests) == 1
            after = context.request.get(origin + "/__fixture/state", params={"email": email}).json()
            assert after["subscriptions"] == after["activated_trials"] == 1 and after["paid_subscriptions"] == 0
            # The real session cookie correctly has Path=/api/v1/account.
            # Forward only this synthetic account cookie to the loopback-only,
            # test-compiled fixture; never widen the production cookie path.
            fixture_session = next(cookie for cookie in context.cookies(origin + "/api/v1/account") if cookie["name"] == "veliq_session")
            seeded = context.request.post(origin + "/__fixture/seed-personal-bindings", data={"email": email, "count": 3},
                                          headers={"Cookie": fixture_session["name"] + "=" + fixture_session["value"]})
            assert seeded.ok, ("real three-binding fixture seed refused", seeded.status)
            page.reload()
            page.locator("[data-step=cabinet]").wait_for(state="visible")
            current = context.request.get(origin + "/api/v1/account").json()
            stage_sub = next(sub for sub in current["subscriptions"] if sub.get("personal_optimization_lease_stage") is True)
            assert stage_sub["used_seats"] == 3 and stage_sub["seats"] == 1 and len(stage_sub["devices"]) == 3
            card = page.locator("#subscription-" + stage_sub["id"])
            expect(card).to_contain_text("Подключено ПК: 3. Одновременная оптимизация: 1.")
            assert "3 из 1" not in card.inner_text()
            assert card.get_by_text("Сгенерировать код", exact=True).count() == 0
            assert card.get_by_text("Создать новый код", exact=True).count() == 0
            select = page.locator("[data-subs] select[aria-label='Срок продления']").first
            prices = {}
            for months, expected in [(1, 39900), (3, 83790), (6, 167580), (12, 335160)]:
                with page.expect_response(lambda r: r.request.method == "POST" and r.url.endswith("/quote")) as quote_response:
                    select.select_option(str(months))
                quote = quote_response.value.json()
                assert quote["amount_kopecks"] == expected, quote
                text = page.locator("[data-subs] p[aria-live=polite]").first
                expect(text).to_contain_text((f"{expected / 100:,.2f}".replace(",", "\u00a0").replace(".", ",")))
                if months == 1:
                    expect(page.locator("[data-subs] .acc-first-month-warning")).to_be_visible()
                    assert quote["first_month_consumes_offer"] is True
                else:
                    assert quote["promotion"] == "personal_first_purchase" and quote["discount"] == 30
                prices[months] = expected
            # Opening the review dialog does not create an order.
            select.select_option("1")
            pay = page.locator("[data-subs] button", has_text="Оплатить").first
            expect(pay).to_be_enabled()
            pay.click()
            dialog = page.locator("dialog[open]")
            expect(dialog.locator(".acc-first-month-warning")).to_be_visible()
            assert not pay_requests
            dialog.get_by_role("button", name="Вернуться к выбору").click()
            select.select_option("3")
            expect(pay).to_be_enabled()
            pay.click()
            expect(page.locator("dialog[open]")).to_contain_text("837,90")
            # Only external test-provider navigation is blocked; the order API
            # response comes from the real backend and real PostgreSQL ledger.
            page.route("https://pay.example.test/**", lambda route: route.fulfill(status=204, body=""))
            with page.expect_response(lambda r: r.request.method == "POST" and r.url.endswith("/pay")) as paid:
                page.get_by_role("button", name="Подтвердить и перейти к оплате").click()
            order = paid.value.json()
            assert paid.value.ok and order["id"] and order["redirect"].startswith("https://pay.example.test/")
            account = context.request.get(origin + "/api/v1/account").json()
            payment = next(item for item in account["payments"] if item["id"] == order["id"])
            assert payment["amount_kopecks"] == prices[3], payment
            page.goto(origin + "/account")
            page.locator("[data-step=cabinet]").wait_for(state="visible")
            expect(page.locator("[data-personal-offer]")).to_be_hidden()
            # Public offers remain adjacent to their primary CTA at each size.
            for path, selector in [("pricing", "[data-offer-public=personal]"), ("download", "[data-offer-public=trial]"), ("clubs", "[data-offer-public=club]")]:
                page.goto(origin + "/" + path)
                page.locator(selector).first.wait_for(state="visible")
                box = page.locator(selector).first.bounding_box()
                assert box["y"] + box["height"] <= height, (width, path, box)
                if path == "pricing":
                    club = page.locator("[data-pricing-early-club]").bounding_box()
                    assert club and club["y"] + club["height"] <= height, (width, "pricing-club", club)
                assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                page.screenshot(path=str(output / f"{path}-{width}.png"))
            context.request.post(origin + "/__fixture/config", data={"enabled": False})
            page.goto(origin + "/pricing")
            expect(page.locator("[data-offer-public=personal]")).to_be_hidden()
            page.goto(origin + "/download")
            expect(page.locator("[data-offer-public=trial]")).to_be_hidden()
            if width == 360:
                # Transport failure is a distinct UI negative, not an invented
                # successful backend response or a fixture price quote.
                page.route("**/api/v1/offers", lambda route: route.abort())
                page.route("**/api/v1/account/offers", lambda route: route.abort())
                context.request.post(origin + "/__fixture/config", data={"enabled": True})
                page.goto(origin + "/pricing")
                expect(page.locator("[data-offer-public=personal]")).to_be_hidden()
                for club_offer in page.locator("[data-offer-public=club]").all():
                    expect(club_offer).to_be_hidden()
                page.goto(origin + "/account")
                page.locator("[data-step=cabinet]").wait_for(state="visible")
                expect(page.locator("[data-trial-panel]")).to_be_hidden()
                expect(page.locator("[data-personal-offer]")).to_be_hidden()
                results["offers_network_failure_hides_unavailable"] = True
            assert not errors, errors
            results["viewports"].append({"width": width, "height": height, "preactivation_DB": before, "after_explicit_activation_DB": after,
                                         "repeat_did_not_extend": True, "server_trial_duration_24h": True, "endtime_exact_in_Europe_Moscow": True, "quotes_minor": prices, "order_UI_equal": True,
                                         "first_screen_no_overflow": True, "server_off_hides_offers": True, "pending_order_hides_new_offer": True,
                                         "actual_three_bound_PCs_one_optimization_copy": True, "no_legacy_raw_code_CTA_for_stage": True, "console_errors": errors})
            context.close()
        browser.close()
    (output / "RESULT.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(results, ensure_ascii=False))


def dark_layout(origin, output):
    """Theme/geometry coverage only; the light suite owns payment-flow coverage."""
    assert origin.startswith("https://127.0.0.1:")
    output.mkdir(parents=True, exist_ok=True)
    evidence = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path="/usr/bin/chromium", headless=True, args=["--no-sandbox"])
        for width, height in [(1440, 900), (390, 844)]:
            context = browser.new_context(ignore_https_errors=True, viewport={"width": width, "height": height}, color_scheme="dark", timezone_id="Europe/Moscow", locale="ru-RU")
            context.add_init_script("localStorage.setItem('veliq-theme','dark')")
            context.request.post(origin + "/__fixture/config", data={"enabled": True})
            email = "dark-browser-" + uuid.uuid4().hex[:10] + "@example.test"
            headers = {"Origin": origin}
            assert context.request.post(origin + "/api/v1/account/login/start", data={"email": email}, headers=headers).ok
            code = context.request.get(origin + "/__fixture/code", params={"email": email}).json()["code"]
            assert context.request.post(origin + "/api/v1/account/login/verify", data={"email": email, "code": code}, headers=headers).ok
            assert context.request.post(origin + "/api/v1/account/profile", data={"kind": "player", "name": "Тест тёмной темы"}, headers=headers).ok
            page = context.new_page()
            for path, selector in [("account", "[data-trial-panel]"), ("pricing", "[data-offer-public=personal]")]:
                page.goto(origin + "/" + path)
                panel = page.locator(selector)
                panel.wait_for(state="visible")
                box = panel.bounding_box()
                assert page.locator("html").get_attribute("data-theme") == "dark"
                assert box["y"] + box["height"] <= height and not page.evaluate("document.documentElement.scrollWidth > innerWidth")
                page.screenshot(path=str(output / f"{path}-dark-{width}.png"))
                evidence.append({"page": path, "theme": "dark", "width": width, "height": height, "offer_box": box, "no_horizontal_overflow": True})
            state = context.request.get(origin + "/__fixture/state", params={"email": email}).json()
            assert state["activated_trials"] == 0
            context.close()
        browser.close()
    (output / "DARK-RESULT.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"dark_real_backend_layout": evidence}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.origin.rstrip("/"), args.output)
    dark_layout(args.origin.rstrip("/"), args.output)
