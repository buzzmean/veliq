"""Run against an existing portable demo with Playwright + Chromium installed."""
import os
from playwright.sync_api import sync_playwright

url = os.environ.get("NEEXITLAG_DEMO_URL", "http://127.0.0.1:8099")
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH", "/usr/bin/chromium"), headless=True, args=["--no-sandbox"])
    page = browser.new_page(viewport={"width": 1280, "height": 900})
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(url)
    page.wait_for_function("() => document.getElementById('connected').textContent.includes('Connected')", timeout=15000)
    page.wait_for_function("() => document.querySelectorAll('#routes tr').length===4", timeout=20000)
    page.get_by_role("button", name="Applications", exact=True).click()
    page.get_by_role("button", name="Add application", exact=True).click()
    page.locator("#appName").fill("Browser smoke game")
    page.locator("#exePath").fill(r"C:\Games\Smoke.exe")
    page.locator("#confirmAdd").click()
    page.get_by_role("cell", name="Browser smoke game", exact=True).wait_for(timeout=10000)
    page.get_by_role("button", name="Routes", exact=True).click()
    # Stop the selected relay only after real measurements and received traffic.
    selected = page.wait_for_function("""() => {
        const id = snapshot?.primary;
        return id && id !== 'DIRECT' && snapshot.rx_bytes > 0 &&
            snapshot.routes.some(r => r.id === id && r.status === 'healthy') && id;
    }""", timeout=25000)
    stopped = selected.json_value()
    row = page.locator("#routes tr").filter(has=page.get_by_role("cell", name=stopped, exact=True))
    row.get_by_role("button", name="Stop relay", exact=True).click()
    # A measured failure is unhealthy; unavailable means no observations yet.
    page.wait_for_function("""id => [...document.querySelectorAll('#routes tr')].some(row =>
        row.cells[0].textContent === id && row.cells[5].textContent === 'unhealthy')
    """, arg=stopped, timeout=15000)
    page.wait_for_function("id => snapshot.primary && snapshot.primary !== id", arg=stopped, timeout=15000)
    rx_after_switch = page.evaluate("snapshot.rx_bytes")
    page.wait_for_function("rx => snapshot.rx_bytes > rx", arg=rx_after_switch, timeout=10000)
    page.get_by_role("button", name="Statistics", exact=True).click()
    page.wait_for_function("() => document.querySelectorAll('#measureHistory tr').length > 0", timeout=10000)
    assert page.locator("#measureHistory tr").first.locator("td").count() == 5
    page.get_by_role("button", name="Diagnostics", exact=True).click()
    page.get_by_role("button", name="Run diagnostics", exact=True).click()
    page.wait_for_function("() => document.querySelectorAll('#checks .card').length >= 4", timeout=10000)
    page.get_by_role("button", name="Settings", exact=True).click()
    page.locator("#fallback").select_option("DIRECT")
    page.get_by_role("button", name="Save preferences", exact=True).click()
    page.get_by_role("button", name="Home", exact=True).click()
    page.screenshot(path="work/demo-browser.png", full_page=True)
    if errors:
        raise AssertionError(errors)
    print("Browser E2E PASS: real measurements, custom profile, unhealthy relay, route switch and continued RX, diagnostics, settings; no JavaScript errors.")
    browser.close()
