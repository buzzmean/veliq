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
    page.wait_for_function("() => [...document.querySelectorAll('#routes button')].some(b=>!b.disabled)", timeout=10000)
    button=page.locator("#routes button:enabled").first
    stopped=button.locator("xpath=ancestor::tr").locator("td").first.inner_text()
    button.click()
    page.wait_for_function("id => [...document.querySelectorAll('#routes tr')].some(row=>row.firstChild.textContent===id && row.children[5].textContent==='unhealthy' && row.querySelector('button').disabled)", arg=stopped, timeout=15000)
    # Unavailable means no observations; a stopped, measured relay is unhealthy.
    # Require failed real probes too, rather than passing on a display label alone.
    page.wait_for_function("""async id => {
        const s=await rpc('status');
        const r=s.routes.find(r=>r.id===id);
        return r && r.status==='unhealthy' && r.quality &&
            s.history.measurements.some(m=>m.route_id===id && !m.available) &&
            (s.primary||s.Primary)!==id;
    }""", arg=stopped, timeout=15000)
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
    print("Browser E2E PASS: real measurements, custom profile, stopped relay, diagnostics, settings; no JavaScript errors.")
    browser.close()
