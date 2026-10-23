# The browse tool's helper (Day 21), run inside the sandbox: loads a page in
# headless Chromium through the egress proxy and prints one line of JSON:
# status, final URL, title, the page's visible text, and where a screenshot
# went (if asked). Errors are JSON too, so the server can explain them.
import json
import os
import sys

url, out = sys.argv[1], sys.argv[2]
shot = sys.argv[3] if len(sys.argv) > 3 else ""


def finish(result):
    # The server reads the result from this file, never from stdout: every
    # path out of this script must write it.
    with open(out, "w") as f:
        json.dump(result, f)
    sys.exit(0)


try:
    from playwright.sync_api import sync_playwright
except ImportError:
    finish({"error": "no-browser"})
result = {}
try:
    with sync_playwright() as p:
        proxy = os.environ.get("HTTPS_PROXY")
        browser = p.chromium.launch(proxy={"server": proxy} if proxy else None, args=["--disable-dev-shm-usage"])
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        resp = page.goto(url, wait_until="domcontentloaded", timeout=45_000)
        try:
            page.wait_for_load_state("networkidle", timeout=5_000)
        except Exception:
            pass  # a page that never goes quiet still has text worth reading
        result = {
            "status": resp.status if resp else 0,
            "url": page.url,
            "title": page.title(),
            "text": page.inner_text("body"),
        }
        if shot:
            page.screenshot(path=shot)
            result["screenshot"] = shot
        browser.close()
except Exception as e:
    result = {"error": str(e).splitlines()[0] if str(e) else type(e).__name__}
finish(result)
