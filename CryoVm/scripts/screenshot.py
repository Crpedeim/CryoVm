#!/usr/bin/env python3
"""Loads a page in headless Chromium and saves a screenshot: Day 20's
done-when, run inside a browser sandbox (`sbx create -image browser`).

    python3 screenshot.py [URL] [OUT.png]

Chromium is given the egress proxy explicitly. pip and curl read
HTTPS_PROXY by themselves; Chromium doesn't reliably, and with default deny
(Day 17) a browser that ignored the proxy would simply get nowhere.

Chromium's own sandbox (namespaces, seccomp) may need kernel features gVisor
doesn't provide, and it refuses to run as root without --no-sandbox.
Playwright passes --no-sandbox unless asked otherwise. That's acceptable
here because gVisor is the boundary: the whole browser already runs inside
a user-space kernel with its own network policy.
"""
import os
import sys
import time

from playwright.sync_api import sync_playwright

url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
out = sys.argv[2] if len(sys.argv) > 2 else "/tmp/shot.png"
proxy = os.environ.get("HTTPS_PROXY")

with sync_playwright() as p:
    start = time.time()
    browser = p.chromium.launch(
        proxy={"server": proxy} if proxy else None,
        args=["--disable-dev-shm-usage"],
    )
    launched = time.time() - start
    page = browser.new_page(viewport={"width": 1280, "height": 800})
    t0 = time.time()
    resp = page.goto(url, timeout=60_000)
    page.screenshot(path=out)
    print(f"{resp.status} {page.title()!r}: launch {launched:.2f}s, load and screenshot {time.time() - t0:.2f}s -> {out}")
    browser.close()
