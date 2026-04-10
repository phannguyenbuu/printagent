"""Test: wait for navigation then check links - corrected approach."""
import re, sys, time
sys.stdout.reconfigure(encoding='utf-8')
from playwright.sync_api import sync_playwright

BASE = "https://support-fb.fujifilm.com"
OS   = "Windows 10 64bit"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    page = ctx.new_page()
    
    url = f"{BASE}/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid=AC325DW"
    page.goto(url, wait_until="networkidle", timeout=20000)
    
    # Select OS and wait for navigation to complete
    with page.expect_navigation(wait_until="networkidle", timeout=15000):
        page.select_option("select[name='oslist']", label=OS)
    
    # Now page has loaded processDriverForm.do
    print(f"URL: {page.url}")
    
    # Try different wait times
    for wait_sec in [0.0, 0.5, 1.0, 2.0]:
        if wait_sec > 0:
            time.sleep(wait_sec)
        
        try:
            links = page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href*="hc_drivers_download"]'))
                           .map(a => a.getAttribute('href')).filter(h=>h&&h.includes('xcrealpath'))
            """)
            print(f"After {wait_sec:.1f}s extra sleep: {len(links)} links")
            if len(links) > 0:
                print(f"  -> {links[0][:80]}")
                break
        except Exception as e:
            print(f"After {wait_sec:.1f}s: Error - {e}")
    
    browser.close()
