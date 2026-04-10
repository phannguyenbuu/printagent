"""Quick check - does Apeos 2560 actually have drivers on website?"""
import re, sys, time
sys.stdout.reconfigure(encoding='utf-8')
from playwright.sync_api import sync_playwright

BASE = "https://support-fb.fujifilm.com"
OS   = "Windows 10 64bit"

def get_links(page):
    return page.evaluate("""
        () => {
            const links = document.querySelectorAll('a[href*="hc_drivers_download"]');
            return Array.from(links).map(a => a.getAttribute('href')).filter(h => h);
        }
    """)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    page = ctx.new_page()

    for pid in ["A2560", "AC325DW"]:
        url = f"{BASE}/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid={pid}"
        page.goto(url, wait_until="networkidle", timeout=20000)
        time.sleep(0.5)
        
        try:
            page.select_option("select[name='oslist']", label=OS)
            page.wait_for_load_state("networkidle", timeout=10000)
            time.sleep(0.5)
        except:
            pass
        
        links = get_links(page)
        print(f"\n{pid}: {len(links)} download links")
        for l in links[:3]:
            print(f"  {l[:80]}")
        
        # Check if page says "no files"
        content = page.content()
        if 'no files available' in content.lower():
            print("  -> Page says: No files available")
        print(f"  Current URL: {page.url}")
    
    browser.close()
