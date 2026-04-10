"""Check where the 18 hrefs are in Playwright DOM vs headless."""
import re, sys, time
sys.stdout.reconfigure(encoding='utf-8')
from playwright.sync_api import sync_playwright

BASE = "https://support-fb.fujifilm.com"
OS   = "Windows 10 64bit"
DL_HREF = re.compile(r'hc_drivers_download\.jsp\?[^\s"\'<>&]+', re.I)

# Test both headless=True and headless=False
for headless in [True, False]:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        page = ctx.new_page()
        
        url = "https://support-fb.fujifilm.com/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid=AC325DW"
        page.goto(url, wait_until="networkidle", timeout=20000)
        
        # Wait extra time
        time.sleep(2)
        
        # Select OS - try both dropdown and form submit
        try:
            page.select_option("select[name='oslist']", label=OS)
            page.wait_for_load_state("networkidle", timeout=10000)
            time.sleep(2)
        except Exception as e:
            print(f"  select_option failed: {e}")
        
        html = page.content()
        hrefs = DL_HREF.findall(html)
        
        print(f"\nheadless={headless}")
        print(f"  HTML size: {len(html)}")
        print(f"  hc_drivers_download hrefs: {len(hrefs)}")
        if hrefs:
            for h in hrefs[:3]: print(f"    {h[:100]}")
        
        # Check page title and current URL
        print(f"  Title: {page.title()}")
        print(f"  URL: {page.url}")
        
        # Check if there's an iframe
        iframes = page.frames
        print(f"  Frames: {len(iframes)}")
        for frame in iframes[1:]:
            fhtml = frame.content()
            fh = DL_HREF.findall(fhtml)
            print(f"    Frame {frame.url}: {len(fh)} hrefs")
        
        browser.close()
        if hrefs:
            break  # Found it, no need to test headless=False
