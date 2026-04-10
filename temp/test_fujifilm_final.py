"""Quick test: resolve 1 download link for AC325DW."""
import re, sys, time, json
sys.stdout.reconfigure(encoding='utf-8')
from playwright.sync_api import sync_playwright

BASE = "https://support-fb.fujifilm.com"
OS   = "Windows 10 64bit"
EXE_RE  = re.compile(r'https?://[^\s"\'<>]+/driver_downloads/[^\s"\'<>]+\.(?:exe|zip)', re.I)
DL_HREF = re.compile(r'(/tiles/common/hc_drivers_download\.jsp\?[^\s"\'<>&]+)', re.I)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    page = ctx.new_page()
    
    url = "https://support-fb.fujifilm.com/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid=AC325DW"
    page.goto(url, wait_until="networkidle", timeout=20000)
    time.sleep(0.5)
    page.select_option("select[name='oslist']", label=OS)
    page.wait_for_load_state("networkidle", timeout=10000)
    time.sleep(0.5)
    
    html = page.content()
    hrefs = list(dict.fromkeys(DL_HREF.findall(html)))
    print(f"hrefs found: {len(hrefs)}")
    for h in hrefs[:3]:
        print(f"  {h}")
    
    # Resolve first href
    if hrefs:
        href = hrefs[0]
        full = BASE + href
        print(f"\nResolving: {full}")
        
        captured = []
        new_pg = ctx.new_page()
        def on_resp(resp):
            u = resp.url
            if '/driver_downloads/' in u:
                m = EXE_RE.search(u)
                if m: captured.append(m.group(0))
        new_pg.on("response", on_resp)
        
        try:
            new_pg.goto(full, wait_until="domcontentloaded", timeout=10000, referer=url)
            print(f"Final URL: {new_pg.url}")
            content = new_pg.content()
            exes = EXE_RE.findall(content + new_pg.url)
            print(f"Exe in page: {exes}")
            print(f"Captured via response: {captured}")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            new_pg.close()

    browser.close()
