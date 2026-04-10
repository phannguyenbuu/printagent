"""Test v7 logic on 3 models including A2560."""
import re, sys, time, urllib.parse
sys.stdout.reconfigure(encoding='utf-8')
from playwright.sync_api import sync_playwright

BASE  = "https://support-fb.fujifilm.com"
OS    = "Windows 10 64bit"
OS_ENC = urllib.parse.quote(OS)
EXE_RE = re.compile(r'https?://[^\s"\'<>]+/driver_downloads/[^\s"\'<>]+\.(?:exe|zip)', re.I)

def get_links(page):
    try:
        return page.evaluate("""
            () => Array.from(document.querySelectorAll('a[href*="hc_drivers_download"]'))
                       .map(a => a.getAttribute('href'))
                       .filter(h => h && h.includes('xcrealpath'))
        """)
    except:
        return []

def resolve(ctx, href):
    full = BASE + "/" + href.lstrip('/') if not href.startswith('http') else href
    captured = []
    pg = ctx.new_page()
    def on_r(r):
        if '/driver_downloads/' in r.url:
            m = EXE_RE.search(r.url)
            if m: captured.append(m.group(0))
    pg.on("response", on_r)
    try:
        pg.goto(full, wait_until="domcontentloaded", timeout=8000)
        if '/driver_downloads/' in pg.url:
            m = EXE_RE.search(pg.url)
            if m: captured.append(m.group(0))
    except:
        pass
    finally:
        pg.remove_listener("response", on_r)
        pg.close()
    return captured[0] if captured else ""

TESTS = [
    ("A2560", "Apeos 2560"),
    ("A2561", "Apeos 2561"),
    ("AC325DW", "Apeos C325 dw"),
]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    page = ctx.new_page()
    page.goto(BASE, wait_until="domcontentloaded")
    time.sleep(0.5)

    for pid, mname in TESTS:
        print(f"\n{'='*50}\n{mname} ({pid})")
        
        setup_url = f"{BASE}/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid={pid}"
        page.goto(setup_url, wait_until="networkidle", timeout=20000)
        hrefs = get_links(page)
        print(f"  A) After setup goto: {len(hrefs)} hrefs")

        if not hrefs:
            proc_url = (f"{BASE}/processDriverForm.do"
                        f"?ctry_code=SG&lang_code=en&d_lang=en"
                        f"&corp_pid={pid}&rts=null"
                        f"&model={urllib.parse.quote(mname)}"
                        f"&type_id=2&oslist={OS_ENC}&lang_list=en")
            page.goto(proc_url, wait_until="networkidle", timeout=15000)
            hrefs = get_links(page)
            print(f"  B) After proc goto: {len(hrefs)} hrefs | URL: {page.url[:80]}")

        if hrefs:
            exe = resolve(ctx, hrefs[0])
            print(f"  Resolve 1st: {exe or 'FAILED'}")
            print(f"  Total hrefs: {len(hrefs)}")
        else:
            print("  NO HREFS FOUND")

    browser.close()
