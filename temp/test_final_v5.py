"""Quick test of final v5 approach on AC325DW."""
import re, sys, time
sys.stdout.reconfigure(encoding='utf-8')
from playwright.sync_api import sync_playwright

BASE  = "https://support-fb.fujifilm.com"
OS    = "Windows 10 64bit"
EXE_RE = re.compile(r'https?://[^\s"\'<>]+/driver_downloads/[^\s"\'<>]+\.(?:exe|zip)', re.I)

def get_download_links(page):
    return page.evaluate("""
        () => {
            const links = document.querySelectorAll('a[href*="hc_drivers_download"]');
            return Array.from(links)
                .map(a => a.getAttribute('href'))
                .filter(h => h && h.includes('xcrealpath'));
        }
    """)

def resolve_to_exe(ctx, href):
    full = BASE + "/" + href.lstrip('/') if not href.startswith('http') else href
    captured = []
    new_pg = ctx.new_page()
    def on_resp(resp):
        url = resp.url
        if '/driver_downloads/' in url:
            m = EXE_RE.search(url)
            if m and m.group(0) not in captured: captured.append(m.group(0))
    new_pg.on("response", on_resp)
    try:
        new_pg.goto(full, wait_until="domcontentloaded", timeout=12000)
        time.sleep(0.3)
        final = new_pg.url
        if '/driver_downloads/' in final:
            m = EXE_RE.search(final)
            if m and m.group(0) not in captured: captured.append(m.group(0))
    except Exception as e:
        print(f"    resolve error: {e}")
    finally:
        new_pg.remove_listener("response", on_resp)
        new_pg.close()
    return captured[0] if captured else ""

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    page = ctx.new_page()

    url = f"{BASE}/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid=AC325DW"
    page.goto(url, wait_until="networkidle", timeout=20000)
    time.sleep(1.5)
    page.select_option("select[name='oslist']", label=OS)
    page.wait_for_load_state("networkidle", timeout=10000)
    time.sleep(1.5)
    
    hrefs = list(dict.fromkeys(get_download_links(page)))
    print(f"hrefs: {len(hrefs)}")
    for h in hrefs[:3]: print(f"  {h[:80]}")
    
    resolved = []
    for href in hrefs[:5]:
        exe = resolve_to_exe(ctx, href)
        print(f"  -> {exe or 'FAILED'}")
        if exe: resolved.append(exe)
        time.sleep(0.3)
    
    print(f"\nResolved: {len(resolved)} exe links")
    for r in resolved: print(f"  {r}")
    browser.close()
