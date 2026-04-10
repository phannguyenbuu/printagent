"""
Debug: Simulate the exact conditions of fujifilm_scraper.py
After discover_models runs, check what happens with A2560
"""
import re, sys, time, json, urllib.parse
sys.stdout.reconfigure(encoding='utf-8')
from playwright.sync_api import sync_playwright

BASE  = "https://support-fb.fujifilm.com"
OS    = "Windows 10 64bit"
OS_ENC = urllib.parse.quote(OS)
EXE_RE = re.compile(r'https?://[^\s"\'<>]+/driver_downloads/[^\s"\'<>]+\.(?:exe|zip)', re.I)

def ts():
    return str(int(time.time() * 1000))

def get_links(page):
    try:
        return page.evaluate("""
            () => Array.from(document.querySelectorAll('a[href*="hc_drivers_download"]'))
                       .map(a => a.getAttribute('href'))
                       .filter(h => h && h.includes('xcrealpath'))
        """)
    except:
        return []

# Minimal discover_models simulation
def discover_models_sim(page):
    """Just discover MFP category like the real scraper does."""
    cat_id, cat_idx = "2", "0"
    url = f"{BASE}/processSupportCat.do?currdate_u={ts()}&cid=1&ctry_code=SG&lang_code=en&cat_id={cat_id}&cat_index={cat_idx}"
    page.goto(url, wait_until="domcontentloaded", timeout=15000)
    html = page.content()
    # Navigate to first family (Apeos)
    m = re.search(r'processSupportFamily\.do\?[^"\']*family_id=(\d+)[^"\']*family_index=(\d+)', html, re.I)
    if m:
        fid, fidx = m.group(1), m.group(2)
        murl = f"{BASE}/processSupportFamily.do?currdate_u={ts()}&cid=1&ctry_code=SG&lang_code=en&cat_id={cat_id}&cat_index={cat_idx}&family_id={fid}&family_index={fidx}"
        page.goto(murl, wait_until="domcontentloaded", timeout=15000)
    print(f"After discover sim: {page.url[:80]}")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    page = ctx.new_page()
    page.goto(BASE, wait_until="domcontentloaded")
    time.sleep(0.5)

    print("=== Simulating discover_models ===")
    discover_models_sim(page)

    print("\n=== Now testing A2560 ===")
    pid = "A2560"
    setup_url = f"{BASE}/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid={pid}"
    page.goto(setup_url, wait_until="networkidle", timeout=20000)
    
    hrefs = get_links(page)
    print(f"After goto setup: {len(hrefs)} hrefs | URL: {page.url[:80]}")
    
    if not hrefs:
        proc_url = (f"{BASE}/processDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en"
                    f"&corp_pid={pid}&rts=null&model=Apeos+2560"
                    f"&type_id=2&oslist={OS_ENC}&lang_list=en")
        page.goto(proc_url, wait_until="networkidle", timeout=15000)
        hrefs = get_links(page)
        print(f"After goto proc: {len(hrefs)} hrefs | URL: {page.url[:80]}")
    
    if not hrefs:
        # Last resort: select_option
        page.goto(setup_url, wait_until="networkidle", timeout=20000)
        try:
            page.select_option("select[name='oslist']", label=OS)
            page.wait_for_load_state("networkidle", timeout=10000)
        except Exception as e:
            print(f"select_option error: {e}")
        hrefs = get_links(page)
        print(f"After select_option: {len(hrefs)} hrefs | URL: {page.url[:80]}")
    
    if hrefs:
        print(f"\n✅ SUCCESS: {len(hrefs)} hrefs found")
        print(f"  First: {hrefs[0][:80]}")
    else:
        print("\n❌ FAILED: No hrefs found")
        # Dump some page info to debug
        content = page.content()
        idx = content.find('hc_drivers_download')
        if idx >= 0:
            print(f"  'hc_drivers_download' found at {idx}: ...{content[idx:idx+100]}...")
        else:
            print("  'hc_drivers_download' NOT in page content")
        print(f"  Page has oslist: {'oslist' in content}")
        print(f"  Page size: {len(content)}")
    
    browser.close()
