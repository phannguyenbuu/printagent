"""Quick test v6 logic on A2560 and AC325DW."""
import re, sys, time
sys.stdout.reconfigure(encoding='utf-8')
from playwright.sync_api import sync_playwright

BASE = "https://support-fb.fujifilm.com"
OS   = "Windows 10 64bit"
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

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    page = ctx.new_page()

    for pid, mname in [("A2560", "Apeos 2560"), ("AC325DW", "Apeos C325 dw")]:
        url = f"{BASE}/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid={pid}"
        page.goto(url, wait_until="networkidle", timeout=20000)

        # Check links BEFORE selecting OS
        hrefs_before = get_links(page)
        print(f"\n{mname} ({pid})")
        print(f"  Links BEFORE OS select: {len(hrefs_before)}")

        if not hrefs_before:
            # Try select
            try:
                cur = page.eval_on_selector("select[name='oslist'] option[selected]", "el => el.value")
                print(f"  Current OS: '{cur}'")
            except:
                print("  No OS dropdown found or no selected option")
                cur = ""

            if cur != OS:
                try:
                    with page.expect_navigation(wait_until="networkidle", timeout=12000):
                        page.select_option("select[name='oslist']", label=OS)
                    print("  Navigation after OS select: YES")
                except Exception as e:
                    print(f"  Navigation after OS select: NO ({e.__class__.__name__})")
                hrefs_after = get_links(page)
                print(f"  Links AFTER OS select: {len(hrefs_after)}")
                hrefs_before = hrefs_after
            else:
                print(f"  OS already '{OS}' - should have links above!")

        hrefs = hrefs_before
        print(f"  Total hrefs: {len(hrefs)}")
        
        # Resolve first 2
        for href in hrefs[:2]:
            exe = resolve(ctx, href)
            print(f"  -> {exe or 'FAILED'}")
        
        time.sleep(0.5)

    browser.close()
