"""Get exact href values for download links via Playwright evaluate."""
import re, sys, time
sys.stdout.reconfigure(encoding='utf-8')
from playwright.sync_api import sync_playwright

BASE = "https://support-fb.fujifilm.com"
OS   = "Windows 10 64bit"
EXE_RE = re.compile(r'https?://[^\s"\'<>]+/driver_downloads/[^\s"\'<>]+\.(?:exe|zip)', re.I)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    page = ctx.new_page()

    url = "https://support-fb.fujifilm.com/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid=AC325DW"
    page.goto(url, wait_until="networkidle", timeout=20000)
    time.sleep(2)
    page.select_option("select[name='oslist']", label=OS)
    page.wait_for_load_state("networkidle", timeout=10000)
    time.sleep(2)
    
    # Get ALL href attributes of download links using JS
    hrefs = page.evaluate("""
        () => {
            const links = document.querySelectorAll('a[href*="hc_drivers_download"]');
            return Array.from(links).map(a => ({
                href: a.getAttribute('href'),
                text: a.textContent.trim().substring(0, 50)
            }));
        }
    """)
    print(f"Download links found: {len(hrefs)}")
    for h in hrefs[:8]:
        print(f"  [{h['text']}] -> {h['href'][:100]}")
    
    # Resolve first link
    if hrefs:
        first_href = hrefs[0]['href']
        full_url = BASE + first_href if first_href.startswith('/') else first_href
        print(f"\nResolving: {full_url}")
        
        captured = []
        def on_resp(resp):
            u = resp.url
            if '/driver_downloads/' in u:
                m = EXE_RE.search(u)
                if m and m.group(0) not in captured: captured.append(m.group(0))
        
        new_pg = ctx.new_page()
        new_pg.on("response", on_resp)
        try:
            new_pg.goto(full_url, wait_until="domcontentloaded", timeout=12000,
                        referer="https://support-fb.fujifilm.com/processDriverForm.do")
            time.sleep(1)
            print(f"Final URL: {new_pg.url}")
            print(f"Captured: {captured}")
            
            # Also check content for exe
            content_exe = EXE_RE.findall(new_pg.content() + new_pg.url)
            print(f"EXE in content: {content_exe[:3]}")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            new_pg.close()
    
    browser.close()
