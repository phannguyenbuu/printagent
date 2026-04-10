"""
DEBUG: Check what processDriverForm actually returns with cookies from Playwright.
"""
import re, sys, requests
sys.stdout.reconfigure(encoding='utf-8')

from playwright.sync_api import sync_playwright

BASE = "https://support-fb.fujifilm.com"
OS   = "Windows 10 64bit"
pid  = "AC325DW"
model = "Apeos C325 dw"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)  # visible for debugging
    ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    page = ctx.new_page()
    
    # Navigate
    url = f"{BASE}/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid={pid}"
    print(f"Going to: {url}")
    page.goto(url, wait_until="networkidle", timeout=20000)
    
    # Select OS
    try:
        page.select_option("select[name='oslist']", label=OS)
        page.wait_for_load_state("networkidle", timeout=10000)
        print("OS selected, page reloaded")
    except Exception as e:
        print(f"OS select failed: {e}")
    
    # Get current URL and HTML
    current_url = page.url
    print(f"Current URL: {current_url}")
    
    html = page.content()
    print(f"HTML size: {len(html)}")
    
    # Search for exe links
    exe = re.findall(r'https?://[^\s"\'<>]+\.(?:exe|zip)', html)
    print(f"Direct exe links: {exe[:10]}")
    
    # Search for hc_drivers_download
    hrefs = re.findall(r'hc_drivers_download[^\s"\'<>]+', html)
    print(f"hc_drivers_download hrefs: {len(hrefs)}")
    for h in hrefs[:5]:
        print(f"  {h}")
    
    # Get cookies
    cookies = {c['name']: c['value'] for c in ctx.cookies()}
    print(f"\nCookies: {list(cookies.keys())}")
    
    # Try requests with these cookies
    drv_url = (f"{BASE}/processDriverForm.do"
               f"?ctry_code=SG&lang_code=en&d_lang=en"
               f"&corp_pid={pid}&type_id=1"
               f"&oslist={requests.utils.quote(OS)}&lang_list=en")
    
    r = requests.get(drv_url, cookies=cookies,
                     headers={"User-Agent": "Mozilla/5.0", "Referer": current_url},
                     timeout=15, allow_redirects=True)
    print(f"\nrequests processDriverForm: HTTP {r.status_code} | Size: {len(r.text)}")
    if r.url != drv_url:
        print(f"Redirected to: {r.url}")
    
    # Check if real driver list
    hrefs2 = re.findall(r'hc_drivers_download[^\s"\'<>]+', r.text)
    print(f"hrefs in response: {len(hrefs2)}")
    
    # Check what's in the driver area  
    idx = html.find('tabitem-10')
    if idx >= 0:
        print(f"\n=== tabitem-10 area (Drivers tab) ===")
        print(html[idx:idx+1500])
    
    import time; time.sleep(3)
    browser.close()
