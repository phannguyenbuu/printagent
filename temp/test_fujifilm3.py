"""
Fujifilm driver scraper - correct API flow:
  processDriverForm.do?...&type_id=1&oslist=Windows+10+64bit&lang_list=en
  -> HTML contains hc_drivers_download.jsp?xcrealpath=... links
  -> Follow 302 redirect to get actual .exe URL at /driver_downloads/...
"""
import re, sys, time, json, requests
sys.stdout.reconfigure(encoding='utf-8')

BASE  = "https://support-fb.fujifilm.com"
OS    = "Windows 10 64bit"
DELAY = 0.8

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": BASE + "/",
})

XCREALPATH_RE = re.compile(r'hc_drivers_download\.jsp\?xcrealpath=([^\s"\'&<>]+)', re.I)
EXE_RE        = re.compile(r'(https?://[^\s"\'<>]+\.(?:exe|zip|dmg))', re.I)

def ts():
    return str(int(time.time() * 1000))

def fetch(url, method='get', **kw):
    for i in range(3):
        try:
            fn = getattr(SESSION, method)
            r = fn(url, timeout=20, allow_redirects=True, **kw)
            return r
        except Exception:
            time.sleep(2)
    return None

def resolve_xcrealpath(xcrealpath: str) -> str:
    """Follow the hc_drivers_download.jsp redirect to get the actual file URL."""
    url = f"{BASE}/tiles/common/hc_drivers_download.jsp?xcrealpath={xcrealpath}"
    r = fetch(url)
    if r and r.url != url:
        # redirected to actual file
        if any(r.url.endswith(e) for e in ['.exe', '.zip', '.dmg']):
            return r.url
    if r:
        # Look for .exe link in response
        m = EXE_RE.search(r.url + r.text)
        if m:
            return m.group(1)
    return ""

def get_driver_page_links(pid: str, model: str, type_id: int = 1) -> list:
    """GET processDriverForm.do and extract all download xcrealpath values."""
    setup_url = f"{BASE}/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid={pid}"
    SESSION.headers["Referer"] = BASE + "/"
    
    # Visit setup page for cookies
    r0 = fetch(setup_url)
    if not r0:
        return []
    
    SESSION.headers["Referer"] = setup_url
    
    # Fetch driver list
    url = (f"{BASE}/processDriverForm.do"
           f"?ctry_code=SG&lang_code=en&d_lang=en"
           f"&corp_pid={pid}&type_id={type_id}"
           f"&oslist={requests.utils.quote(OS)}&lang_list=en"
           f"&model={requests.utils.quote(model)}")
    
    r = fetch(url)
    if not r:
        return []
    
    # Find all xcrealpath values
    paths = list(dict.fromkeys(XCREALPATH_RE.findall(r.text)))
    
    # Also check for direct .exe links
    direct = list(dict.fromkeys(EXE_RE.findall(r.text)))
    
    return paths, direct, r.text, r.status_code

# ── Test with AC325DW ────────────────────────────────────────────────────────
pid   = "AC325DW"
model = "Apeos C325 dw"
print(f"Testing: {model} ({pid})")

paths, direct, html, status = get_driver_page_links(pid, model, type_id=1)
print(f"HTTP Status: {status}")
print(f"xcrealpath found: {len(paths)}")
print(f"Direct .exe found: {len(direct)}")

if paths:
    print("\nResolving xcrealpath links -> actual file URLs:")
    for p in paths[:5]:
        url = resolve_xcrealpath(p)
        print(f"  xcrealpath: {p[:50]}...")
        print(f"  -> {url}")
        time.sleep(0.5)
elif direct:
    for d in direct:
        print(f"  Direct: {d}")
else:
    # Debug: show snippet of HTML
    print("\nNo links found. Status:", status)
    # look for 'files available' phrase
    for phrase in ['no files', 'files available', 'driver', 'download', 'exe']:
        idx = html.lower().find(phrase)
        if idx >= 0:
            print(f"  Found '{phrase}' at {idx}: ...{html[idx:idx+200]}...")
            break
    print("\nFirst 1000 chars of response:")
    print(html[:1000])
