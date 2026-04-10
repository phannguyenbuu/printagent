"""Quick test of Fujifilm driver flow for 3 models."""
import re, sys, time, requests
sys.stdout.reconfigure(encoding='utf-8')

BASE = "https://support-fb.fujifilm.com"
OS   = "Windows 10 64bit"
EXE_RE = re.compile(r'href=["\']?(https?://[^"\'>\s]+\.(?:exe|zip))["\']?', re.I)

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Referer": BASE + "/",
})

TESTS = [
    ("AC325DW", "Apeos C325 dw"),
    ("APPC3070", "ApeosPort-VI C3070"),
]

for pid, mname in TESTS:
    print(f"\n{'='*60}\nModel: {mname} ({pid})")
    
    # Visit setup page first (set cookies)
    setup_url = f"{BASE}/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid={pid}"
    r0 = SESSION.get(setup_url, timeout=20)
    print(f"  Setup page: HTTP {r0.status_code}")
    
    # Submit form for Win10 64bit drivers
    driver_url = (f"{BASE}/processDriverForm.do"
                  f"?ctry_code=SG&lang_code=en&d_lang=en"
                  f"&corp_pid={pid}&oslist={requests.utils.quote(OS)}"
                  f"&type_id=2&model={requests.utils.quote(mname)}")
    SESSION.headers["Referer"] = setup_url
    r1 = SESSION.get(driver_url, timeout=20)
    print(f"  Driver form: HTTP {r1.status_code} | Size: {len(r1.text)} chars")
    
    # Extract links
    exe_links = list(dict.fromkeys(EXE_RE.findall(r1.text)))
    print(f"  .exe/.zip links: {len(exe_links)}")
    for link in exe_links[:5]:
        print(f"    {link}")
    
    if 'no files available' in r1.text.lower():
        print("  -> Page says: No files available")
    elif not exe_links:
        # Show snippet
        print("  No links found. Snippet:")
        needle = 'tabitem-10'
        idx = r1.text.find(needle)
        if idx >= 0:
            print(r1.text[idx:idx+500])
    
    time.sleep(1)
