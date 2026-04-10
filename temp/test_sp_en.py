"""Test: SP series loads actual driver list from the 'en' language file."""
import sys, re, requests
sys.stdout.reconfigure(encoding='utf-8')
SESSION = requests.Session()
SESSION.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
EXE_RE = re.compile(r'href=["\']?(https?://support\.ricoh\.com/bb/pub_e/dr_ut_e/[^"\'>\s]+\.exe)', re.I)

# The actual English driver data file (found in the source)
en_url = "https://support.ricoh.com/bb/html/dr_ut_e/re2/model/spc360snw/spc360snwen.htm"
print(f"Fetching: {en_url}")
resp = SESSION.get(en_url, timeout=20)
print(f"HTTP {resp.status_code} | Size: {len(resp.text)} chars")

if resp.status_code == 200:
    html = resp.text
    exe_links = list(dict.fromkeys(EXE_RE.findall(html)))
    print(f"Total .exe links: {len(exe_links)}")
    for e in exe_links:
        print(f"  {e}")

    # Named drivers
    DRIVER_DEFS = [
        ("PCL 6 Driver",                    "PCL6",     True),
        ("PCL 5c Driver",                   "PCL5c",    False),
        ("PCL6 Driver for Universal Print", "PCL6_Univ",False),
        ("PostScript3 Driver",              "PS3",      False),
    ]
    hl = html.lower()
    print()
    for label, key, excl in DRIVER_DEFS:
        pos = 0
        while True:
            idx = hl.find(label.lower(), pos)
            if idx == -1: break
            window = html[idx:idx+800]
            if excl and "universal print" in window.lower()[:200]:
                pos = idx + 1; continue
            m = EXE_RE.search(window)
            if m:
                print(f"  [{key}] {m.group(1)}")
                break
            pos = idx + 1
