"""Test SP C361SFNw flow to verify fixes."""
import sys, re, requests
sys.stdout.reconfigure(encoding='utf-8')

BRAND_ID    = "bf120732-ce83-453e-aaee-7dac0a646e6f"
CATEGORY_ID = "ada185a2-6c5a-4c10-ba3c-fef873d112ff"
BASE_EU     = "https://download.ricoh-europe.com"
ASSETS_URL  = f"{BASE_EU}/en-GB/product/assets"
EXE_RE = re.compile(r'href=["\']?(https?://support\.ricoh\.com/bb/pub_e/dr_ut_e/[^"\'>\s]+\.exe)', re.I)
WIN_KW = ["microsoft windows 11 (64-bit)", "microsoft windows 10 (64-bit)",
          "windows 11 (64-bit)", "windows 10 (64-bit)"]
DRIVER_DEFS = [
    ("PCL 6 Driver",                    "PCL6",     True),
    ("PCL6 Driver for Universal Print", "PCL6_Univ",False),
    ("PCL 5c Driver",                   "PCL5c",    False),
    ("Generic PCL5 Driver",             "PCL5",     False),
    ("PostScript3 Driver",              "PS3",      False),
]

SESSION = requests.Session()
SESSION.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# SP C361SFNw ProductId (from the category page)
PRODUCT_ID = "your-product-id"  # dummy, we'll test with direct URL

# Step 2: assets page
# We know the support URL from screenshot: http://support.ricoh.com/bb/html/dr_ut_e/re2/model/spc360snw/spc360snw.htm
support_url = "http://support.ricoh.com/bb/html/dr_ut_e/re2/model/spc360snw/spc360snw.htm"
print(f"Testing: {support_url}")

resp = SESSION.get(support_url, timeout=20)
print(f"HTTP {resp.status_code}")
if resp.status_code != 200:
    print("FAILED - trying https")
    support_url = support_url.replace("http://", "https://")
    resp = SESSION.get(support_url, timeout=20)
    print(f"HTTPS: HTTP {resp.status_code}")

if resp.status_code == 200:
    html = resp.text
    hl = html.lower()
    
    # Check OS selector
    os_pos = -1
    for kw in WIN_KW:
        idx = hl.find(kw)
        if idx != -1:
            os_pos = idx
            print(f"OS selector found at pos {idx}: '{kw}'")
            break
    
    if os_pos == -1:
        print("No OS selector - using full page scan")
        all_exe = list(dict.fromkeys(EXE_RE.findall(html)))
        print(f"Total .exe links: {len(all_exe)}")
        for e in all_exe[:5]:
            print(f"  {e}")
        
        # Named driver lookup
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
