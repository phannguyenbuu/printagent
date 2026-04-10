"""Quick test on 3 known models before full run."""
import sys, re, requests
sys.stdout.reconfigure(encoding='utf-8')

EXE_RE = re.compile(r'href=["\']?(https://support\.ricoh\.com/bb/pub_e/dr_ut_e/[^"\'>\s]+\.exe)', re.I)
WIN_OS_KEYWORDS = ["microsoft windows 11 (64-bit)", "microsoft windows 10 (64-bit)",
                   "windows 11 (64-bit)", "windows 10 (64-bit)"]

DRIVER_DEFS = [
    ("PCL 6 Driver",                    "PCL6",     True),
    ("PCL6 Driver for Universal Print", "PCL6_Univ",False),
    ("Generic PCL5 Driver",             "PCL5",     False),
    ("PostScript3 Driver",              "PS3",      False),
]

SESSION = requests.Session()
SESSION.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

TESTS = [
    ("IM C320F",   "https://support.ricoh.com/bb/html/dr_ut_e/re2/model/imc320f/imc320fen.htm"),
    ("IM C3510",   "https://support.ricoh.com/bb/html/dr_ut_e/re2/model/imc3510/imc3510en.htm"),
    ("MP 2554SP",  "https://support.ricoh.com/bb/html/dr_ut_e/re2/model/mp2554sp/mp2554sp.htm"),
]

for name, url in TESTS:
    print(f"\n{'='*60}\n{name} -> {url}")
    resp = SESSION.get(url, timeout=20)
    print(f"  HTTP {resp.status_code}")
    if resp.status_code != 200:
        continue
    
    html = resp.text
    lower = html.lower()
    
    os_pos = -1
    for kw in WIN_OS_KEYWORDS:
        idx = lower.find(kw)
        if idx != -1:
            os_pos = idx
            print(f"  OS section found at pos {idx}: '{kw}'")
            break
    
    if os_pos == -1:
        print("  No Win10/11 section found")
        all_exe = EXE_RE.findall(html)
        print(f"  All .exe in page: {len(all_exe)}")
        for e in all_exe[:5]:
            print(f"    {e}")
        continue
    
    # Find end of OS section
    next_pos = len(html)
    for kw in ["windows 10 (32-bit)", "windows 8", "macintosh", "linux"]:
        idx2 = lower.find(kw, os_pos + 100)
        if idx2 != -1 and idx2 < next_pos:
            next_pos = idx2
    
    work = html[os_pos:next_pos]
    print(f"  Work section: {len(work)} chars")
    
    for label, key, excl in DRIVER_DEFS:
        wl = work.lower()
        p = 0
        while True:
            idx = wl.find(label.lower(), p)
            if idx == -1: break
            window = work[idx:idx+800]
            if excl and "universal print" in window.lower()[:200]:
                p = idx + 1; continue
            m = EXE_RE.search(window)
            if m:
                print(f"  [{key}] {m.group(1)}")
                break
            p = idx + 1
    
    all_exe = list(dict.fromkeys(EXE_RE.findall(work)))
    print(f"  Total .exe in section: {len(all_exe)}")
    for e in all_exe:
        print(f"    {e}")
