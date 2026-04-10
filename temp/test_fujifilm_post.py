"""Try POST to processDriverForm.do and inspect response."""
import re, sys, time, requests
sys.stdout.reconfigure(encoding='utf-8')

BASE = "https://support-fb.fujifilm.com"
EXE_RE = re.compile(r'href=["\']?(https?://[^"\'>\s]+\.(?:exe|zip))["\']?', re.I)

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Referer": BASE + "/",
})

pid = "AC325DW"
mname = "Apeos C325 dw"

# 1. First fetch setup page to get cookies & hidden values
setup_url = f"{BASE}/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid={pid}"
r0 = SESSION.get(setup_url, timeout=20)
print(f"Setup: HTTP {r0.status_code}")

# Extract hidden form values
rts_m = re.search(r'name="rts"\s+value="([^"]*)"', r0.text)
rts = rts_m.group(1) if rts_m else "null"

# 2. POST to processDriverForm.do
SESSION.headers.update({
    "Referer": setup_url,
    "Content-Type": "application/x-www-form-urlencoded",
})
payload = {
    "ctry_code": "SG",
    "lang_code": "en",
    "d_lang": "en",
    "corp_pid": pid,
    "oslist": "Windows 10 64bit",
    "type_id": "2",
    "model": mname,
    "rts": rts,
}
r1 = SESSION.post(f"{BASE}/processDriverForm.do", data=payload, timeout=20)
print(f"POST: HTTP {r1.status_code} | Size: {len(r1.text)}")

# Extract links
exe_links = list(dict.fromkeys(EXE_RE.findall(r1.text)))
print(f".exe/.zip: {len(exe_links)}")
for e in exe_links:
    print(f"  {e}")

# Show content around download section
no_files = 'no files available' in r1.text.lower()
print(f"No-files message: {no_files}")

# Find the driver list area
for needle in ['dl_info', 'driver-list', 'driverlist', 'tabitem-10', 'content_driver']:
    idx = r1.text.find(needle)
    if idx >= 0:
        print(f"\n=== '{needle}' at {idx} ===")
        print(r1.text[idx:idx+600])
        break
