"""Check raw HTML of SP support page for JS/AJAX patterns."""
import sys, re, requests
sys.stdout.reconfigure(encoding='utf-8')
SESSION = requests.Session()
SESSION.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

url = "http://support.ricoh.com/bb/html/dr_ut_e/re2/model/spc360snw/spc360snw.htm"
resp = SESSION.get(url, timeout=20)
html = resp.text
print(f"Page size: {len(html)} chars")

# Check for exe anywhere
exe_count = html.lower().count('.exe')
print(f".exe mentions: {exe_count}")

# Check for API/AJAX endpoints
for pattern in ['api', 'ajax', 'json', 'fetch', 'xmlhttp', 'getJSON', 'dataUrl', 'driverUrl', '/pub_e/']:
    idx = html.lower().find(pattern.lower())
    if idx != -1:
        print(f"Found '{pattern}' at pos {idx}: ...{html[idx:idx+150].strip()}...")

# Show first 2000 chars
print("\n--- First 1500 chars of raw HTML ---")
print(html[:1500])
