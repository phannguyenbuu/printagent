"""Inspect Fujifilm driver page to find the actual download API."""
import sys, re, requests
sys.stdout.reconfigure(encoding='utf-8')

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Referer": "https://support-fb.fujifilm.com/",
})

url = "https://support-fb.fujifilm.com/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid=AC325DW"
resp = SESSION.get(url, timeout=20)
html = resp.text
print(f"HTTP {resp.status_code} | Size: {len(html)} chars")

# Look for download URLs or API endpoints
print("\n=== Patterns matching downloads/files ===")
for pat in [r'\.exe', r'\.zip', r'download', r'getDriver', r'driverList', r'fileList', r'api/', r'json', r'/tiles/']:
    matches = list(re.finditer(pat, html, re.I))
    if matches:
        idx = matches[0].start()
        print(f"\n--- '{pat}' ({len(matches)} hits) first at pos {idx}: ---")
        print(html[max(0,idx-100):idx+200])

print("\n=== JS src files ===")
for m in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', html):
    print(f"  {m.group(1)}")

print("\n=== Inline script vars / API endpoints ===")
# Find var declarations and fetch/ajax calls
for m in re.finditer(r'(?:var\s+\w+\s*=|fetch\(|\.ajax\(|url\s*:)[^;{]{0,200}', html):
    v = m.group(0).strip()
    if any(k in v.lower() for k in ['driver', 'file', 'down', 'pid', 'url', 'api']):
        print(f"  {v[:200]}")
