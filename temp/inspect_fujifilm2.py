"""Find processDriverForm endpoint and driver list in Fujifilm page."""
import sys, re, requests
sys.stdout.reconfigure(encoding='utf-8')

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*",
})

url = "https://support-fb.fujifilm.com/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid=AC325DW"
resp = SESSION.get(url, timeout=20)
html = resp.text

# Find the processDriverForm section
idx = html.find('processDriverForm')
if idx >= 0:
    print("=== processDriverForm context ===")
    print(html[idx-200:idx+500])

# Find data-url and data-href
print("\n=== data-url / data-href attrs ===")
for m in re.finditer(r'data-(?:url|href)=["\']([^"\']+)["\']', html):
    print(f"  {m.group(0)[:200]}")

# Find any .exe links already in page
print("\n=== .exe download links in page ===")
for m in re.finditer(r'https?://[^\s"\'<>]+\.(?:exe|zip|dmg)', html, re.I):
    print(f"  {m.group(0)}")

# Look for the OS selection form hidden inputs
print("\n=== Form hidden inputs ===")
form_start = html.find('id="mainForm"')
if form_start >= 0:
    print(html[form_start:form_start+2000])
