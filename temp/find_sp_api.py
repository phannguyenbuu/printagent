"""Find the AJAX/JSON API endpoint that loads driver data for SP series."""
import sys, re, requests
sys.stdout.reconfigure(encoding='utf-8')
SESSION = requests.Session()
SESSION.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

url = "http://support.ricoh.com/bb/html/dr_ut_e/re2/model/spc360snw/spc360snw.htm"
resp = SESSION.get(url, timeout=20)
html = resp.text

# Find all JS src files and potential data endpoints
print("=== JS files loaded ===")
for m in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', html):
    print(f"  {m.group(1)}")

print("\n=== Any URLs with 'dr_ut_e' or 'pub_e' or 'driver' ===")
for m in re.finditer(r'["\']([^"\']*(?:dr_ut_e|pub_e|driver|download)[^"\']*)["\']', html, re.I):
    v = m.group(1)
    if v not in ['dr_ut_e', 'pub_e'] and len(v) > 10:
        print(f"  {v}")

print("\n=== Look for 'model' or 'productId' or 'lang' as API params ===")
for m in re.finditer(r'["\']([^"\']*(?:modelId|productId|langId|driverApi)[^"\']*)["\']', html, re.I):
    print(f"  {m.group(1)}")

# Show 3000-7000 chars (where JS setup usually is)
print("\n=== Mid-page HTML (script area) ===")
print(html[3000:6000])
