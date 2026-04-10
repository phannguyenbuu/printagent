"""
Ricoh Driver Scraper v3 - Complete multi-step flow
  Step 1: Category page → list all models + ProductId
  Step 2: Assets page → find ANY support.ricoh.com link (Drivers section)
  Step 3: Support page → extract ALL .exe links for Win 10/11 64-bit
           (full page scan, no window limit, regex matching HTML structure)
  Output: CSV + Markdown report with all links per model
"""

import re
import sys
import time
import csv
import requests

sys.stdout.reconfigure(encoding='utf-8')

# ── Config ────────────────────────────────────────────────────────────────────
BRAND_ID     = "bf120732-ce83-453e-aaee-7dac0a646e6f"
CATEGORY_ID  = "ada185a2-6c5a-4c10-ba3c-fef873d112ff"
BASE_EU      = "https://download.ricoh-europe.com"
CATEGORY_URL = f"{BASE_EU}/en-GB/product/category?BrandId={BRAND_ID}&ProductCategoryId={CATEGORY_ID}"
ASSETS_URL   = f"{BASE_EU}/en-GB/product/assets"
OUTPUT_CSV   = "ricoh_drivers_v3.csv"
OUTPUT_MD    = "ricoh_drivers_v3.md"
DELAY        = 0.6
# ─────────────────────────────────────────────────────────────────────────────

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept-Language": "en-GB,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
})

# ── Step 1: Get all models from category (paginated) ─────────────────────────
def get_all_models() -> list[dict]:
    """Return [{"name": ..., "product_id": ...}, ...]"""
    models = []
    seen = set()
    page = 1
    # Pattern: href="...assets?...ProductId={uuid}">ModelName<
    pat = re.compile(
        r'href=["\'][^"\']*product/assets\?[^"\']*ProductId=([a-f0-9\-]{36})[^"\']*["\'][^>]*>\s*([^<]+?)\s*<',
        re.I
    )
    while True:
        url = CATEGORY_URL + (f"&page={page}" if page > 1 else "")
        try:
            resp = SESSION.get(url, timeout=15)
        except Exception:
            break
        if resp.status_code != 200:
            break
        found = False
        for m in pat.finditer(resp.text):
            pid = m.group(1)
            name = re.sub(r'\s+', ' ', m.group(2).strip())
            # Skip HTML entities and empty names
            if pid not in seen and name and '&' not in name and len(name) < 60:
                seen.add(pid)
                models.append({"name": name, "product_id": pid})
                found = True
        if not found:
            break
        page += 1
        time.sleep(DELAY)
    return models

# ── Step 2: Get support.ricoh.com URL from assets page ───────────────────────
def get_support_url(product_id: str) -> str:
    """Find the 'Drivers and Software' link on the assets page."""
    url = f"{ASSETS_URL}?BrandId={BRAND_ID}&ProductCategoryId={CATEGORY_ID}&ProductId={product_id}"
    try:
        resp = SESSION.get(url, timeout=15)
    except Exception:
        return ""
    if resp.status_code != 200:
        return ""
    html = resp.text

    # Accept both http:// and https:// support.ricoh.com links
    # Pattern 1: bb/html/dr_ut_e (main driver index pages)
    m = re.search(r'href=["\']?(https?://support\.ricoh\.com/bb/html/dr_ut_e[^"\'>\s]+)["\']', html, re.I)
    if m:
        return m.group(1)

    # Pattern 2: plain text links (sometimes unquoted in href)
    m = re.search(r'(https?://support\.ricoh\.com/bb/html/dr_ut_e[^\s<>"\' ]+)', html, re.I)
    if m:
        return m.group(1)

    # Pattern 3: any support.ricoh.com .htm link
    m = re.search(r'href=["\']?(https?://support\.ricoh\.com[^"\'>\s]+\.htm[^"\'>\s]*)["\']', html, re.I)
    if m:
        return m.group(1)

    return ""

# ── Step 3: Extract ALL PCL6 .exe links from support page ────────────────────
# HTML structure on support.ricoh.com:
#   <strong>PCL 6 Driver</strong>
#   ...
#   <a href="https://support.ricoh.com/bb/pub_e/...z06071L1e.exe" class="button...">Download</a>
#
# OS sections are separated by: <a href="javascript:void(0)" onclick=...>Microsoft Windows 10 (64-bit)</a>
# The page contains ALL OS content statically. We scan from Win10/Win11 section.

EXE_RE = re.compile(
    r'href=["\']?(https://support\.ricoh\.com/bb/pub_e/dr_ut_e/[^"\'>\s]+\.exe)',
    re.I
)

# Named driver types to extract (in priority order)
DRIVER_DEFS = [
    ("PCL 6 Driver",                 "PCL6",    True),   # (label, short_key, exclude_universal)
    ("PCL6 Driver for Universal Print", "PCL6_Univ", False),
    ("PCL6 V4 Driver for Universal Print", "PCL6_V4",  False),
    ("Generic PCL5 Driver",          "PCL5",    False),
    ("PostScript3 Driver",           "PS3",     False),
    ("PS Driver for Universal Print","PS3_Univ",False),
]

WIN_OS_KEYWORDS = [
    "microsoft windows 11 (64-bit)",
    "microsoft windows 10 (64-bit)",
    "windows 11 (64-bit)",
    "windows 10 (64-bit)",
]

def extract_drivers(support_url: str) -> dict:
    """
    Returns dict with keys from DRIVER_DEFS + 'raw_links', 'note', 'os_found'.
    Extracts drivers for Win 10/11 64-bit.
    """
    result = {k: "" for _, k, _ in DRIVER_DEFS}
    result["note"] = ""
    result["os_found"] = False
    result["all_exe"] = []

    if not support_url:
        result["note"] = "No support URL"
        return result

    try:
        resp = SESSION.get(support_url, timeout=20)
        if resp.status_code == 404:
            result["note"] = "404"
            return result
        if resp.status_code != 200:
            result["note"] = f"HTTP {resp.status_code}"
            return result
        html = resp.text
    except Exception as e:
        result["note"] = f"Error: {e}"
        return result

    # Detect JS shell pages: no .exe in content but has language variants listed
    # e.g. spc360snw.htm is a shell; spc360snwen.htm has actual data
    # Strategy: if no exe links found AND URL ends in slug.htm (no lang suffix),
    # try fetching the 'en' (English) variant: slugen.htm
    if '.exe' not in html.lower():
        # Try to find the 'en' lang variant from the language list in the page
        en_variant = re.search(
            r'["\'](/bb/html/dr_ut_e/[^"\']+en\.htm)["\']', html, re.I
        )
        if en_variant:
            en_url = f"https://support.ricoh.com{en_variant.group(1)}"
        else:
            # Construct manually: slug.htm -> slugen.htm
            base = support_url.rstrip('/')
            if base.endswith('.htm') and not re.search(r'[a-z]{2}\.htm$', base):
                en_url = base[:-4] + 'en.htm'
            else:
                en_url = None

        if en_url and en_url != support_url:
            try:
                resp2 = SESSION.get(en_url, timeout=20)
                if resp2.status_code == 200 and '.exe' in resp2.text.lower():
                    html = resp2.text
                    result["note_url"] = en_url  # track which URL worked
            except Exception:
                pass


    html_lower = html.lower()

    # Find the start of the Win10/11 64-bit section
    os_pos = -1
    for kw in WIN_OS_KEYWORDS:
        idx = html_lower.find(kw)
        if idx != -1:
            os_pos = idx
            break

    if os_pos == -1:
        # Old-format pages (SP series, older models) don't have OS selector.
        # They list all drivers directly — extract from full page.
        all_links = list(dict.fromkeys(EXE_RE.findall(html)))
        result["all_exe"] = all_links
        if all_links:
            # Try to identify named drivers from full page
            for label, key, excl in DRIVER_DEFS:
                label_lower = label.lower()
                hl = html.lower()
                pos = 0
                while True:
                    idx = hl.find(label_lower, pos)
                    if idx == -1:
                        break
                    window = html[idx:idx + 800]
                    if excl and "universal print" in window.lower()[:200]:
                        pos = idx + 1
                        continue
                    m2 = EXE_RE.search(window)
                    if m2:
                        result[key] = m2.group(1)
                        break
                    pos = idx + 1
            if any(result[k] for _, k, _ in DRIVER_DEFS):
                result["note"] = "OK (no OS selector, full page scan)"
            else:
                result["note"] = f"No named driver found ({len(all_links)} exe in page)"
        else:
            result["note"] = "No Win10/11 section and no .exe links found"
        return result

    result["os_found"] = True

    # Working area: from Win10 section to end OR next major section (~50k chars)
    # Find the NEXT OS section after our target to limit scope
    next_os_pos = len(html)
    for kw in ["microsoft windows 10 (32-bit)", "microsoft windows 8", "macintosh", "linux"]:
        idx = html_lower.find(kw, os_pos + 100)
        if idx != -1 and idx < next_os_pos:
            next_os_pos = idx

    work_html = html[os_pos:next_os_pos]

    # For each driver type, find its block and extract the .exe link
    for label, key, excl_universal in DRIVER_DEFS:
        label_lower = label.lower()
        work_lower = work_html.lower()
        pos = 0
        while True:
            idx = work_lower.find(label_lower, pos)
            if idx == -1:
                break
            # Window of 800 chars after label to find the href
            window = work_html[idx:idx + 800]
            # Exclusion check: skip if 'universal print' appears before the exe link
            # (for the base PCL6 Driver entry)
            if excl_universal and "universal print" in window.lower()[:200]:
                pos = idx + 1
                continue
            m = EXE_RE.search(window)
            if m:
                result[key] = m.group(1)
                break
            pos = idx + 1

    # Also collect ALL exe links in this section (deduped)
    all_links = EXE_RE.findall(work_html)
    result["all_exe"] = list(dict.fromkeys(all_links))

    if not any(result[k] for _, k, _ in DRIVER_DEFS):
        result["note"] = "No driver links found in Win10/11 section"
    else:
        result["note"] = "OK"

    return result

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("  Ricoh Driver Scraper v3 - Full flow extraction")
    print("=" * 70)

    # Step 1
    print("\n[Step 1] Fetching model list...")
    models = get_all_models()
    print(f"  Found {len(models)} models")

    rows = []

    for i, model in enumerate(models, 1):
        name = model["name"]
        pid  = model["product_id"]
        print(f"  [{i:03}/{len(models)}] {name}...", end=" ", flush=True)

        # Step 2
        sup_url = get_support_url(pid)
        time.sleep(DELAY)

        if not sup_url:
            print("-> No support page")
            rows.append({"stt": i, "model": name, "support_url": "",
                         "status": "No support page", **{k: "" for _, k, _ in DRIVER_DEFS},
                         "all_exe": "", "note": "No support page"})
            continue

        # Step 3
        drv = extract_drivers(sup_url)
        time.sleep(DELAY)

        has_driver = bool(drv.get("PCL6") or drv.get("PCL6_Univ"))
        n_total = len(drv.get("all_exe", []))

        print(f"-> {'OK' if has_driver else drv['note']} ({n_total} exe links total)")

        rows.append({
            "stt": i,
            "model": name,
            "support_url": sup_url,
            "status": "OK" if has_driver else drv["note"],
            **{k: drv.get(k, "") for _, k, _ in DRIVER_DEFS},
            "all_exe": " | ".join(drv.get("all_exe", [])),
            "note": drv["note"],
        })

    # Save CSV
    fieldnames = ["stt","model","status","PCL6","PCL6_Univ","PCL6_V4","PCL5","PS3","PS3_Univ","all_exe","support_url","note"]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Save Markdown
    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write("# Ricoh Driver Download Links\n\n")
        f.write("| STT | Model | Status | PCL6 Direct | PCL6 Universal | All Links (count) |\n")
        f.write("|---|---|---|---|---|---|\n")
        for r in rows:
            pcl6 = f"[Download]({r['PCL6']})" if r.get("PCL6") else "-"
            univ = f"[Download]({r['PCL6_Univ']})" if r.get("PCL6_Univ") else "-"
            n = len(r["all_exe"].split(" | ")) if r["all_exe"] else 0
            f.write(f"| {r['stt']} | {r['model']} | {r['status']} | {pcl6} | {univ} | {n} |\n")

    # Summary
    ok     = sum(1 for r in rows if r.get("PCL6") or r.get("PCL6_Univ"))
    no_sup = sum(1 for r in rows if r["status"] == "No support page")
    no_drv = len(rows) - ok - no_sup
    print(f"\n{'=' * 70}")
    print(f"  Done! {len(rows)} models processed")
    print(f"  OK (has PCL6):      {ok}")
    print(f"  No support page:    {no_sup}")
    print(f"  Has page, no PCL6:  {no_drv}")
    print(f"  CSV:    {OUTPUT_CSV}")
    print(f"  Report: {OUTPUT_MD}")
    print("=" * 70)

if __name__ == "__main__":
    main()
