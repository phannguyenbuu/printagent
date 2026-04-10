"""
TOSHIBA Driver Scraper v2
=========================
- Source: https://business.toshiba.com/support-drivers
- API: GET /api/models → categories + model slugs  (B/W COPIER + COLOR COPIER)
- API: GET /api/drivers?id={slug} → drivers, manuals, msds JSON
- Download URL: https://business.toshiba.com/downloads/KB/{hash}/{id}/{filename}

Output: toshiba_drivers.json
Includes ALL 102 models (B/W + Color Copier).
Models with Print Drivers → download_url built from hash.
Models with no drivers   → drivers=[], product_url provided.
"""
import json
import re
import sys
import time

sys.stdout.reconfigure(encoding="utf-8")

import requests
from playwright.sync_api import sync_playwright

BASE = "https://business.toshiba.com"
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json",
    "Referer": BASE,
})

TARGET_CATEGORIES = {"B/W COPIER", "COLOR COPIER"}
PRINT_DRIVERS_SUB = "Print Drivers"

# ── Step 1: Get model list via API ──────────────────────────────────────────
def get_model_list() -> list[tuple[str, str, str]]:
    """Returns list of (category, model_slug, model_name)"""
    resp = SESSION.get(f"{BASE}/api/models", timeout=20)
    resp.raise_for_status()
    data = resp.json()
    
    categories = data["categories"]   # ["B/W COPIER", "COLOR COPIER", "FAX", "PRINTER"]
    models_by_cat = data["models"]    # list of lists
    
    result = []
    for cat, models in zip(categories, models_by_cat):
        if cat.upper() not in TARGET_CATEGORIES:
            continue
        for m in models:
            slug = m.lower()  # e.g. "e-studio1208"
            result.append((cat, slug, m))
    
    print(f"[API] Found {len(result)} models in {TARGET_CATEGORIES}")
    return result

# ── Step 2: Get drivers for a model via API ─────────────────────────────────
def get_drivers(slug: str) -> list[dict]:
    """Returns drivers list from API, filtered to Print Drivers only."""
    try:
        resp = SESSION.get(f"{BASE}/api/drivers?id={slug}", timeout=15)
        if resp.status_code != 200:
            return []
        data = resp.json()
        drivers = data.get("drivers", [])
        # Filter Print Drivers only
        return [d for d in drivers if d.get("uploadSub") == PRINT_DRIVERS_SUB]
    except Exception as e:
        print(f"  [ERR] {slug}: {e}")
        return []

# ── Step 3: Resolve download hash via Playwright (once, for first model) ────
_HASH_CACHE: str = ""

def capture_download_hash(slug: str, driver_id: str, filename: str) -> str:
    """Use Playwright to navigate to product page and intercept download URL."""
    global _HASH_CACHE
    if _HASH_CACHE:
        return _HASH_CACHE
    
    captured = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        page = ctx.new_page()
        
        def on_request(req):
            u = req.url
            if "/downloads/KB/" in u:
                m = re.search(r"/downloads/KB/([^/]+)/", u)
                if m:
                    captured.append(m.group(1))
        
        page.on("request", on_request)
        
        # Go to product page with downloads anchor
        page.goto(f"{BASE}/product/{slug}#downloads", wait_until="load", timeout=20000)
        time.sleep(2)
        
        # Try to expand Print Drivers and click download
        try:
            # Click Print Drivers accordion
            page.click("text=Print Drivers", timeout=5000)
            time.sleep(1)
            # Click first download icon
            page.eval_on_selector(
                "a[href*='/downloads/KB/']",
                "el => el.click()"
            )
            time.sleep(1)
        except Exception:
            pass
        
        # Also intercept via evaluate
        try:
            hrefs = page.eval_on_selector_all(
                "a[href*='/downloads/KB/']",
                "els => els.map(e => e.href)"
            )
            for h in hrefs:
                m = re.search(r"/downloads/KB/([^/]+)/", h)
                if m:
                    captured.append(m.group(1))
        except Exception:
            pass
        
        browser.close()
    
    if captured:
        _HASH_CACHE = captured[0]
        print(f"  [HASH] Captured download hash: {_HASH_CACHE}")
    else:
        # Fallback: use a known working hash from browser inspection
        _HASH_CACHE = "f1Ulds"
        print(f"  [HASH] Fallback hash: {_HASH_CACHE}")
    
    return _HASH_CACHE

def build_download_url(driver_id: str, filename: str, hash_key: str) -> str:
    return f"{BASE}/downloads/KB/{hash_key}/{driver_id}/{filename}"

# ── Step 4: Classify drivers ────────────────────────────────────────────────
WIN_EXTS = {".zip", ".exe", ".msi"}

def is_windows_driver(driver: dict) -> bool:
    ext = "." + driver.get("downloadExt", "").lower()
    name = (driver.get("name", "") + " " + driver.get("description", "")).lower()
    if ext not in WIN_EXTS:
        return False
    if "mac" in name:
        return False
    return True

def product_url(slug: str) -> str:
    return f"{BASE}/product/{slug}#downloads"

# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  TOSHIBA Driver Scraper")
    print("  Categories: B/W Copier + Color Copier")
    print("  Filter: Print Drivers, Windows only")
    print("=" * 60)

    # Step 1: Model list
    models = get_model_list()

    # Capture hash once (needed to build download URLs)
    hash_key = ""

    results = []
    has_drivers_count = 0
    no_driver_count = 0

    for i, (cat, slug, name) in enumerate(models, 1):
        print(f"  [{i:03d}/{len(models)}] {name} ({slug})...", end=" ", flush=True)

        all_drivers = get_drivers(slug)           # Print Drivers only (any OS)
        win_drivers  = [d for d in all_drivers if is_windows_driver(d)]

        # Capture download hash on first model that has Windows drivers
        if win_drivers and not hash_key:
            hash_key = capture_download_hash(slug, win_drivers[0]["id"], win_drivers[0]["downloadFile"])

        driver_list = []
        for d in win_drivers:
            url = build_download_url(d["id"], d["downloadFile"], hash_key) if hash_key else ""
            driver_list.append({
                "name": d.get("name", ""),
                "description": d.get("description", ""),
                "filename": d.get("downloadFile", ""),
                "version": d.get("versionName", ""),
                "date": d.get("versionDate", ""),
                "download_url": url,
                "driver_id": d.get("id", ""),
            })

        # Always append — even models with 0 drivers
        purl = product_url(slug)
        results.append({
            "category": cat,
            "model": name,
            "slug": slug,
            "product_url": purl,
            "drivers": driver_list,
            "total_windows_drivers": len(driver_list),
        })

        if driver_list:
            has_drivers_count += 1
            print(f"-> OK ({len(driver_list)} Windows drivers)")
        else:
            no_driver_count += 1
            print(f"-> No local drivers (link: {purl})")

        # Polite delay
        time.sleep(0.3)

    # Save results
    out_file = "toshiba_drivers.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    # Summary
    print("\n" + "=" * 60)
    print(f"  DONE: {len(results)} total models saved")
    print(f"  With Windows drivers: {has_drivers_count}")
    print(f"  No local drivers (link-only): {no_driver_count}")
    print(f"  Output: {out_file}")
    print(f"  Download hash: {hash_key or 'f1Ulds (fallback)'}")
    print("=" * 60)

if __name__ == "__main__":
    main()
