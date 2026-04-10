"""
FUJIFILM Driver Scraper v7 - FINAL WORKING
Strategy:
  1. Discover all models (category → family → models)
  2. For each model, navigate DIRECTLY to processDriverForm.do with correct params
     instead of going through setupDriverForm + select OS
  3. Parse DOM for download links
  4. Resolve each link in new tab → actual .exe URL
"""
import re, sys, json, time, urllib.parse
sys.stdout.reconfigure(encoding='utf-8')

from playwright.sync_api import sync_playwright

BASE  = "https://support-fb.fujifilm.com"
OS    = "Windows 10 64bit"
OS_ENC = urllib.parse.quote(OS)
DELAY = 0.4

EXE_RE = re.compile(r'https?://[^\s"\'<>]+/driver_downloads/[^\s"\'<>]+\.(?:exe|zip)', re.I)


def ts():
    return str(int(time.time() * 1000))


def get_download_links_js(page) -> list:
    """Get all hc_drivers_download.jsp href values that include xcrealpath."""
    try:
        return page.evaluate("""
            () => {
                const links = document.querySelectorAll('a[href*="hc_drivers_download"]');
                return Array.from(links)
                    .map(a => a.getAttribute('href'))
                    .filter(h => h && h.includes('xcrealpath'));
            }
        """)
    except Exception:
        return []


def resolve_to_exe(ctx, href: str) -> str:
    """Open download link in a new page, intercept response redirect, return actual .exe URL."""
    full = BASE + "/" + href.lstrip('/') if not href.startswith('http') else href
    captured = []
    new_pg = ctx.new_page()

    def on_resp(resp):
        url = resp.url
        if '/driver_downloads/' in url:
            m = EXE_RE.search(url)
            if m and m.group(0) not in captured:
                captured.append(m.group(0))

    new_pg.on("response", on_resp)
    try:
        new_pg.goto(full, wait_until="domcontentloaded", timeout=8000)
        # Also check final URL
        final = new_pg.url
        if '/driver_downloads/' in final:
            m = EXE_RE.search(final)
            if m and m.group(0) not in captured:
                captured.append(m.group(0))
    except Exception:
        pass
    finally:
        new_pg.remove_listener("response", on_resp)
        try:
            new_pg.close()
        except Exception:
            pass

    return captured[0] if captured else ""


def get_model_drivers(page, ctx, pid: str, mname: str) -> list:
    """
    Navigate directly to processDriverForm.do with the proper OS and model params.
    This bypasses the OS selection step entirely.
    """
    # Strategy A: Go directly to processDriverForm.do (same URL the form posts to)
    # We need a valid rts value - use null (works in tests)
    proc_url = (f"{BASE}/processDriverForm.do"
                f"?ctry_code=SG&lang_code=en&d_lang=en"
                f"&corp_pid={pid}&rts=null"
                f"&model={urllib.parse.quote(mname)}"
                f"&type_id=2&oslist={OS_ENC}&lang_list=en")

    try:
        # First warm up with setup page to get session/cookies
        setup_url = f"{BASE}/setupDriverForm.do?ctry_code=SG&lang_code=en&d_lang=en&pid={pid}"
        page.goto(setup_url, wait_until="load", timeout=20000)

        # Check for links immediately (Win10 64bit default)
        hrefs = get_download_links_js(page)

        if not hrefs:
            # Try navigating directly with OS param in URL
            page.goto(proc_url, wait_until="load", timeout=15000)
            hrefs = get_download_links_js(page)

        if not hrefs:
            # Last resort: go back to setup page, select OS, wait
            try:
                page.goto(setup_url, wait_until="load", timeout=20000)
                page.select_option("select[name='oslist']", label=OS)
                page.wait_for_load_state("load", timeout=10000)
                hrefs = get_download_links_js(page)
            except Exception:
                pass

        direct = EXE_RE.findall(page.content())
        hrefs = list(dict.fromkeys(hrefs))

        # Resolve each href to actual exe file URL
        resolved = []
        for href in hrefs[:20]:
            exe = resolve_to_exe(ctx, href)
            if exe and exe not in resolved:
                resolved.append(exe)
            time.sleep(0.15)

        return list(dict.fromkeys(direct + resolved))

    except Exception:
        return []



def discover_models(page) -> list:
    all_models = []
    cats = [("2","0","MFP"), ("1","1","Printer"), ("8","5","Scanner")]
    for cat_id, cat_idx, cat_name in cats:
        url = (f"{BASE}/processSupportCat.do?currdate_u={ts()}"
               f"&cid=1&ctry_code=SG&lang_code=en"
               f"&cat_id={cat_id}&cat_index={cat_idx}")
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
        html = page.content()
        fams, seen = [], set()
        for m in re.finditer(
            r'processSupportFamily\.do\?[^"\']*family_id=(\d+)[^"\']*family_index=(\d+)'
            r'[^"\'">]*["\'][^>]*>([^<]+)<', html, re.I
        ):
            fid, fidx, fname = m.group(1), m.group(2), m.group(3).strip()
            if fid not in seen:
                seen.add(fid)
                fams.append((fid, fidx, fname))
        for fid, fidx, fname in fams:
            murl = (f"{BASE}/processSupportFamily.do?currdate_u={ts()}"
                    f"&cid=1&ctry_code=SG&lang_code=en"
                    f"&cat_id={cat_id}&cat_index={cat_idx}"
                    f"&family_id={fid}&family_index={fidx}")
            page.goto(murl, wait_until="domcontentloaded", timeout=15000)
            html2 = page.content()
            seen2 = set()
            for m in re.finditer(
                r'setupDriverForm\.do\?[^"\']*pid=([A-Z0-9\-_]+)'
                r'[^"\'">]*["\'][^>]*>([^<]+)<', html2, re.I
            ):
                pid_v, mname = m.group(1).strip(), m.group(2).strip()
                if pid_v not in seen2 and 1 < len(pid_v) <= 25:
                    seen2.add(pid_v)
                    all_models.append({
                        "cat": cat_name, "family": fname,
                        "pid": pid_v, "model": mname
                    })
    return all_models


def main():
    results = []
    print("=" * 65)
    print("  FUJIFILM Driver Scraper v7")
    print("=" * 65)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            locale="en-US",
        )
        page = ctx.new_page()
        page.goto(BASE, wait_until="domcontentloaded", timeout=15000)
        time.sleep(0.5)

        print("\n[Step 1] Discovering models...")
        models = discover_models(page)
        print(f"  Total: {len(models)} models\n")

        for i, mdl in enumerate(models, 1):
            pid, mname = mdl["pid"], mdl["model"]
            print(f"  [{i:03d}/{len(models)}] {mname} ({pid})...", end=" ", flush=True)

            links = get_model_drivers(page, ctx, pid, mname)
            note = "OK" if links else "No files"
            print(f"→ {note} ({len(links)} links)")

            results.append({
                "category": mdl["cat"],
                "family": mdl["family"],
                "model": mname,
                "pid": pid,
                "note": note,
                "all_links": links,
                "total_files": len(links),
            })
            time.sleep(DELAY)

        browser.close()

    with_drv = [r for r in results if r["all_links"]]
    with open("fujifilm_drivers.json", "w", encoding="utf-8") as f:
        json.dump(with_drv, f, ensure_ascii=False, indent=2)
    with open("fujifilm_all.json", "w", encoding="utf-8") as f:
        json.dump({
            "total": len(results),
            "with_drivers": len(with_drv),
            "models": results
        }, f, ensure_ascii=False, indent=2)

    print(f"\n{'=' * 65}")
    print(f"  Done! {len(results)} models | {len(with_drv)} with drivers")
    print(f"  Clean: fujifilm_drivers.json")
    print(f"  Full:  fujifilm_all.json")
    print("=" * 65)


if __name__ == "__main__":
    main()
