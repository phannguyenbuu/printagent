import zipfile
from pathlib import Path
import json
import hashlib

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def main():
    root = Path(__file__).resolve().parent
    agent_dir = root / "agent"
    zip_path = root / "agent_core.zip"
    
    print(f"Packaging agent folder into {zip_path}...")
    
    # We will read version from a file, or prompt / default
    # Let's see if there is an existing version we should use, e.g. "1.3.56"
    version = "1.3.80"
    
    exclude_names = {
        "address_book.py",
        "wizard.py",
        "web_scan.py"
    }
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for file_path in agent_dir.rglob('*'):
            # Skip caches, local databases/data
            if "__pycache__" in file_path.parts:
                continue
            if ".git" in file_path.parts:
                continue
            if file_path.suffix in {".pyc", ".pyo", ".db", ".log"}:
                continue
            if file_path.name in exclude_names:
                continue
                
            if file_path.is_file():
                # Store relative to root, i.e., "agent/..."
                rel_path = file_path.relative_to(root)
                zip_file.write(file_path, rel_path)
                
    sha = sha256_file(zip_path)
    size = zip_path.stat().st_size
    
    print(f"Packaged successfully! Size: {size} bytes, SHA256: {sha}")
    
    # Update local release manifest on server
    releases_dir = root / "backend" / "storage" / "releases"
    releases_dir.mkdir(parents=True, exist_ok=True)
    
    import datetime
    now_str = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=7))).isoformat()
    
    manifest_path = releases_dir / "agent_core_release.json"
    manifest = {
        "version": version,
        "download_url": "/static/releases/agent_core.zip",
        "sha256": sha,
        "size": size,
        "notes": "Auto-packaged via pack_agent_core.py",
        "published_at": now_str
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Updated backend release manifest at {manifest_path}")
    
    # Copy agent_core.zip to backend/static/releases/ for local testing
    static_releases_dir = root / "backend" / "static" / "releases"
    static_releases_dir.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy2(zip_path, static_releases_dir / "agent_core.zip")
    print(f"Copied agent_core.zip to static releases path: {static_releases_dir / 'agent_core.zip'}")
    
    scripts_to_copy = ["scan_ricoh.py", "ricoh_address_book.py", "ricoh_wizard.py", "ricoh_web_scan.py"]
    for script_name in scripts_to_copy:
        script_file = root / script_name
        if script_file.exists():
            shutil.copy2(script_file, static_releases_dir / script_name)
            print(f"Copied {script_name} to static releases path: {static_releases_dir / script_name}")

if __name__ == "__main__":
    main()

