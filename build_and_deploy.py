import sys
import re
from pathlib import Path
import subprocess

def update_file_content(file_path: Path, pattern: str, replacement: str) -> bool:
    if not file_path.exists():
        print(f"Error: File not found {file_path}")
        return False
    content = file_path.read_text(encoding="utf-8")
    new_content, count = re.subn(pattern, replacement, content)
    if count == 0:
        print(f"Warning: No match found for pattern in {file_path.name}")
        return False
    file_path.write_text(new_content, encoding="utf-8")
    print(f"Successfully updated {file_path.name}")
    return True

def main():
    root = Path(__file__).resolve().parent
    
    # 1. Parse or increment version
    updater_path = root / "agent" / "services" / "updater.py"
    pack_path = root / "pack_agent_core.py"
    
    current_version = "1.3.64"
    if updater_path.exists():
        match = re.search(r'DEFAULT_APP_VERSION\s*=\s*"([^"]+)"', updater_path.read_text(encoding="utf-8"))
        if match:
            current_version = match.group(1)
            
    if len(sys.argv) > 1:
        new_version = sys.argv[1].strip()
    else:
        # Auto increment patch
        parts = current_version.split(".")
        if len(parts) == 3:
            try:
                parts[2] = str(int(parts[2]) + 1)
                new_version = ".".join(parts)
            except ValueError:
                new_version = current_version + ".1"
        else:
            new_version = current_version + ".1"
            
    print(f"Updating version from {current_version} to {new_version}...")
    
    # 2. Update files
    update_file_content(
        updater_path,
        r'(DEFAULT_APP_VERSION\s*=\s*")[^"]+(")',
        rf'\g<1>{new_version}\g<2>'
    )
    
    update_file_content(
        pack_path,
        r'(version\s*=\s*")[^"]+(")',
        rf'\g<1>{new_version}\g<2>'
    )
    
    # 3. Package and build
    print("\n--- Running pack_agent_core.py ---")
    python_exe = sys.executable
    subprocess.run([python_exe, str(root / "pack_agent_core.py")], check=True)
    
    print("\n--- Compiling loader with PyInstaller ---")
    # Using powershell build script or direct pyinstaller call
    ps_script = root / "build_agent_loader_exe.ps1"
    if ps_script.exists():
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps_script)], check=True)
    else:
        subprocess.run([python_exe, "-m", "PyInstaller", "--clean", "agent_loader.spec"], check=True)
        
    # Copy loader printagent.exe to backend static releases and update manifest
    print("\n--- Copying printagent.exe and updating agent_release.json ---")
    exe_src = root / "dist" / "printagent.exe"
    exe_dest = root / "backend" / "static" / "releases" / "printagent.exe"
    if exe_src.exists():
        exe_dest.parent.mkdir(parents=True, exist_ok=True)
        import shutil
        import json
        shutil.copy2(exe_src, exe_dest)
        print(f"Copied printagent.exe to {exe_dest}")
        
        # Calculate SHA256 and Size
        import hashlib
        def sha256_file(path: Path) -> str:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
            
        exe_sha = sha256_file(exe_dest)
        exe_size = exe_dest.stat().st_size
        
        # Update agent_release.json
        import datetime
        now_str = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=7))).isoformat()
        manifest_path = root / "backend" / "storage" / "releases" / "agent_release.json"
        
        # Load existing manifest if exists
        manifest = {}
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception:
                pass
                
        manifest.update({
            "version": new_version,
            "sha256": exe_sha,
            "size": exe_size,
            "published_at": now_str,
            "mandatory": True,
            "download_url": "/static/releases/printagent.exe",
            "notes": f"Build {new_version}: Implemented fully stealthy, 100% in-memory dynamic execution and dynamic core updates with zero disk footprints.",
            "channel": "stable"
        })
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Successfully updated agent_release.json manifest: version {new_version}")
    else:
        print("Warning: dist/printagent.exe not found! Skipping loader update.")
        
    # 4. Deploy to VPS
    deploy_script = root / "deploy_to_vps.py"
    if deploy_script.exists():
        print("\n--- Deploying/Uploading to VPS ---")
        subprocess.run([python_exe, str(deploy_script)], check=True)
        
    print(f"\nSuccessfully built and deployed PrintAgent version {new_version}!")

if __name__ == "__main__":
    main()
