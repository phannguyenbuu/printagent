import os
import sys
from pathlib import Path

# Change CWD to the executable parent directory when frozen to prevent write errors in default CWD (like system32)
# Hide console window and redirect stdout/stderr when frozen to prevent crashes and capture logs
if getattr(sys, "frozen", False):
    if sys.platform == "win32":
        if not any(arg in sys.argv for arg in ["--debug", "test", "--console"]):
            try:
                import ctypes
                hwnd = ctypes.windll.kernel32.GetConsoleWindow()
                if hwnd:
                    ctypes.windll.user32.ShowWindow(hwnd, 0)  # 0 = SW_HIDE
            except Exception:
                pass
    try:
        exe_dir = Path(sys.executable).resolve().parent
        os.chdir(exe_dir)
    except Exception:
        pass
    try:
        log_dir = Path("storage/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        sys.stdout = open(log_dir / "loader.txt", "a", encoding="utf-8", buffering=1)
        sys.stderr = sys.stdout
    except Exception:
        class DummyWriter:
            def write(self, *args, **kwargs): pass
            def flush(self, *args, **kwargs): pass
        sys.stdout = DummyWriter()
        sys.stderr = sys.stdout

import json
import sqlite3
import hashlib
import io
import zipfile
import requests

# Force PyInstaller to bundle these standard/dependency modules used by agent core
import xml.etree.ElementTree
import ipaddress
import ftplib
import winreg
import ctypes
import threading
import time
import uuid
import csv
import platform
import re
import shutil
import traceback
import urllib.request
import urllib.parse
import struct
import select
import pyftpdlib
import pyftpdlib.authorizers
import pyftpdlib.handlers
import pyftpdlib.servers
import unicodedata

from importlib.machinery import ModuleSpec

DEFAULT_VERSION = "0.0.0"
CORE_ZIP_NAME = "agent_core.zip"

class MemoryZipImporter:
    def __init__(self, zip_bytes):
        self.zip_file = zipfile.ZipFile(io.BytesIO(zip_bytes))
        self.toc = {}
        for name in self.zip_file.namelist():
            if name.endswith('.py'):
                parts = name[:-3].split('/')
                if parts[-1] == '__init__':
                    mod_name = '.'.join(parts[:-1])
                    is_pkg = True
                else:
                    mod_name = '.'.join(parts)
                    is_pkg = False
                self.toc[mod_name] = (name, is_pkg)

    def find_spec(self, fullname, path, target=None):
        if fullname in self.toc:
            spec = ModuleSpec(fullname, self, is_package=self.toc[fullname][1])
            spec.origin = self.toc[fullname][0]
            return spec
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        filename, is_pkg = self.toc[module.__name__]
        code_bytes = self.zip_file.read(filename)
        code = compile(code_bytes, filename, 'exec')
        module.__file__ = filename
        if is_pkg:
            module.__path__ = []
        exec(code, module.__dict__)

def get_config():
    config = {
        "url": "https://agentapi.quanlymay.com",
        "lead": "default",
        "token": "change-me"
    }
    
    db_path = Path("storage/data/agent_config.db")
    if db_path.exists():
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE IF NOT EXISTS app_settings (key VARCHAR(128) PRIMARY KEY, value TEXT NOT NULL)")
            rows = cursor.execute("SELECT key, value FROM app_settings").fetchall()
            conn.close()
            for key, val in rows:
                if key == "polling.url":
                    config["url"] = val.strip()
                elif key == "polling.lead":
                    config["lead"] = val.strip()
                elif key == "polling.token":
                    config["token"] = val.strip()
        except Exception:
            pass
            
    if os.getenv("POLLING_URL"):
        config["url"] = os.getenv("POLLING_URL").strip()
    if os.getenv("POLLING_LEAD"):
        config["lead"] = os.getenv("POLLING_LEAD").strip()
    if os.getenv("POLLING_TOKEN"):
        config["token"] = os.getenv("POLLING_TOKEN").strip()
        
    return config

def safe_input(prompt=""):
    try:
        if sys.stdin and sys.stdin.isatty():
            input(prompt)
        else:
            time.sleep(5)
    except Exception:
        pass

def _get_core_zip_path() -> Path:
    temp_dir = os.environ.get("TEMP")
    if temp_dir:
        folder = Path(temp_dir) / "GoPrinxAgent"
    else:
        import tempfile
        folder = Path(tempfile.gettempdir()) / "GoPrinxAgent"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        return folder / "agent_core.zip"
    except Exception:
        return Path("agent_core.zip")

def main():
    Path("storage/data").mkdir(parents=True, exist_ok=True)
    
    config = get_config()
    base_url = config["url"].rstrip("/")



    # Ensure dynamic scripts directory exists
    temp_dir = os.environ.get("TEMP")
    if temp_dir:
        scripts_dir = Path(temp_dir) / "GoPrinxAgent" / "scripts"
    else:
        import tempfile
        scripts_dir = Path(tempfile.gettempdir()) / "GoPrinxAgent" / "scripts"
    try:
        scripts_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    # Download scripts
    scripts_to_download = ["scan_ricoh.py", "ricoh_address_book.py", "ricoh_wizard.py", "ricoh_web_scan.py"]
    for script_name in scripts_to_download:
        script_url = f"{base_url}/static/releases/{script_name}"
        print(f"Downloading dynamic script: {script_name} from {script_url}...")
        try:
            resp = requests.get(script_url, headers={"X-Lead-Token": config["token"]}, timeout=15)
            if resp.status_code == 200:
                (scripts_dir / script_name).write_bytes(resp.content)
                print(f"Successfully downloaded {script_name}")
            else:
                print(f"Failed to download {script_name}: Status {resp.status_code}")
        except Exception as exc:
            print(f"Error downloading {script_name}: {exc}")

    # 1. Try to load bundled agent_core.zip
    import sys
    if getattr(sys, "frozen", False):
        base_path = Path(getattr(sys, "_MEIPASS", os.getcwd()))
    else:
        base_path = Path(__file__).resolve().parent

    local_zip_path = base_path / "agent_core.zip"
    zip_bytes = None

    if local_zip_path.exists():
        print(f"Loading bundled agent core from {local_zip_path}...")
        try:
            zip_bytes = local_zip_path.read_bytes()
        except Exception as read_err:
            print(f"Failed to read bundled agent core: {read_err}")

    if not zip_bytes:
        print("Error: Could not find or read bundled agent_core.zip. Cannot start agent.")
        safe_input("Press Enter to exit...")
        sys.exit(1)
        
    print("Loading agent core in-memory...")
    try:
        importer = MemoryZipImporter(zip_bytes)
        sys.meta_path.insert(0, importer)
        
        os.environ["AGENT_RUNNING_LOADER"] = "true"
        
        import agent.main
        sys.exit(agent.main.main())
    except Exception as run_exc:
        print(f"Fatal error running agent core: {run_exc}")
        traceback.print_exc()
        safe_input("Press Enter to exit...")
        sys.exit(1)

if __name__ == "__main__":
    main()
