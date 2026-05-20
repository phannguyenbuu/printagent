import os
import sys
import json
import sqlite3
import hashlib
import io
import zipfile
from pathlib import Path
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

from importlib.machinery import ModuleSpec

# Redirect stdout/stderr when frozen to prevent windowless crashes and capture logs
if getattr(sys, "frozen", False):
    log_dir = Path("storage/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    sys.stdout = open(log_dir / "loader.txt", "w", encoding="utf-8", buffering=1)
    sys.stderr = sys.stdout

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
    download_url = f"{base_url}/static/releases/agent_core.zip"
    headers = {
        "Accept": "application/zip",
        "X-Lead-Token": config["token"]
    }
    
    zip_bytes = None
    print(f"Downloading agent core in-memory from {download_url}...")
    try:
        response = requests.get(download_url, headers=headers, timeout=20)
        response.raise_for_status()
        zip_bytes = response.content
        print("Agent core downloaded successfully in-memory.")
        
        # Save to temp path for fallback
        try:
            zip_path = _get_core_zip_path()
            zip_path.write_bytes(zip_bytes)
        except Exception as write_err:
            print(f"Warning: Failed to save fallback agent_core.zip to temp folder: {write_err}")
    except Exception as exc:
        print(f"Failed to download agent core from server: {exc}")
        try:
            print("Retrying download with SSL verification disabled...")
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        try:
            response = requests.get(download_url, headers=headers, timeout=20, verify=False)
            response.raise_for_status()
            zip_bytes = response.content
            print("Agent core downloaded successfully with verify=False.")
            
            # Save to temp path for fallback
            try:
                zip_path = _get_core_zip_path()
                zip_path.write_bytes(zip_bytes)
            except Exception as write_err:
                print(f"Warning: Failed to save fallback agent_core.zip to temp folder: {write_err}")
        except Exception as retry_exc:
            print(f"Retry with verify=False failed: {retry_exc}")
            # Fallback to local file if exists
            zip_path = _get_core_zip_path()
            if zip_path.exists():
                print(f"Falling back to local agent_core.zip at {zip_path}...")
                try:
                    zip_bytes = zip_path.read_bytes()
                except Exception as read_exc:
                    print(f"Failed to read local fallback agent_core.zip: {read_exc}")
        
    if not zip_bytes:
        print("Error: Could not retrieve agent core bytes. Cannot start agent.")
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
