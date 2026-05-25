import sys
from pathlib import Path
import json

root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(root))

from backend.db import session_factory
from backend.models import Printer

def main():
    with session_factory() as session:
        printers = session.query(Printer).all()
        for p in printers:
            print(f"Printer: {p.printer_name} | IP: {p.ip} | LAN UID: {p.lan_uid}")

if __name__ == "__main__":
    main()
