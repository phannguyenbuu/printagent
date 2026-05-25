import sys
import logging
from agent.config import AppConfig
from agent.services.api_client import APIClient, Printer
from agent.modules.ricoh.service import RicohService

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def main():
    config = AppConfig.load()
    # Override for test printer
    printer = Printer(
        name="Test Ricoh Copier",
        ip="192.168.1.226",
        user="admin",
        password="",
        printer_type="ricoh",
    )
    print(f"Testing address list fetch from printer IP: {printer.ip}")
    api_client = APIClient(config)
    service = RicohService(api_client, config=config)
    try:
        payload = service.process_address_list(printer)
        print("\n=== SUCCESS ===")
        print(f"Timestamp: {payload.get('timestamp')}")
        print(f"Total entries: {len(payload.get('address_list', []))}")
        print("\nAddress Book Entries:")
        for idx, entry in enumerate(payload.get('address_list', [])):
            print(f"[{idx}] RegNo: {entry.get('registration_no')} | Type: {entry.get('type')} | Name: {entry.get('name')} | UserCode: {entry.get('user_code')} | Email: {entry.get('email_address')} | Folder: {entry.get('folder')}")
    except Exception as e:
        print(f"\n=== FAILED ===")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
