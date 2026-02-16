from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time

from dotenv import load_dotenv

from app.config import AppConfig
from app.modules.ricoh.service import RicohService
from app.services.api_client import APIClient, Printer
from app.web import create_app


def setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def load_test_printer(config: AppConfig) -> Printer:
    return Printer(
        name="Test Printer",
        ip=config.get_string("test.ip"),
        user=config.get_string("test.user"),
        password=config.get_string("test.password"),
        printer_type="ricoh",
    )


def run_test_mode(config: AppConfig, service: RicohService) -> None:
    printer = load_test_printer(config)
    if not printer.ip:
        raise ValueError("Missing test.ip in config.yaml")

    post_server = config.get_bool("test.post_server", True)
    while True:
        print("\n=== MENU TEST ===")
        print("1. Lay Status")
        print("2. Lay Device Info")
        print("3. Lay Counter")
        print("4. Bat may")
        print("5. Khoa may")
        print("6. Lay Address List")
        print("7. Log Counter (moi phut)")
        print("8. Log Status (moi 30s)")
        print("0. Thoat")
        choice = input("Chon chuc nang (0-8): ").strip()

        try:
            if choice == "1":
                payload = service.process_status(printer, post_server)
                print(payload["status_data"])
            elif choice == "2":
                payload = service.process_device_info(printer, post_server)
                print(payload["device_info"])
            elif choice == "3":
                payload = service.process_counter(printer, post_server)
                print(payload["counter_data"])
            elif choice == "4":
                service.enable_machine(printer)
                print("Da bat may thanh cong")
            elif choice == "5":
                service.lock_machine(printer)
                print("Da khoa may thanh cong")
            elif choice == "6":
                payload = service.process_address_list(printer)
                print(f"Tong so entry: {max(len(payload['address_list']) - 1, 0)}")
            elif choice == "7":
                print("Nhan Ctrl+C de dung")
                service.start_counter_logging(printer)
            elif choice == "8":
                print("Nhan Ctrl+C de dung")
                service.start_status_logging(printer)
            elif choice == "0":
                return
            else:
                print("Lua chon khong hop le")
        except KeyboardInterrupt:
            print("\nDa dung")
        except Exception as exc:  # noqa: BLE001
            print(f"Loi: {exc}")


def run_normal_mode(service: RicohService) -> None:
    stop = False

    def handle_signal(_sig: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    service.start()
    try:
        while not stop:
            time.sleep(0.2)
    finally:
        service.stop()


def main() -> int:
    load_dotenv()
    setup_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["web", "service", "test"],
        default="web",
        help="Run mode: web (Flask UI), service (scheduler), test (interactive menu)",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("FLASK_HOST", "127.0.0.1"),
        help="Flask host in web mode (env: FLASK_HOST)",
    )
    parser.add_argument(
        "--port",
        default=int(os.getenv("FLASK_PORT", "5000")),
        type=int,
        help="Flask port in web mode (env: FLASK_PORT)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=os.getenv("FLASK_DEBUG", "false").strip().lower() in {"1", "true", "yes", "on"},
        help="Enable Flask debug mode (env: FLASK_DEBUG=true/false)",
    )
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    args = parser.parse_args()

    if args.mode == "web":
        app = create_app(args.config)
        app.run(host=args.host, port=args.port, debug=args.debug)
        return 0

    config = AppConfig.load(args.config)
    service = RicohService(APIClient(config))
    if args.mode == "test":
        run_test_mode(config, service)
    else:
        run_normal_mode(service)
    return 0


if __name__ == "__main__":
    sys.exit(main())
