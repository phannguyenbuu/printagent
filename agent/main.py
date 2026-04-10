from __future__ import annotations

import argparse
import logging
from datetime import date
from logging import FileHandler, Filter
import os
import signal
import sys
import threading
import time
from pathlib import Path

from app.config import AppConfig
from app.modules.ricoh.service import RicohService
from app.services.api_client import APIClient, Printer
from app.services.ftp_worker import FtpWorker
from app.services.polling_bridge import PollingBridge
from app.services.runtime import acquire_single_instance, default_log_path, ensure_startup_registration, startup_command_for_current_exe
from agent.services.tray import TrayController
from app.services.updater import AutoUpdater
from app.web import create_app, run_web_server, shutdown_app_resources


DEFAULT_WEB_PORT = 9173
BACKGROUND_HEARTBEAT_SECONDS = 300


class _MaxLevelFilter(Filter):
    def __init__(self, max_level: int) -> None:
        super().__init__()
        self.max_level = max_level

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno < self.max_level


class _DailyStoutFileHandler(FileHandler):
    def __init__(self, base_path: Path, encoding: str = "utf-8") -> None:
        self.base_path = base_path
        self.current_day = date.today()
        try:
            if self.base_path.exists():
                file_day = date.fromtimestamp(self.base_path.stat().st_mtime)
                if file_day != self.current_day:
                    archive_path = self.base_path.with_name(f"{self.base_path.stem}_{file_day.isoformat()}{self.base_path.suffix}")
                    try:
                        if archive_path.exists():
                            archive_path.unlink()
                    except Exception:
                        pass
                    try:
                        self.base_path.replace(archive_path)
                    except Exception:
                        pass
        except Exception:
            pass
        super().__init__(base_path, encoding=encoding)

    def _rollover_if_needed(self) -> None:
        today = date.today()
        if today == self.current_day:
            return
        self.acquire()
        try:
            if today == self.current_day:
                return
            try:
                if self.stream:
                    self.stream.flush()
                    self.stream.close()
                    self.stream = None
            except Exception:
                pass
            previous_day = self.current_day
            if self.base_path.exists():
                archive_path = self.base_path.with_name(f"{self.base_path.stem}_{previous_day.isoformat()}{self.base_path.suffix}")
                try:
                    if archive_path.exists():
                        archive_path.unlink()
                except Exception:
                    pass
                try:
                    self.base_path.replace(archive_path)
                except Exception:
                    pass
            self.current_day = today
            self.stream = self._open()
        finally:
            self.release()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._rollover_if_needed()
            super().emit(record)
        except Exception:
            self.handleError(record)


def _resolve_log_path(preferred: str, runtime_root: Path, fallback_name: str) -> Path:
    candidate = Path(preferred)
    try:
        candidate.parent.mkdir(parents=True, exist_ok=True)
        return candidate
    except Exception:
        fallback = runtime_root / fallback_name
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return fallback


def setup_logging(runtime_root: Path) -> tuple[Path, Path]:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    stdout_path = _resolve_log_path(str(default_log_path("stout.txt")), runtime_root, "stout.txt")
    stderr_path = _resolve_log_path(str(default_log_path("sterror.txt")), runtime_root, "sterror.txt")

    stdout_handler = _DailyStoutFileHandler(stdout_path, encoding="utf-8")
    stdout_handler.setLevel(logging.INFO)
    stdout_handler.addFilter(_MaxLevelFilter(logging.ERROR))
    stdout_handler.setFormatter(formatter)

    stderr_handler = FileHandler(stderr_path, encoding="utf-8")
    stderr_handler.setLevel(logging.ERROR)
    stderr_handler.setFormatter(formatter)

    stdout_stream = logging.StreamHandler(sys.stdout)
    stdout_stream.setLevel(logging.INFO)
    stdout_stream.addFilter(_MaxLevelFilter(logging.ERROR))
    stdout_stream.setFormatter(formatter)

    stderr_stream = logging.StreamHandler(sys.stderr)
    stderr_stream.setLevel(logging.ERROR)
    stderr_stream.setFormatter(formatter)

    root.addHandler(stdout_handler)
    root.addHandler(stderr_handler)
    root.addHandler(stdout_stream)
    root.addHandler(stderr_stream)
    return stdout_path, stderr_path


def _ensure_runtime_root() -> Path:
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        os.chdir(exe_dir)
        return exe_dir
    return Path.cwd()


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
        raise ValueError("Missing test.ip configuration")

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


def run_normal_mode(service: RicohService, config: AppConfig, updater: AutoUpdater) -> None:
    import socket

    # Resolve LAN UID for display
    hostname = socket.gethostname()
    local_ip = PollingBridge._resolve_local_ip()
    restart_event = threading.Event()
    bridge = PollingBridge(
        config,
        service._api_client,
        service,
        updater=updater,
        run_mode="service",
        web_port=0,
        restart_callback=restart_event.set,
    )
    lan_uid, _ = bridge._resolve_lan_info(hostname, local_ip)

    print(f"\n{'='*60}")
    print(f" PRINT AGENT STARTING...")
    print(f" MODE: SERVICE")
    print(f" LAN UID: {lan_uid}")
    print(f" LEAD   : {config.get_string('polling.lead')}")
    print(f"{'='*60}\n")
    
    stop = False

    def handle_signal(_sig: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    ok, message = bridge.start()
    if not ok and "already running" not in message.lower():
        raise RuntimeError(message)
    try:
        while not stop and not restart_event.wait(0.2):
            time.sleep(0.2)
    finally:
        bridge.stop()
        service.stop()


def run_ftp_worker_mode() -> None:
    worker = FtpWorker()
    try:
        worker.run_forever()
    finally:
        worker.stop()


def main() -> int:
    runtime_root = _ensure_runtime_root()
    stdout_path, stderr_path = setup_logging(runtime_root)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["web", "service", "test", "ftp-worker"],
        default="web",
        help="Run mode: web (Flask UI), service (scheduler), test (interactive menu), ftp-worker (persistent FTP host)",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("FLASK_HOST", "127.0.0.1"),
        help="Flask host in web mode (env: FLASK_HOST)",
    )
    parser.add_argument(
        "--port",
        default=int(os.getenv("FLASK_PORT", str(DEFAULT_WEB_PORT))),
        type=int,
        help="Flask port in web mode (env: FLASK_PORT)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=os.getenv("FLASK_DEBUG", "false").strip().lower() in {"1", "true", "yes", "on"},
        help="Enable Flask debug mode (env: FLASK_DEBUG=true/false)",
    )
    args = parser.parse_args()
    instance_name = "Global\\GoPrinxAgentFtpWorker" if args.mode == "ftp-worker" else "Global\\GoPrinxAgentMain"
    instance_lock, is_primary = acquire_single_instance(instance_name)
    if not is_primary:
        logging.info("Another GoPrinxAgent process is already running for mode=%s; skipping startup", args.mode)
        return 0

    startup_ok = False
    startup_note = "skipped"
    if args.mode == "ftp-worker":
        worker_cmd = startup_command_for_current_exe("ftp-worker")
        startup_ok, startup_note = ensure_startup_registration(app_name="GoPrinxAgentFtpWorker", command=worker_cmd)
    else:
        worker_cmd = startup_command_for_current_exe("ftp-worker")
        if args.mode == "web":
            main_cmd = startup_command_for_current_exe("web", args.host, args.port)
        elif args.mode == "service":
            main_cmd = startup_command_for_current_exe("service")
        else:
            main_cmd = startup_command_for_current_exe("web", args.host, args.port)
        startup_ok, startup_note = ensure_startup_registration(command=main_cmd)
        worker_ok, worker_note = ensure_startup_registration(app_name="GoPrinxAgentFtpWorker", command=worker_cmd)
        logging.info("FTP worker startup registration: %s (%s)", worker_ok, worker_note)
    logging.info("Startup registration: %s (%s)", startup_ok, startup_note)
    logging.info("Log files: stdout=%s stderr=%s", stdout_path.as_posix(), stderr_path.as_posix())

    try:
        updater_args: list[str]
        if args.mode == "web":
            updater_args = ["--mode", "web", "--host", args.host, "--port", str(args.port)]
        elif args.mode == "service":
            updater_args = ["--mode", "service"]
        elif args.mode == "ftp-worker":
            updater_args = ["--mode", "ftp-worker"]
        else:
            updater_args = ["--mode", "test"]
        updater = AutoUpdater(project_root=Path(__file__).resolve().parents[1], current_args=updater_args)

        if args.mode == "web":
            os.environ["APP_RUN_MODE"] = "web"
            os.environ["APP_WEB_PORT"] = str(args.port)
            current_args = ["--mode", "web", "--host", args.host, "--port", str(args.port)]
            stop_event = threading.Event()
            app = create_app(current_args=current_args, shutdown_event=stop_event)
            server, server_thread = run_web_server(app, args.host, args.port)
            tray = TrayController(f"http://127.0.0.1:{args.port}", stop_event=stop_event)
            tray_thread = threading.Thread(target=tray.run, daemon=True, name="agent-tray")
            tray_thread.start()
            try:
                while not stop_event.wait(0.5):
                    if not tray_thread.is_alive():
                        LOGGER.warning("Tray thread exited unexpectedly; keeping web server alive")
                        tray_thread = threading.Thread(target=tray.run, daemon=True, name="agent-tray-restart")
                        tray_thread.start()
            finally:
                stop_event.set()
                shutdown_app_resources(app)
                try:
                    server.shutdown()
                except Exception:
                    pass
                try:
                    server.server_close()
                except Exception:
                    pass
                if server_thread.is_alive():
                    server_thread.join(timeout=5)
            return 0

        if args.mode == "ftp-worker":
            run_ftp_worker_mode()
            return 0

        config = AppConfig.load()
        service = RicohService(APIClient(config), config=config)
        if args.mode == "test":
            run_test_mode(config, service)
        else:
            os.environ["APP_RUN_MODE"] = "service"
            os.environ["APP_WEB_PORT"] = "0"
            run_normal_mode(service, config, updater)
        return 0
    finally:
        if instance_lock is not None:
            instance_lock.release()


if __name__ == "__main__":
    sys.exit(main())
