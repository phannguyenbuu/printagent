from __future__ import annotations

import logging
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

LOGGER = logging.getLogger(__name__)

class SubnetScanner:
    def __init__(self, max_workers: int = 50) -> None:
        self.max_workers = max_workers

    @staticmethod
    def get_local_ip() -> str:
        try:
            # Create a dummy socket to find local interface IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            # Doesn't need to be reachable
            s.connect(("8.8.8.8", 1))
            local_ip = s.getsockname()[0]
            s.close()
            return str(local_ip)
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def get_subnet_prefix(ip: str) -> str:
        if not ip or ip == "127.0.0.1":
            return ""
        parts = ip.split(".")
        if len(parts) != 4:
            return ""
        return ".".join(parts[:3])

    def ping_host(self, ip: str) -> bool:
        """
        Performs a single ping to a host.
        On Windows: -n 1 (one packet), -w 500 (500ms timeout)
        """
        try:
            # -n 1: 1 packet
            # -w 500: 500ms wait
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "500", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            return result.returncode == 0
        except Exception:
            return False

    PRINTER_PORTS = [80, 443, 9100, 515, 631]

    def check_port(self, ip: str, port: int, timeout: float = 0.3) -> bool:
        """Checks if a specific port is open on the host."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, port)) == 0
        except Exception:
            return False

    def is_likely_printer(self, ip: str) -> bool:
        """Probes common printer ports to determine if the host is a printer."""
        # Use a smaller timeout for port checks during mass scan
        for port in self.PRINTER_PORTS:
            if self.check_port(ip, port):
                return True
        return False

    def scan_subnet(self, prefix: str | None = None) -> list[dict[str, Any]]:
        if not prefix:
            local_ip = self.get_local_ip()
            prefix = self.get_subnet_prefix(local_ip)
        
        if not prefix:
            LOGGER.warning("Could not determine subnet prefix for scanning")
            return []

        LOGGER.info("Starting parallel subnet scan (ping + port) for %s.0/24", prefix)
        ips = [f"{prefix}.{i}" for i in range(1, 255)]
        discovered_devices: list[dict[str, Any]] = []
        
        lock = threading.Lock()

        def worker(ip: str) -> None:
            if self.ping_host(ip):
                is_printer = self.is_likely_printer(ip)
                with lock:
                    discovered_devices.append({
                        "ip": ip,
                        "is_printer": is_printer
                    })

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(worker, ips)

        LOGGER.info("Subnet scan finished. Found %d active hosts.", len(discovered_devices))
        return discovered_devices
