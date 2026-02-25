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

    def scan_subnet(self, prefix: str | None = None) -> list[str]:
        if not prefix:
            local_ip = self.get_local_ip()
            prefix = self.get_subnet_prefix(local_ip)
        
        if not prefix:
            LOGGER.warning("Could not determine subnet prefix for scanning")
            return []

        LOGGER.info("Starting parallel subnet scan for %s.0/24", prefix)
        ips = [f"{prefix}.{i}" for i in range(1, 255)]
        active_ips: list[str] = []
        
        lock = threading.Lock()

        def worker(ip: str) -> None:
            if self.ping_host(ip):
                with lock:
                    active_ips.append(ip)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(worker, ips)

        LOGGER.info("Subnet scan finished. Found %d active hosts.", len(active_ips))
        return active_ips
