from __future__ import annotations

import logging
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

LOGGER = logging.getLogger(__name__)

class SubnetScanner:
    PRINTER_PORTS = [80, 443, 9100, 515, 631]

    def __init__(self, max_workers: int = 50) -> None:
        self.max_workers = max_workers

    def check_port(self, ip: str, port: int, timeout: float = 0.3) -> bool:
        """Checks if a specific port is open on the host."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, port)) == 0
        except Exception:
            return False

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

    RICOH_MAC_PREFIXES = [
        "00:00:74", "00:26:73", "00:E0:21", "00:1B:ED",
        "00:00:18", "00:06:78", "00:15:C5", "00:80:91",
        "00:0B:A9"
    ]

    @classmethod
    def is_ricoh_mac(cls, mac: str) -> bool:
        if not mac:
            return False
        clean_mac = mac.replace("-", ":").upper()
        return any(clean_mac.startswith(prefix) for prefix in cls.RICOH_MAC_PREFIXES)

    def is_ricoh_web_ui(self, ip: str) -> bool:
        """Probes the Web UI of the IP to check for Ricoh-specific markers."""
        try:
            # Use a slightly longer timeout for HTTP probe than for connect_ex
            url = f"http://{ip}/"
            # Ricoh Web Image Monitor usually has distinctive headers or title
            response = requests.get(url, timeout=1.0, verify=False)
            content = response.text.lower()
            return "ricoh" in content or "web image monitor" in content
        except Exception:
            return False

    def is_ricoh_probe(self, ip: str, mac: str = "") -> bool:
        """Determines if the host is likely a Ricoh printer."""
        # Step 1: MAC OUI Check (fastest if MAC is known)
        if mac and self.is_ricoh_mac(mac):
            return True

        # Step 2: Port check (standard printer ports)
        has_printer_ports = False
        for port in self.PRINTER_PORTS:
            if self.check_port(ip, port):
                has_printer_ports = True
                break
        
        if not has_printer_ports:
            return False

        # Step 3: Deep Web Probe (definitive)
        return self.is_ricoh_web_ui(ip)

    def scan_subnet(self, prefix: str | None = None) -> list[dict[str, Any]]:
        if not prefix:
            local_ip = self.get_local_ip()
            prefix = self.get_subnet_prefix(local_ip)
        
        if not prefix:
            LOGGER.warning("Could not determine subnet prefix for scanning")
            return []

        LOGGER.info("Starting refined Ricoh subnet scan for %s.0/24", prefix)
        ips = [f"{prefix}.{i}" for i in range(1, 255)]
        discovered_devices: list[dict[str, Any]] = []
        
        lock = threading.Lock()

        def worker(ip: str) -> None:
            if self.ping_host(ip):
                # At this stage we might not know the MAC yet (it will be in ARP after ping)
                # so we rely primarily on the Web UI probe if MAC is missing.
                is_ricoh = self.is_ricoh_probe(ip)
                with lock:
                    discovered_devices.append({
                        "ip": ip,
                        "is_ricoh": is_ricoh
                    })

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(worker, ips)

        ricoh_count = sum(1 for d in discovered_devices if d["is_ricoh"])
        LOGGER.info("Subnet scan finished. Active hosts: %d, Ricoh machines: %d", 
                    len(discovered_devices), ricoh_count)
        return discovered_devices
