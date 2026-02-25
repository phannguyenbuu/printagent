from __future__ import annotations

import logging
import threading
import time
from typing import Any

from app.modules.ricoh.base import RicohServiceBase
from app.modules.ricoh.collector import RicohCollectorMixin
from app.modules.ricoh.control import RicohControlMixin
from app.modules.ricoh.address_book import RicohAddressBookMixin
from app.modules.ricoh.wizard import RicohAddressWizardMixin
from app.services.api_client import APIClient, Printer
from app.utils.shares import ShareManager

LOGGER = logging.getLogger(__name__)

class RicohService(
    RicohCollectorMixin,
    RicohControlMixin,
    RicohAddressBookMixin,
    RicohAddressWizardMixin
):
    """
    Unified Ricoh printer service that coordinates polling, counters, 
    machine control, and address book management.
    """
    def __init__(self, api_client: APIClient, interval_seconds: int = 60) -> None:
        super().__init__(api_client, interval_seconds)
        self.share_manager = ShareManager()

    def process_printers(self, printers: list[Printer], should_post: bool = True) -> list[dict[str, Any]]:
        results = []
        for printer in printers:
            try:
                # 1. Check/Persist Credentials if missing
                if not printer.user or not printer.password:
                    try:
                        session = self.create_http_client(printer, authenticated=True)
                        LOGGER.info("Discovered credentials for %s: %s", printer.ip, printer.user)
                    except Exception:
                        pass
                
                # 2. Collect Data
                status = self.process_status(printer, should_post)
                counter = self.process_counter(printer, should_post)
                results.append({"ip": printer.ip, "status": status, "counter": counter})
            except Exception as e:
                LOGGER.error("Error processing printer %s: %s", printer.ip, e)
        return results

    def start(self, printers: list[Printer]) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, args=(printers,), daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run_loop(self, printers: list[Printer]) -> None:
        while not self._stop_event.is_set():
            self.process_printers(printers)
            time.sleep(self.interval_seconds)
