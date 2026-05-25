# ricoh_web_scan.py
# Stub for backward compatibility. All routes and functions are now consolidated into scan_ricoh.py.
import logging
import scan_ricoh

LOGGER = logging.getLogger(__name__)
LOGGER.info("ricoh_web_scan stub loaded (delegating to scan_ricoh.py).")

def register_scan_routes(app):
    scan_ricoh.register_scan_routes(app)
