from __future__ import annotations

from agent.web_scan_address import register_scan_address_routes
from agent.web_scan_misc import register_scan_misc_routes


def register_scan_routes(app):
    register_scan_address_routes(app)
    register_scan_misc_routes(app)
