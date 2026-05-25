from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any

from flask import Flask
from werkzeug.serving import make_server

from agent.config import AppConfig
from agent.modules.ricoh.service import RicohService
from agent.modules.toshiba.service import ToshibaService
from agent.services.api_client import APIClient
from agent.services.polling_bridge import PollingBridge
from agent.services.updater import AutoUpdater


LOGGER = logging.getLogger(__name__)
DEFAULT_WEB_PORT = 9173


def create_app(
    current_args: list[str] | None = None,
    shutdown_event: threading.Event | None = None,
) -> Flask:
    # Check if we are running via MemoryZipImporter (loader)
    # If so, extract the templates and static resources to a temp folder on disk so Flask can load them
    extracted_template_dir = None
    extracted_static_dir = None
    
    importer = next((imp for imp in sys.meta_path if hasattr(imp, "zip_file")), None)
    if importer is not None:
        import tempfile
        try:
            temp_root = Path(tempfile.gettempdir()) / "GoPrinxAgent" / "extracted_resources"
            temp_root.mkdir(parents=True, exist_ok=True)
            for name in importer.zip_file.namelist():
                if name.startswith("agent/templates/") or name.startswith("agent/static/"):
                    dest = temp_root / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(importer.zip_file.read(name))
            
            extracted_template_dir = temp_root / "agent" / "templates"
            extracted_static_dir = temp_root / "agent" / "static"
            LOGGER.info("Extracted in-memory templates to %s and static to %s", extracted_template_dir, extracted_static_dir)
        except Exception as exc:
            LOGGER.error("Failed to extract in-memory zip resources: %s", exc)

    bundle_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    template_candidates = []
    if extracted_template_dir and extracted_template_dir.exists():
        template_candidates.append(extracted_template_dir)
    template_candidates.extend([
        Path(__file__).resolve().parent / "templates",
        Path(__file__).resolve().parents[1] / "backend" / "templates",
        bundle_root / "agent" / "templates",
        bundle_root / "templates",
    ])
    template_dir = next((path for path in template_candidates if path.exists()), Path(__file__).resolve().parent / "templates")
    
    static_candidates = []
    if extracted_static_dir and extracted_static_dir.exists():
        static_candidates.append(extracted_static_dir)
    static_candidates.extend([
        Path(__file__).resolve().parent / "static",
        bundle_root / "agent" / "static",
        bundle_root / "static",
        Path(__file__).resolve().parents[1] / "backend" / "static",
    ])
    static_dir = next((path for path in static_candidates if path.exists()), Path(__file__).resolve().parent / "static")

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
        instance_path=os.path.abspath(os.getcwd())
    )
    config = AppConfig.load()
    api_client = APIClient(config)
    ricoh_service = RicohService(api_client, config=config)
    toshiba_service = ToshibaService(api_client)
    updater_args = list(current_args or ["--mode", "web"])
    updater = AutoUpdater(project_root=Path(__file__).resolve().parents[1], current_args=updater_args)
    web_port = int(str(os.getenv("APP_WEB_PORT", os.getenv("FLASK_PORT", str(DEFAULT_WEB_PORT))) or str(DEFAULT_WEB_PORT)))
    polling_bridge = PollingBridge(
        config,
        api_client,
        ricoh_service,
        toshiba_service=toshiba_service,
        updater=updater,
        run_mode="web",
        web_port=web_port,
        restart_callback=(shutdown_event.set if shutdown_event is not None else None),
    )

    app.config["APP_CONFIG"] = config
    app.config["API_CLIENT"] = api_client
    app.config["RICOH_SERVICE"] = ricoh_service
    app.config["TOSHIBA_SERVICE"] = toshiba_service
    app.config["POLLING_BRIDGE"] = polling_bridge
    app.config["UPDATER"] = updater
    app.config["LOG_JOBS"] = {"counter": {}, "status": {}}

    p_ok, p_msg = polling_bridge.start()
    LOGGER.info("Polling bridge: %s (%s)", p_ok, p_msg)

    from agent.web_device import register_device_routes
    from agent.web_scan_ftp import register_scan_ftp_routes
    from agent.web_ui import register_ui_routes

    register_ui_routes(app)
    register_scan_ftp_routes(app)
    register_device_routes(app)

    # Register dynamic routes from compiled scripts (skip if already registered by source)
    try:
        import scan_ricoh
        if hasattr(scan_ricoh, "register_scan_routes") and "api_scan_address_list" not in app.view_functions:
            scan_ricoh.register_scan_routes(app)
    except ImportError:
        pass

    return app


def run_web_server(app: Flask, host: str, port: int) -> tuple[Any, threading.Thread]:
    server = make_server(host, port, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="agent-web-server")
    thread.start()
    LOGGER.info("Web server started on http://%s:%s", host, port)
    return server, thread


def shutdown_app_resources(app: Flask) -> None:
    bridge = app.config.get("POLLING_BRIDGE")
    if bridge is not None:
        try:
            bridge.stop()
        except Exception:  # noqa: BLE001
            pass

    jobs = app.config.get("LOG_JOBS", {})
    for group in (jobs.get("counter", {}), jobs.get("status", {})):
        for value in group.values():
            try:
                value["stop"].set()
            except Exception:  # noqa: BLE001
                pass
