from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Callable

from websocket import WebSocketApp


LOGGER = logging.getLogger(__name__)


class WSClient:
    def __init__(self, url: str = "", token: str = "", on_message_callback: Callable[[str], None] | None = None) -> None:
        self.url = url.strip()
        self.token = token.strip()
        self.on_message_callback = on_message_callback
        self._app: WebSocketApp | None = None
        self._thread: threading.Thread | None = None
        self._send_lock = threading.Lock()
        self._connected = False
        self._last_error = ""
        self._last_message_at = ""

    def is_configured(self) -> bool:
        return bool(self.url)

    def connect(self) -> tuple[bool, str]:
        if not self.url:
            return False, "Missing websocket URL"
        if self._thread and self._thread.is_alive():
            return True, "Already connecting/connected"

        headers: list[str] = []
        if self.token:
            headers.append(f"Authorization: Bearer {self.token}")

        self._app = WebSocketApp(
            self.url,
            header=headers,
            on_open=self._on_open,
            on_close=self._on_close,
            on_error=self._on_error,
            on_message=self._on_message,
        )
        self._thread = threading.Thread(target=self._run_forever, daemon=True, name="ws-client-thread")
        self._thread.start()
        return True, "Connecting"

    def disconnect(self) -> tuple[bool, str]:
        if self._app is None:
            return True, "Not connected"
        try:
            self._app.close()
        except Exception as exc:  # noqa: BLE001
            self._last_error = str(exc)
            return False, str(exc)
        self._connected = False
        return True, "Disconnected"

    def send(self, event: str, payload: dict[str, Any]) -> tuple[bool, str]:
        if not self._connected or self._app is None:
            return False, "WebSocket is not connected"
        message = {
            "event": event,
            "payload": payload,
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }
        raw = json.dumps(message, ensure_ascii=True)
        try:
            with self._send_lock:
                self._app.send(raw)
            self._last_message_at = message["sent_at"]
            return True, "Sent"
        except Exception as exc:  # noqa: BLE001
            self._last_error = str(exc)
            return False, str(exc)

    def status(self) -> dict[str, Any]:
        return {
            "configured": self.is_configured(),
            "url": self.url,
            "connected": self._connected,
            "thread_alive": bool(self._thread and self._thread.is_alive()),
            "last_error": self._last_error,
            "last_message_at": self._last_message_at,
        }

    def _run_forever(self) -> None:
        if self._app is None:
            return
        try:
            self._app.run_forever(ping_interval=20, ping_timeout=10)
        except Exception as exc:  # noqa: BLE001
            self._last_error = str(exc)
            LOGGER.exception("WebSocket run_forever failed: %s", exc)

    def _on_open(self, _ws: WebSocketApp) -> None:
        self._connected = True
        self._last_error = ""
        LOGGER.info("WebSocket connected: %s", self.url)

    def _on_close(self, _ws: WebSocketApp, _status_code: int, _msg: str) -> None:
        self._connected = False
        LOGGER.info("WebSocket disconnected")

    def _on_error(self, _ws: WebSocketApp, error: Any) -> None:
        self._connected = False
        self._last_error = str(error)
        LOGGER.warning("WebSocket error: %s", error)

    def _on_message(self, _ws: WebSocketApp, message: str) -> None:
        self._last_message_at = datetime.now(timezone.utc).isoformat()
        LOGGER.debug("WebSocket message: %s", message[:200])
        if self.on_message_callback is not None:
            try:
                self.on_message_callback(message)
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("WebSocket message callback failed: %s", exc)
