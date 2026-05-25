from __future__ import annotations

import logging
import mimetypes
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import requests

from config import ServerConfig


LOGGER = logging.getLogger(__name__)
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_DRIVE_FILES_URL = "https://www.googleapis.com/drive/v3/files"
GOOGLE_DRIVE_UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files"
GOOGLE_DRIVE_FOLDER_MIME = "application/vnd.google-apps.folder"


@dataclass(slots=True)
class GoogleDriveSyncResult:
    enabled: bool
    ok: bool
    drive_path: str = ""
    file_id: str = ""
    file_name: str = ""
    web_view_link: str = ""
    updated_existing: bool = False
    error: str = ""
    mode: str = ""

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "enabled": self.enabled,
            "ok": self.ok,
        }
        if self.drive_path:
            payload["drive_path"] = self.drive_path
        if self.file_id:
            payload["file_id"] = self.file_id
        if self.file_name:
            payload["file_name"] = self.file_name
        if self.web_view_link:
            payload["web_view_link"] = self.web_view_link
        payload["updated_existing"] = self.updated_existing
        if self.error:
            payload["error"] = self.error
        if self.mode:
            payload["mode"] = self.mode
        return payload


class GoogleDriveSync:
    def __init__(self, config: ServerConfig) -> None:
        self._requested = bool(config.google_drive_sync_enabled)
        self._mode_requested = str(config.google_drive_sync_mode or "auto").strip().lower() or "auto"
        self._path_prefix = [part for part in str(config.google_drive_sync_prefix).strip("/").split("/") if part]
        self._client_id = config.google_drive_client_id
        self._client_secret = config.google_drive_client_secret
        self._refresh_token = config.google_drive_refresh_token
        self._root_folder_id = config.google_drive_root_folder_id
        self._rclone_bin = str(config.google_drive_rclone_bin or "rclone").strip() or "rclone"
        self._rclone_remote = str(config.google_drive_rclone_remote or "").strip().rstrip("/")
        self._rclone_config = str(config.google_drive_rclone_config or "").strip()
        self._timeout_seconds = config.google_drive_timeout_seconds
        self._session = requests.Session()
        self._access_token = ""
        self._access_token_expires_at = 0.0
        self._folder_cache: dict[tuple[str, str], str] = {}
        self.mode = self._resolve_mode()
        self._missing_fields = self._compute_missing_fields()
        self.enabled = self._requested and not self._missing_fields
        if self._requested and self._missing_fields:
            LOGGER.warning(
                "Google Drive sync enabled but missing config for mode=%s: %s",
                self.mode,
                ", ".join(self._missing_fields),
            )

    def _resolve_mode(self) -> str:
        requested = self._mode_requested
        if requested in {"api", "rclone"}:
            return requested
        if self._has_api_credentials():
            return "api"
        if self._rclone_remote and self._rclone_available():
            return "rclone"
        return "api"

    def _has_api_credentials(self) -> bool:
        return bool(self._client_id and self._client_secret and self._refresh_token and self._root_folder_id)

    def _rclone_available(self) -> bool:
        try:
            cmd = [self._rclone_bin]
            if self._rclone_config:
                cmd.extend(["--config", self._rclone_config])
            cmd.append("version")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.returncode == 0
        except Exception:
            return False

    def _compute_missing_fields(self) -> list[str]:
        if not self._requested:
            return []
        if self.mode == "rclone":
            missing: list[str] = []
            if not self._rclone_remote:
                missing.append("GOOGLE_DRIVE_RCLONE_REMOTE")
            if not self._rclone_available():
                missing.append(f"missing rclone binary: {self._rclone_bin}")
            return missing
        missing = []
        if not self._client_id:
            missing.append("GOOGLE_DRIVE_CLIENT_ID")
        if not self._client_secret:
            missing.append("GOOGLE_DRIVE_CLIENT_SECRET")
        if not self._refresh_token:
            missing.append("GOOGLE_DRIVE_REFRESH_TOKEN")
        if not self._root_folder_id:
            missing.append("GOOGLE_DRIVE_ROOT_FOLDER_ID")
        return missing

    def disabled_result(self) -> GoogleDriveSyncResult:
        if not self._requested:
            return GoogleDriveSyncResult(enabled=False, ok=False, mode=self.mode)
        message = "Missing config: " + ", ".join(self._missing_fields)
        return GoogleDriveSyncResult(enabled=True, ok=False, error=message, mode=self.mode)

    def _drive_path_parts(self, remote_parts: list[str]) -> list[str]:
        normalized = [str(part or "").strip().strip("/") for part in remote_parts if str(part or "").strip().strip("/")]
        return [*self._path_prefix, *normalized]

    def upload_scan(
        self,
        local_path: Path,
        *,
        remote_parts: list[str],
        source_path: str = "",
    ) -> GoogleDriveSyncResult:
        if not self.enabled:
            return self.disabled_result()

        drive_path_parts = self._drive_path_parts(remote_parts)
        if not drive_path_parts:
            raise RuntimeError("Google Drive remote path is empty")
        if self.mode == "rclone":
            return self._upload_scan_rclone(local_path=local_path, drive_path_parts=drive_path_parts)
        return self._upload_scan_api(local_path=local_path, drive_path_parts=drive_path_parts, source_path=source_path)

    def _upload_scan_rclone(self, *, local_path: Path, drive_path_parts: list[str]) -> GoogleDriveSyncResult:
        remote_target = f"{self._rclone_remote}/{'/'.join(drive_path_parts)}"
        cmd = [self._rclone_bin]
        if self._rclone_config:
            cmd.extend(["--config", self._rclone_config])
        cmd.extend(
            [
                "copyto",
                str(local_path),
                remote_target,
                "--stats=0",
                "--checkers=4",
                "--transfers=1",
            ]
        )
        timeout_seconds = max(60, self._timeout_seconds * 10)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        if result.returncode != 0:
            error_text = (result.stderr or result.stdout or f"rclone copyto failed with code {result.returncode}").strip()
            raise RuntimeError(error_text[:2000])
        return GoogleDriveSyncResult(
            enabled=True,
            ok=True,
            drive_path=remote_target,
            file_name=drive_path_parts[-1],
            updated_existing=False,
            mode="rclone",
        )

    def _upload_scan_api(self, *, local_path: Path, drive_path_parts: list[str], source_path: str) -> GoogleDriveSyncResult:
        parent_id = self._root_folder_id
        for folder_name in drive_path_parts[:-1]:
            parent_id = self._ensure_child_folder(parent_id, folder_name)
        file_name = drive_path_parts[-1]
        created: dict[str, object] = {}
        existing = self._find_child_file(parent_id=parent_id, file_name=file_name)
        updated_existing = False
        if existing:
            file_id = str(existing.get("id", "") or "").strip()
            updated_existing = True
        else:
            created = self._create_remote_file(parent_id=parent_id, file_name=file_name, source_path=source_path)
            file_id = str(created.get("id", "") or "").strip()
        try:
            uploaded = self._upload_remote_file(file_id=file_id, local_path=local_path)
        except Exception:
            if file_id and not updated_existing:
                self._delete_remote_file(file_id)
            raise

        return GoogleDriveSyncResult(
            enabled=True,
            ok=True,
            drive_path="/".join(drive_path_parts),
            file_id=str(uploaded.get("id", "") or file_id),
            file_name=str(uploaded.get("name", "") or file_name),
            web_view_link=str(uploaded.get("webViewLink", "") or created.get("webViewLink", "") or ""),
            updated_existing=updated_existing,
            mode="api",
        )

    def _access_token_value(self) -> str:
        now = time.time()
        if self._access_token and now < self._access_token_expires_at - 60:
            return self._access_token

        response = self._session.post(
            GOOGLE_OAUTH_TOKEN_URL,
            data={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "refresh_token": self._refresh_token,
                "grant_type": "refresh_token",
            },
            timeout=self._timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        token = str(payload.get("access_token", "") or "").strip()
        if not token:
            raise RuntimeError("Google OAuth token response missing access_token")
        expires_in = int(payload.get("expires_in", 3600) or 3600)
        self._access_token = token
        self._access_token_expires_at = now + max(300, expires_in)
        return self._access_token

    def _request(self, method: str, url: str, **kwargs: object) -> requests.Response:
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["Authorization"] = f"Bearer {self._access_token_value()}"
        response = self._session.request(method, url, headers=headers, timeout=self._timeout_seconds, **kwargs)
        response.raise_for_status()
        return response

    @staticmethod
    def _escape_query_value(value: str) -> str:
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def _ensure_child_folder(self, parent_id: str, folder_name: str) -> str:
        cache_key = (parent_id, folder_name)
        cached = self._folder_cache.get(cache_key)
        if cached:
            return cached

        escaped_name = self._escape_query_value(folder_name)
        query = (
            f"trashed = false and mimeType = '{GOOGLE_DRIVE_FOLDER_MIME}' "
            f"and name = '{escaped_name}' and '{parent_id}' in parents"
        )
        response = self._request(
            "GET",
            GOOGLE_DRIVE_FILES_URL,
            params={
                "q": query,
                "fields": "files(id,name)",
                "pageSize": 1,
                "spaces": "drive",
            },
        )
        payload = response.json()
        files = payload.get("files", []) if isinstance(payload, dict) else []
        if isinstance(files, list) and files:
            folder_id = str((files[0] or {}).get("id", "") or "").strip()
            if folder_id:
                self._folder_cache[cache_key] = folder_id
                return folder_id

        create_response = self._request(
            "POST",
            GOOGLE_DRIVE_FILES_URL,
            params={"fields": "id,name"},
            headers={"Content-Type": "application/json"},
            json={
                "name": folder_name,
                "mimeType": GOOGLE_DRIVE_FOLDER_MIME,
                "parents": [parent_id],
            },
        )
        folder_payload = create_response.json()
        folder_id = str(folder_payload.get("id", "") or "").strip()
        if not folder_id:
            raise RuntimeError(f"Google Drive folder create returned no id for {folder_name}")
        self._folder_cache[cache_key] = folder_id
        return folder_id

    def _find_child_file(self, *, parent_id: str, file_name: str) -> dict[str, object]:
        escaped_name = self._escape_query_value(file_name)
        query = (
            f"trashed = false and name = '{escaped_name}' and "
            f"mimeType != '{GOOGLE_DRIVE_FOLDER_MIME}' and '{parent_id}' in parents"
        )
        response = self._request(
            "GET",
            GOOGLE_DRIVE_FILES_URL,
            params={
                "q": query,
                "fields": "files(id,name,webViewLink)",
                "pageSize": 1,
                "spaces": "drive",
            },
        )
        payload = response.json()
        files = payload.get("files", []) if isinstance(payload, dict) else []
        if isinstance(files, list) and files:
            first = files[0]
            if isinstance(first, dict):
                return first
        return {}

    def _create_remote_file(self, *, parent_id: str, file_name: str, source_path: str) -> dict[str, object]:
        description = "Uploaded by PrintAgent"
        if source_path:
            description = f"{description} from {source_path}"
        response = self._request(
            "POST",
            GOOGLE_DRIVE_FILES_URL,
            params={"fields": "id,name,webViewLink"},
            headers={"Content-Type": "application/json"},
            json={
                "name": file_name,
                "parents": [parent_id],
                "description": description[:1000],
            },
        )
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("Google Drive file create returned invalid payload")
        return payload

    def _upload_remote_file(self, *, file_id: str, local_path: Path) -> dict[str, object]:
        if not file_id:
            raise RuntimeError("Cannot upload to Google Drive without file id")
        content_type = mimetypes.guess_type(local_path.name)[0] or "application/octet-stream"
        with local_path.open("rb") as handle:
            response = self._request(
                "PATCH",
                f"{GOOGLE_DRIVE_UPLOAD_URL}/{file_id}",
                params={"uploadType": "media", "fields": "id,name,size,webViewLink"},
                headers={"Content-Type": content_type},
                data=handle,
            )
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("Google Drive upload returned invalid payload")
        return payload

    def _delete_remote_file(self, file_id: str) -> None:
        try:
            self._request("DELETE", f"{GOOGLE_DRIVE_FILES_URL}/{file_id}")
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Google Drive cleanup failed for file_id=%s: %s", file_id, exc)
