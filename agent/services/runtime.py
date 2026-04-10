from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import sys
import socket
import tempfile
import winreg
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import msvcrt
except Exception:  # noqa: BLE001
    msvcrt = None  # type: ignore[assignment]


LOGGER = logging.getLogger(__name__)
ERROR_ALREADY_EXISTS = 183
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
APP_RUNTIME_DIR_NAME = "GoPrinxAgent"


@dataclass
class SingleInstanceLock:
    name: str
    handle: int
    file_handle: Any | None = None
    lock_path: Path | None = None

    def release(self) -> None:
        if self.file_handle is not None:
            try:
                if msvcrt is not None:
                    try:
                        self.file_handle.seek(0)
                    except Exception:
                        pass
                    try:
                        msvcrt.locking(self.file_handle.fileno(), msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                self.file_handle.close()
            except Exception:
                pass
            self.file_handle = None
        if not self.handle:
            return
        try:
            ctypes.windll.kernel32.ReleaseMutex(self.handle)
        except Exception:
            pass
        try:
            ctypes.windll.kernel32.CloseHandle(self.handle)
        except Exception:
            pass
        self.handle = 0


def is_windows() -> bool:
    return os.name == "nt"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _safe_runtime_segment(value: str, default: str) -> str:
    text = str(value or "").strip()
    cleaned = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in text)
    cleaned = cleaned.strip("_")
    return cleaned or default


def _safe_runtime_filename(value: str, default: str) -> str:
    text = str(value or "").strip()
    cleaned = "".join(ch if ch.isalnum() or ch in {"_", "-", "."} else "_" for ch in text)
    cleaned = cleaned.strip("_.")
    return cleaned or default


def user_temp_root(app_name: str = APP_RUNTIME_DIR_NAME) -> Path:
    candidates: list[Path] = []
    if is_windows():
        env_base = str(os.getenv("LOCALAPPDATA") or "").strip()
        if env_base:
            candidates.append(Path(env_base) / "Temp")
        candidates.append(Path.home() / "AppData" / "Local" / "Temp")
    candidates.append(Path(tempfile.gettempdir()))
    candidates.append(Path.cwd() / "storage" / "temp")

    safe_name = _safe_runtime_segment(app_name, APP_RUNTIME_DIR_NAME)
    for base in candidates:
        try:
            root = base / safe_name
            root.mkdir(parents=True, exist_ok=True)
            return root
        except Exception:
            continue
    return Path(tempfile.gettempdir()) / safe_name


def default_ftp_root(site_name: str = "") -> Path:
    root = user_temp_root() / "ftp"
    root.mkdir(parents=True, exist_ok=True)
    safe_site_name = _safe_runtime_segment(site_name, "ftp_site")
    return root / safe_site_name if site_name else root


def default_log_path(filename: str) -> Path:
    logs_dir = user_temp_root() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir / _safe_runtime_filename(filename, "agent.log")


def fresh_pyinstaller_env() -> dict[str, str]:
    env = dict(os.environ)
    if not is_frozen():
        return env
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    env.pop("_MEIPASS2", None)
    for key in list(env.keys()):
        if key.startswith("_PYI_"):
            env.pop(key, None)
    return env


def _lock_file_path(name: str) -> Path:
    base = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    safe_name = "".join(ch if ch.isalnum() else "_" for ch in name).strip("_") or "GoPrinxAgent"
    return base / "GoPrinxAgent" / f"{safe_name}.lock"


def acquire_single_instance(name: str) -> tuple[SingleInstanceLock | None, bool]:
    if not is_windows():
        return SingleInstanceLock(name=name, handle=0), True

    lock_path = _lock_file_path(name)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    file_handle = open(lock_path, "a+b")
    try:
        file_handle.seek(0)
        file_handle.truncate(0)
        file_handle.write(f"{os.getpid()}\n".encode("utf-8"))
        file_handle.flush()
        os.fsync(file_handle.fileno())
        if msvcrt is not None:
            file_handle.seek(0)
            msvcrt.locking(file_handle.fileno(), msvcrt.LK_NBLCK, 1)
    except Exception:
        try:
            file_handle.close()
        except Exception:
            pass
        return None, False

    kernel32 = ctypes.windll.kernel32
    mutex = kernel32.CreateMutexW(None, False, name)
    if not mutex:
        try:
            if msvcrt is not None:
                file_handle.seek(0)
                msvcrt.locking(file_handle.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
        try:
            file_handle.close()
        except Exception:
            pass
        raise OSError("CreateMutexW failed")
    return SingleInstanceLock(name=name, handle=int(mutex), file_handle=file_handle, lock_path=lock_path), True


def startup_command_for_current_exe(mode: str = "web", host: str = "127.0.0.1", port: int = 9173) -> str:
    target = Path(sys.executable if is_frozen() else sys.argv[0]).resolve()
    safe_mode = str(mode or "web").strip() or "web"
    if safe_mode == "web":
        return f'"{target}" --mode web --host {host} --port {int(port)}'
    return f'"{target}" --mode {safe_mode}'


def get_machine_agent_uid(preferred: str = "") -> str:
    text = str(preferred or "").strip()
    if text and text.lower() not in {"agent-pc-01", "legacy-agent", "agent-default", "pc-01"}:
        return text
    hostname = socket.gethostname().strip().lower()
    hostname = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in hostname).strip("_")
    return hostname or "agent"


def ensure_startup_registration(app_name: str = "GoPrinxAgent", command: str | None = None) -> tuple[bool, str]:
    if not is_windows():
        return False, "Startup registration is only supported on Windows"
    if not is_frozen():
        return False, "Startup registration skipped outside frozen build"

    launch_command = (command or startup_command_for_current_exe()).strip()
    if not launch_command:
        return False, "Missing startup command"
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_READ | winreg.KEY_SET_VALUE,
        ) as key:
            current, _ = winreg.QueryValueEx(key, app_name)
            if str(current or "").strip() == launch_command:
                return True, "Startup already registered"
    except FileNotFoundError:
        pass
    except OSError:
        pass

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE,
        ) as key:
            winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, launch_command)
        return True, "Startup registered"
    except OSError as exc:
        LOGGER.warning("Failed to register startup entry: %s", exc)
        return False, str(exc)


def spawn_detached_command(command: str) -> None:
    if not command.strip():
        raise ValueError("Detached command is empty")
    creation_flags = 0
    if is_windows():
        creation_flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    subprocess.Popen(
        command,
        shell=True,
        creationflags=creation_flags,
        close_fds=True,
        cwd=str(Path.cwd()),
        env=fresh_pyinstaller_env(),
    )


def no_window_subprocess_kwargs() -> dict[str, object]:
    if not is_windows():
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return {
        "startupinfo": startupinfo,
        "creationflags": CREATE_NO_WINDOW,
    }
