"""
Deploy the current backend layout to the production VPS.

Remote layout:
  /opt/printagent/app.py
  /opt/printagent/models.py
  /opt/printagent/serializers.py
  /opt/printagent/utils.py
  /opt/printagent/templates/*
  /opt/printagent/storage/drivers/*
  /opt/printagent/storage/releases/agent_release.json
"""

from __future__ import annotations

import os
from pathlib import Path

import paramiko
from scp import SCPClient


HOSTNAME = "agentapi.quanlymay.com"
USERNAME = "root"
PASSWORD = "@baoLong0511"
REMOTE_BASE = "/opt/printagent"
ROOT_DIR = Path(__file__).resolve().parents[2]

ROOT_FILES = [
    "app.py",
    "config.py",
    "db.py",
    "google_drive_sync.py",
    "init_db.py",
    "models.py",
    "PUBLIC_API.md",
    "requirements.txt",
    "serializers.py",
    "utils.py",
    "__init__.py",
]

DIRECTORIES = [
    ("templates", "templates"),
    ("storage/drivers", "storage/drivers"),
    ("storage/releases", "storage/releases"),
]


def _print(line: str) -> None:
    print(line, flush=True)


def _connect() -> paramiko.SSHClient:
    _print(f"Connecting to {HOSTNAME}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOSTNAME, username=USERNAME, password=PASSWORD)
    _print("Connected OK")
    return ssh


def _run(ssh: paramiko.SSHClient, command: str, *, echo: bool = True) -> tuple[str, str, int]:
    stdin, stdout, stderr = ssh.exec_command(command)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    code = stdout.channel.recv_exit_status()
    if echo:
        if out:
            _print(f"  [OUT] {out}")
        if err:
            _print(f"  [ERR] {err}")
    return out, err, code


def _iter_backend_files() -> list[tuple[Path, str]]:
    backend_dir = ROOT_DIR / "backend"
    items: list[tuple[Path, str]] = []

    for name in ROOT_FILES:
        local = backend_dir / name
        if local.exists():
            items.append((local, f"{REMOTE_BASE}/{name}"))

    for local_subdir, remote_subdir in DIRECTORIES:
        source_dir = backend_dir / local_subdir
        if not source_dir.exists():
            continue
        for path in source_dir.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(source_dir).as_posix()
            items.append((path, f"{REMOTE_BASE}/{remote_subdir}/{rel}"))

    return items


def deploy() -> None:
    files = _iter_backend_files()
    if not files:
        raise RuntimeError("No backend files resolved for deployment")

    ssh = _connect()
    try:
        _print("\n[1] Ensuring remote directories...")
        for _, remote_subdir in DIRECTORIES:
            _run(ssh, f"mkdir -p {REMOTE_BASE}/{remote_subdir}")
        _run(ssh, f"mkdir -p {REMOTE_BASE}")

        _print("\n[2] Uploading backend files...")
        with SCPClient(ssh.get_transport()) as scp:
            for local, remote in files:
                size = os.path.getsize(local)
                _print(f"  >> {local.relative_to(ROOT_DIR).as_posix()} -> {remote} ({size:,} bytes)")
                scp.put(str(local), remote_path=remote)

        _print("\n[3] Installing backend requirements in remote venv...")
        _run(
            ssh,
            f"test -x {REMOTE_BASE}/venv/bin/pip && {REMOTE_BASE}/venv/bin/pip install -r {REMOTE_BASE}/requirements.txt || true",
        )

        _print("\n[4] Restarting backend service...")
        _, _, code = _run(ssh, "systemctl restart printagent")
        if code != 0:
            raise RuntimeError("Failed to restart printagent service")

        _print("\n[5] Verifying service...")
        status_out, _, _ = _run(ssh, "systemctl is-active printagent")
        if status_out.strip() != "active":
            raise RuntimeError(f"Unexpected service state: {status_out or 'unknown'}")
        _run(ssh, "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8005/api-docs || true")

        _print("\nBackend deploy completed successfully")
    finally:
        ssh.close()


if __name__ == "__main__":
    deploy()
