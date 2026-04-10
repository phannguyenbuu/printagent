"""
Deploy driver catalog JSON + updated templates + app.py to VPS.
Files to deploy:
  - backend/storage/drivers/ricoh.json    → /opt/printagent/storage/drivers/
  - backend/storage/drivers/toshiba.json  → /opt/printagent/storage/drivers/
  - backend/storage/drivers/fujifilm.json → /opt/printagent/storage/drivers/
  - backend/templates/drivers.html        → /opt/printagent/templates/
  - backend/app.py                        → /opt/printagent/app.py
"""
import paramiko
import os
import sys
from scp import SCPClient

HOSTNAME = "agentapi.quanlymay.com"
USERNAME = "root"
PASSWORD = "@baoLong0511"
REMOTE_BASE = "/opt/printagent"

FILES = [
    # (local_path, remote_path)
    ("backend/storage/drivers/ricoh.json",    f"{REMOTE_BASE}/storage/drivers/ricoh.json"),
    ("backend/storage/drivers/toshiba.json",  f"{REMOTE_BASE}/storage/drivers/toshiba.json"),
    ("backend/storage/drivers/fujifilm.json", f"{REMOTE_BASE}/storage/drivers/fujifilm.json"),
    ("backend/templates/drivers.html",        f"{REMOTE_BASE}/templates/drivers.html"),
    ("backend/app.py",                        f"{REMOTE_BASE}/app.py"),
]

def deploy():
    print(f"Connecting to {HOSTNAME}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOSTNAME, username=USERNAME, password=PASSWORD)

    # Ensure remote dirs exist
    print("Creating remote directories...")
    ssh.exec_command(f"mkdir -p {REMOTE_BASE}/storage/drivers")

    print("Uploading files...")
    with SCPClient(ssh.get_transport()) as scp:
        for local, remote in FILES:
            if not os.path.exists(local):
                print(f"  ⚠ SKIP (not found): {local}")
                continue
            size = os.path.getsize(local)
            print(f"  >> {local} -> {remote} ({size:,} bytes)")
            scp.put(local, remote_path=remote)

    print("\nRestarting service...")
    stdin, stdout, stderr = ssh.exec_command("systemctl restart printagent 2>&1 || pm2 restart printagent-server 2>&1")
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out: print("  OUT:", out)
    if err: print("  ERR:", err)

    print("\nChecking service status...")
    _, status_out, _ = ssh.exec_command("systemctl is-active printagent 2>/dev/null || pm2 list 2>/dev/null | grep printagent | head -1")
    print(" ", status_out.read().decode().strip())

    ssh.close()
    print("\n✅ Deploy finished!")

if __name__ == "__main__":
    deploy()
