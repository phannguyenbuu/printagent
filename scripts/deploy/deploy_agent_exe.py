"""
Deploy printagent.exe and its release manifest to VPS.
- Removes old .exe files in /opt/printagent/static/releases/
- Uploads new printagent.exe as printagent.exe
- Uploads backend/storage/releases/agent_release.json
"""
import hashlib
import json
import paramiko
from scp import SCPClient
from pathlib import Path

HOSTNAME = "agentapi.quanlymay.com"
USERNAME = "root"
PASSWORD = "@baoLong0511"
REMOTE_DIR = "/opt/printagent/static/releases"
REMOTE_MANIFEST = "/opt/printagent/storage/releases/agent_release.json"
ROOT_DIR = Path(__file__).resolve().parents[2]
LOCAL_EXE = ROOT_DIR / "dist" / "printagent.exe"
LOCAL_MANIFEST = ROOT_DIR / "backend" / "storage" / "releases" / "agent_release.json"
REMOTE_EXE = f"{REMOTE_DIR}/printagent.exe"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _prepare_local_manifest() -> None:
    if not LOCAL_EXE.exists():
        raise FileNotFoundError(f"Missing exe: {LOCAL_EXE}")
    payload: dict[str, object] = {}
    if LOCAL_MANIFEST.exists():
        try:
            loaded = json.loads(LOCAL_MANIFEST.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = loaded
        except Exception:
            payload = {}
    payload["version"] = str(payload.get("version") or "1.3.31")
    payload["download_url"] = str(payload.get("download_url") or "/static/releases/printagent.exe")
    payload["published_at"] = str(payload.get("published_at") or "2026-03-26T00:00:00+07:00")
    payload["mandatory"] = bool(payload.get("mandatory", False))
    payload["channel"] = str(payload.get("channel") or "stable")
    payload["notes"] = str(payload.get("notes") or "")
    payload["sha256"] = _sha256_file(LOCAL_EXE)
    payload["size"] = int(LOCAL_EXE.stat().st_size)
    LOCAL_MANIFEST.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run(ssh, cmd, echo=True):
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if echo:
        if out:
            print(f"  [OUT] {out}")
        if err:
            print(f"  [ERR] {err}")
    return out, err


def main():
    _prepare_local_manifest()
    print(f"Connecting to {HOSTNAME}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOSTNAME, username=USERNAME, password=PASSWORD)
    print("Connected OK")

    print(f"\n[1] Current EXE files in {REMOTE_DIR}:")
    run(ssh, f"ls -lh {REMOTE_DIR}/*.exe 2>/dev/null || echo '  (no .exe found)'")

    print(f"\n[2] Removing all old .exe files...")
    run(ssh, f"rm -f {REMOTE_DIR}/*.exe")
    run(ssh, f"ls {REMOTE_DIR}/ | head -20")

    print(f"\n[3] Uploading {LOCAL_EXE} -> {REMOTE_EXE} ...")
    with SCPClient(ssh.get_transport(), progress=_progress) as scp:
        scp.put(str(LOCAL_EXE), remote_path=REMOTE_EXE)
    print("\n  Upload complete OK")

    print(f"\n[4] Uploading manifest {LOCAL_MANIFEST} -> {REMOTE_MANIFEST} ...")
    with SCPClient(ssh.get_transport(), progress=_progress) as scp:
        scp.put(str(LOCAL_MANIFEST), remote_path=REMOTE_MANIFEST)
    print("\n  Manifest upload complete OK")

    print(f"\n[5] Fixing permissions...")
    run(ssh, f"chmod 755 {REMOTE_EXE}")
    run(ssh, f"chown www-data:www-data {REMOTE_EXE} 2>/dev/null || true")
    run(ssh, f"chmod 644 {REMOTE_MANIFEST}")
    run(ssh, f"chown www-data:www-data {REMOTE_MANIFEST} 2>/dev/null || true")

    print(f"\n[6] Verify:")
    run(ssh, f"ls -lh {REMOTE_DIR}/*.exe")
    out, _ = run(ssh, f"python3 -c \"import json; p='{REMOTE_MANIFEST}'; m=json.load(open(p, encoding='utf-8-sig')); print(m.get('version',''), m.get('channel',''))\"")
    print(f"  Release: {out}")
    out, _ = run(ssh, f"md5sum {REMOTE_EXE}", echo=False)
    print(f"  MD5: {out}")

    ssh.close()
    print("\nDone! Agent EXE deployed successfully OK")


_last_pct = -1

def _progress(filename, size, sent):
    global _last_pct
    pct = int(sent * 100 / size) if size else 0
    if pct != _last_pct and pct % 10 == 0:
        mb_sent = sent / 1024 / 1024
        mb_total = size / 1024 / 1024
        print(f"  {pct}%  {mb_sent:.1f}/{mb_total:.1f} MB", flush=True)
        _last_pct = pct


if __name__ == "__main__":
    main()
