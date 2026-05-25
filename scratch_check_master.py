import paramiko
import json

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('31.97.76.62', username='root', key_filename=r'C:\Users\nguyenbuu.DESKTOP-TOEFTR1\.ssh\id_ed25519')

python_code = """
import psycopg2
import os
import json
from pathlib import Path
from dotenv import load_dotenv

env_path = Path("/opt/printagent/.env")
if env_path.exists():
    load_dotenv(env_path)
db_url = os.getenv("DATABASE_URL", "postgresql://postgres:myPass@localhost:5432/GoPrinx")
if db_url.startswith("postgresql+psycopg2://"):
    db_url = db_url.replace("postgresql+psycopg2://", "postgresql://")

conn = psycopg2.connect(db_url)
cur = conn.cursor()
cur.execute('SELECT id, agent_uid, hostname, local_ip, last_seen_at FROM "AgentNode" WHERE lan_uid = \\'default_84_93_B2_7C_EE_78_192_168_1_1\\' ORDER BY id ASC')
col_names = [desc[0] for desc in cur.description]
rows = cur.fetchall()
print("Found", len(rows), "agents on this LAN:")
for r in rows:
    res = dict(zip(col_names, r))
    print(json.dumps(res, default=str, indent=2))
conn.close()
"""

sftp = ssh.open_sftp()
temp_remote_file = "/tmp/check_master.py"
with sftp.file(temp_remote_file, "w") as f:
    f.write(python_code)
sftp.close()

stdin, stdout, stderr = ssh.exec_command(f"/opt/printagent/venv/bin/python3 {temp_remote_file}")
print("STDOUT:")
print(stdout.read().decode('utf-8'))
print("STDERR:")
print(stderr.read().decode('utf-8'))

ssh.exec_command(f"rm -f {temp_remote_file}")
ssh.close()
