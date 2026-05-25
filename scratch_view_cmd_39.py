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
cur.execute('SELECT * FROM "PrinterControlCommand" WHERE id = 39')
col_names = [desc[0] for desc in cur.description]
row = cur.fetchone()
if row:
    res = dict(zip(col_names, row))
    # We don't want to print the entire address book if it's huge, but it's small here
    print(json.dumps(res, default=str, indent=2))
else:
    print("Command 39 not found")
conn.close()
"""

sftp = ssh.open_sftp()
temp_remote_file = "/tmp/check_cmd_39.py"
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
