import paramiko

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
cursor = conn.cursor()
cursor.execute('SELECT address_book_sync FROM "Printer" WHERE id = 48')
row = cursor.fetchone()
if row and row[0]:
    print("Address Book Sync Status in DB:")
    print(json.dumps(row[0], indent=2, ensure_ascii=False))
else:
    print("No sync status or printer found")
conn.close()
"""

sftp = ssh.open_sftp()
temp_remote_file = "/tmp/check_sync_temp.py"
with sftp.file(temp_remote_file, "w") as f:
    f.write(python_code)
sftp.close()

stdin, stdout, stderr = ssh.exec_command(f"/opt/printagent/venv/bin/python3 {temp_remote_file}")
print("STDOUT:")
print(stdout.read().decode('utf-8', errors='replace'))
print("STDERR:")
print(stderr.read().decode('utf-8', errors='replace'))

ssh.exec_command(f"rm -f {temp_remote_file}")
ssh.close()
