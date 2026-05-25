import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('31.97.76.62', username='root', key_filename=r'C:\Users\nguyenbuu.DESKTOP-TOEFTR1\.ssh\id_ed25519')

python_code = """
import psycopg2
import os
from pathlib import Path
from dotenv import load_dotenv

env_path = Path("/opt/printagent/.env")
if env_path.exists():
    load_dotenv(env_path)
db_url = os.getenv("DATABASE_URL", "postgresql://postgres:myPass@localhost:5432/GoPrinx")
if db_url.startswith("postgresql+psycopg2://"):
    db_url = db_url.replace("postgresql+psycopg2://", "postgresql://")

import subprocess
# Run curl to fetch controls list on VPS
cmd = "curl -s -H 'X-Lead-Token: change-me' 'http://localhost:8005/api/polling/controls?lead=default&lan_uid=default_84_93_B2_7C_EE_78_192_168_1_1&agent_uid=kythuat02'"
print("Fetching controls list on VPS:")
res = subprocess.check_output(cmd, shell=True).decode('utf-8')
print(res)
# Let's run it using psycopg2 to see the exact row in PrinterControlCommand too
import psycopg2
conn = psycopg2.connect(db_url)
cursor = conn.cursor()
cursor.execute('SELECT id, printer_id, command_type, status, error_message, lead, lan_uid, agent_uid FROM "PrinterControlCommand" WHERE id = 37')
row = cursor.fetchone()
print("PrinterControlCommand row 37 in DB:", row)
conn.close()

"""

sftp = ssh.open_sftp()
temp_remote_file = "/tmp/check_command_temp.py"
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
