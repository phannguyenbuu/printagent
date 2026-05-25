import paramiko
import os
from pathlib import Path

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('31.97.76.62', username='root', key_filename=r'C:\Users\nguyenbuu.DESKTOP-TOEFTR1\.ssh\id_ed25519')

sftp = ssh.open_sftp()

local_backend = Path(r"d:\Dropbox\_Documents\Goxprint\printagent_v2\backend")
remote_backend = "/opt/printagent"

# Upload all .py files in backend
for py_file in local_backend.glob("*.py"):
    remote_path = f"{remote_backend}/{py_file.name}"
    print(f"Uploading {py_file} to {remote_path}...")
    sftp.put(str(py_file), remote_path)

# HTML templates
for html_file in local_backend.glob("templates/*.html"):
    remote_path = f"{remote_backend}/templates/{html_file.name}"
    print(f"Uploading {html_file} to {remote_path}...")
    sftp.put(str(html_file), remote_path)

# Static and Storage releases
import shutil
local_exe = Path(r'd:\Dropbox\_Documents\Goxprint\printagent_v2\dist\printagent.exe')
dest_exe = Path(r'd:\Dropbox\_Documents\Goxprint\printagent_v2\backend\static\releases\printagent.exe')
if local_exe.exists():
    print(f"Copying {local_exe} to {dest_exe}...")
    dest_exe.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(local_exe), str(dest_exe))

files_to_copy = [
    (r'd:\Dropbox\_Documents\Goxprint\printagent_v2\backend\static\releases\scan_ricoh.py', '/opt/printagent/static/releases/scan_ricoh.py'),
    (r'd:\Dropbox\_Documents\Goxprint\printagent_v2\backend\static\releases\ricoh_address_book.py', '/opt/printagent/static/releases/ricoh_address_book.py'),
    (r'd:\Dropbox\_Documents\Goxprint\printagent_v2\backend\static\releases\ricoh_wizard.py', '/opt/printagent/static/releases/ricoh_wizard.py'),
    (r'd:\Dropbox\_Documents\Goxprint\printagent_v2\backend\static\releases\ricoh_web_scan.py', '/opt/printagent/static/releases/ricoh_web_scan.py'),
    (r'd:\Dropbox\_Documents\Goxprint\printagent_v2\backend\storage\releases\agent_release.json', '/opt/printagent/storage/releases/agent_release.json'),
    (r'd:\Dropbox\_Documents\Goxprint\printagent_v2\backend\storage\releases\agent_core_release.json', '/opt/printagent/storage/releases/agent_core_release.json'),
    (r'd:\Dropbox\_Documents\Goxprint\printagent_v2\backend\static\releases\agent_core.zip', '/opt/printagent/static/releases/agent_core.zip'),
    (r'd:\Dropbox\_Documents\Goxprint\printagent_v2\backend\static\releases\printagent.exe', '/opt/printagent/static/releases/printagent.exe')
]

for local_file, remote_file in files_to_copy:
    if os.path.exists(local_file):
        print(f"Uploading {local_file} to {remote_file}...")
        sftp.put(local_file, remote_file)

sftp.close()

print("Restarting printagent service on remote VPS...")
_, out, err = ssh.exec_command('systemctl restart printagent.service || systemctl restart printagent')
print("Restart STDOUT:", out.read().decode('utf-8'))
print("Restart STDERR:", err.read().decode('utf-8'))

ssh.close()
print("Done!")
