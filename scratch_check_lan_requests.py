import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('31.97.76.62', username='root', key_filename=r'C:\Users\nguyenbuu.DESKTOP-TOEFTR1\.ssh\id_ed25519')

import sys
sys.stdout.reconfigure(encoding='utf-8')

print("=== VPS logs for /api/lan-sites ===")
_, out, err = ssh.exec_command("journalctl -u printagent -g '/api/lan-sites' -n 50 --no-pager")
print(out.read().decode('utf-8', errors='replace'))
print(err.read().decode('utf-8', errors='replace'))

ssh.close()
