import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('31.97.76.62', username='root', key_filename=r'C:\Users\nguyenbuu.DESKTOP-TOEFTR1\.ssh\id_ed25519')

# View printagent service logs
stdin, stdout, stderr = ssh.exec_command("journalctl -u printagent -n 300 --no-pager | grep -E 'reconcile|fetch_address_book|kythuat02|emails'")
print("STDOUT:")
print(stdout.read().decode('utf-8', errors='replace'))
print("STDERR:")
print(stderr.read().decode('utf-8', errors='replace'))

ssh.close()
