import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('31.97.76.62', username='root', key_filename=r'C:\Users\nguyenbuu.DESKTOP-TOEFTR1\.ssh\id_ed25519')

# Get detailed journalctl logs for printagent
stdin, stdout, stderr = ssh.exec_command("journalctl -u printagent -n 10000 --no-pager")
log_content = stdout.read().decode('utf-8', errors='replace')

print("Filtering logs...")
lines = log_content.splitlines()
matched = []
for line in lines:
    if "kythuat02" in line or "fetch_address" in line or "reconcile" in line or "email" in line or "39" in line:
        matched.append(line)

print("Found", len(matched), "matched log lines:")
for m in matched[-150:]:
    print(m)

ssh.close()
