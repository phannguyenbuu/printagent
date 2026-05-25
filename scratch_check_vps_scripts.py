import paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('31.97.76.62', username='root', key_filename=r'C:\Users\nguyenbuu.DESKTOP-TOEFTR1\.ssh\id_ed25519')

# Print the size and md5sum of ricoh_wizard.py in static/releases on VPS
stdin, stdout, stderr = ssh.exec_command("md5sum /opt/printagent/static/releases/ricoh_wizard.py")
print("VPS Static Release HASH:", stdout.read().decode('utf-8').strip())

stdin, stdout, stderr = ssh.exec_command("wc -l /opt/printagent/static/releases/ricoh_wizard.py")
print("VPS Static Release LINES:", stdout.read().decode('utf-8').strip())

# Also read lines 190 to 215 from VPS static/releases/ricoh_wizard.py
stdin, stdout, stderr = ssh.exec_command("sed -n '190,215p' /opt/printagent/static/releases/ricoh_wizard.py")
print("VPS ricoh_wizard.py credentials lookup snippet:")
print(stdout.read().decode('utf-8'))

ssh.close()
