import paramiko
import sys

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('31.97.76.62', username='root', key_filename=r'C:\Users\nguyenbuu.DESKTOP-TOEFTR1\.ssh\id_ed25519')

# View .env file on VPS to get the real port and token
stdin, stdout, stderr = ssh.exec_command("cat /opt/printagent/.env")
env_content = stdout.read().decode('utf-8')
print("VPS .env Content:\n", env_content)

# Parse lead and token from env_content or fallback to default
token = "change-me"
port = "8005"
for line in env_content.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    if "LEAD_KEYS" in line:
        # e.g. LEAD_KEYS="default:gox918721" or LEAD_KEYS=default:gox918721
        val = line.split("=", 1)[1].strip().strip('"').strip("'")
        if ":" in val:
            token = val.split(":", 1)[1]
    if "SERVER_PORT" in line:
        port = line.split("=", 1)[1].strip().strip('"').strip("'")

print(f"Using Token: {token}, Port: {port}")

# Trigger rescan / fetch-address-book command
# We use curl with X-Lead-Token or X-API-Token header
cmd = f"curl -s -X POST -H 'Content-Type: application/json' -H 'X-Lead-Token: {token}' http://localhost:{port}/api/devices/48/fetch-address-book"
print(f"Running on VPS: {cmd}")
stdin, stdout, stderr = ssh.exec_command(cmd)
print("Curl STDOUT:", stdout.read().decode('utf-8'))
print("Curl STDERR:", stderr.read().decode('utf-8'))

ssh.close()
