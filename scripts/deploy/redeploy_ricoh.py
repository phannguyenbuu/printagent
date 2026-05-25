import paramiko, os
from scp import SCPClient

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('agentapi.quanlymay.com', username='root', password='@baoLong0511')

# Check current server file keys
_, out, _ = ssh.exec_command(
    'python3 -c \'import json; f=open("/opt/printagent/storage/drivers/ricoh.json"); d=json.load(f); print(list(d[0].keys()))\''
)
print('VPS current keys:', out.read().decode().strip())

# Upload correct file
with SCPClient(ssh.get_transport()) as scp:
    size = os.path.getsize('backend/storage/drivers/ricoh.json')
    scp.put('backend/storage/drivers/ricoh.json',
            remote_path='/opt/printagent/storage/drivers/ricoh.json')
    print(f'Uploaded ricoh.json ({size:,} bytes)')

# Restart to clear in-memory cache
ssh.exec_command('systemctl restart printagent')
print('Restarted service (cache cleared)')

# Verify new keys
import time; time.sleep(3)
_, out2, _ = ssh.exec_command(
    'python3 -c \'import json; f=open("/opt/printagent/storage/drivers/ricoh.json"); d=json.load(f); print("Keys:", list(d[0].keys())); print("Driver names:", list(d[0].get("drivers",{}).keys())[:3])\''
)
print('VPS new file:', out2.read().decode().strip())
ssh.close()
print('Done.')
