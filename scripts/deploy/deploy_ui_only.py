import paramiko
import os
from scp import SCPClient

def deploy():
    hostname = "agentapi.quanlymay.com"
    username = "root"
    password = "@baoLong0511"
    
    print(f"Connecting to {hostname}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    print("Uploading updated templates...")
    with SCPClient(ssh.get_transport()) as scp:
        scp.put("backend/templates/devices.html", remote_path="/opt/printagent/templates/devices.html")
    
    print("Restarting pm2...")
    ssh.exec_command("pm2 restart printagent-server")
    
    ssh.close()
    print("UI Deployment finished successfully!")

if __name__ == "__main__":
    deploy()
