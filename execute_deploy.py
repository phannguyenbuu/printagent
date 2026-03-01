import paramiko
import os
import sys
from scp import SCPClient

def progress(filename, size, sent):
    sys.stdout.write(f"\rUploading {filename}: {float(sent)/float(size)*100:.2f}%")
    sys.stdout.flush()

def deploy():
    hostname = "agentapi.quanlymay.com"
    username = "root"
    password = "@baoLong0511"
    
    print(f"Connecting to {hostname}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    print("Uploading files...")
    with SCPClient(ssh.get_transport(), progress=progress) as scp:
        # Upload server directory
        scp.put("server", recursive=True, remote_path="/tmp/")
        # Upload nginx config
        scp.put("nginx/sites-available/agentapi.quanlymay.com", remote_path="/tmp/")
        # Upload remote setup script
        scp.put("remote_setup.sh", remote_path="/tmp/")
    
    print("\nExecuting remote setup...")
    print("This may take a few minutes as it installs dependencies.")
    
    # Move files and run setup
    commands = [
        "mv /tmp/server /opt/printagent",
        "chmod +x /tmp/remote_setup.sh",
        "bash /tmp/remote_setup.sh"
    ]
    
    for cmd in commands:
        print(f"Running: {cmd}")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        
        # Read output in real-time
        for line in stdout:
            print(f"  [OUT] {line.strip()}")
        for line in stderr:
            print(f"  [ERR] {line.strip()}")
            
    ssh.close()
    print("Deployment finished successfully!")

if __name__ == "__main__":
    deploy()
