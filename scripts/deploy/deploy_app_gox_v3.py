import paramiko
import os
from scp import SCPClient

def progress(filename, size, sent):
    print(f"\rUploading {filename}: {float(sent)/float(size)*100:.2f}%", end="")

def deploy():
    hostname = "agentapi.quanlymay.com"
    username = "root"
    password = "@baoLong0511"
    
    local_dist_path = "app-gox/dist"
    remote_path = "/var/www/app-gox"
    
    print(f"Connecting to {hostname}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    # Ensure remote directory exists and is clean
    print(f"Cleaning remote directory: {remote_path}")
    ssh.exec_command(f"mkdir -p {remote_path} && rm -rf {remote_path}/*")
    
    print("Uploading build files...")
    with SCPClient(ssh.get_transport(), progress=progress) as scp:
        for item in os.listdir(local_dist_path):
            local_item = os.path.join(local_dist_path, item)
            if os.path.isdir(local_item):
                scp.put(local_item, recursive=True, remote_path=remote_path)
            else:
                scp.put(local_item, remote_path=remote_path)
    
    print("\nSetting permissions...")
    ssh.exec_command(f"chown -R www-data:www-data {remote_path}")
    
    print("Reloading Nginx...")
    ssh.exec_command("systemctl reload nginx")
    
    ssh.close()
    print("Frontend deployment finished successfully!")

if __name__ == "__main__":
    deploy()
