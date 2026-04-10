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
    
    print("Uploading updated files...")
    with SCPClient(ssh.get_transport()) as scp:
        # Static releases
        try:
            ssh.exec_command("mkdir -p /opt/printagent/static/releases")
            scp.put("dist/GoPrinxAgent.exe", remote_path="/opt/printagent/static/releases/GoPrinxAgent.exe")
            scp.put("agent/icon.ico", remote_path="/opt/printagent/static/releases/icon.ico")
        except Exception as e:
            print(f"Release upload failed: {e}")

        # Core files
        scp.put("server/models.py", remote_path="/opt/printagent/models.py")
        scp.put("server/app.py", remote_path="/opt/printagent/app.py")
        scp.put("server/utils.py", remote_path="/opt/printagent/utils.py")
        scp.put("server/serializers.py", remote_path="/opt/printagent/serializers.py")
        scp.put("server/PUBLIC_API.md", remote_path="/opt/printagent/PUBLIC_API.md")
        
        # All Templates
        templates = [
            "base.html", "_app_scripts.html", "_app_styles.html", "api_docs.html",
            "lan_sites.html", "workspaces.html", "locations.html", "materials.html",
            "repairs.html", "users.html", "networks.html", "leads.html",
            "downloads.html", "tasks.html", "drivers.html"
        ]
        for t in templates:
            scp.put(f"server/templates/{t}", remote_path=f"/opt/printagent/templates/{t}")
        
        # Seeding script
        scp.put("seed_mock_data.py", remote_path="/opt/printagent/seed_mock_data.py")
    
    print("Executing database updates and seeding...")
    commands = [
        "cd /opt/printagent && venv/bin/python3 init_db.py",
        "cd /opt/printagent && venv/bin/python3 seed_mock_data.py",
        "pm2 restart printagent-server"
    ]
    
    for cmd in commands:
        print(f"Running: {cmd}")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode()
        err = stderr.read().decode()
        if out: print(f"OUT: {out}")
        if err: print(f"ERR: {err}")
        
    ssh.close()
    print("Deployment finished successfully!")

if __name__ == "__main__":
    deploy()
