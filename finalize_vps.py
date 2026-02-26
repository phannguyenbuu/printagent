import paramiko

def finalize():
    hostname = "31.97.76.62"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    # Finalize systemd service
    service_content = """[Unit]
Description=PrintAgent Central Server
After=network.target postgresql.service

[Service]
User=root
WorkingDirectory=/opt/printagent
Environment="DATABASE_URL=postgresql+psycopg2://postgres:myPass@localhost:5432/GoPrinx"
Environment="LEAD_KEYS=default:change-me"
ExecStart=/usr/bin/python3 /opt/printagent/app.py
Restart=always

[Install]
WantedBy=multi-user.target
"""
    
    # Create service file directly via SSH
    cmd_service = f"cat <<EOF > /etc/systemd/system/printagent.service\n{service_content}\nEOF"
    ssh.exec_command(cmd_service)
    
    commands = [
        "systemctl daemon-reload",
        "systemctl enable printagent",
        "pkill -f 'python3 /opt/printagent/app.py' || true",
        "systemctl start printagent",
        "systemctl status printagent --no-pager",
        "nginx -t",
        "systemctl reload nginx"
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print(stdout.read().decode('utf-8', errors='ignore'))
        
    ssh.close()

if __name__ == "__main__":
    finalize()
