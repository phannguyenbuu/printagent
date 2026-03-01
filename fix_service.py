import paramiko

def fix_service():
    hostname = "agentapi.quanlymay.com"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    # Update service content to use venv python
    service_content = """[Unit]
Description=PrintAgent Central Server
After=network.target postgresql.service

[Service]
User=root
WorkingDirectory=/opt/printagent
Environment="DATABASE_URL=postgresql+psycopg2://postgres:myPass@localhost:5432/GoPrinx"
Environment="LEAD_KEYS=default:change-me"
ExecStart=/opt/printagent/venv/bin/python3 /opt/printagent/app.py
Restart=always

[Install]
WantedBy=multi-user.target
"""
    
    cmd_service = f"cat <<EOF > /etc/systemd/system/printagent.service\n{service_content}\nEOF"
    ssh.exec_command(cmd_service)
    
    commands = [
        "systemctl daemon-reload",
        "systemctl restart printagent",
        "sleep 2",
        "systemctl is-active printagent",
        "curl -s http://localhost:8005/health"
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print(stdout.read().decode('utf-8', errors='ignore'))
        
    ssh.close()

if __name__ == "__main__":
    fix_service()
