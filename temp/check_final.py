import paramiko

def check_final():
    hostname = "agentapi.quanlymay.com"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    commands = [
        "ls -l /opt/printagent/venv/bin/gunicorn || echo 'Gunicorn not found'",
        "sudo -u postgres psql -c \"SELECT datname FROM pg_database WHERE datname='GoPrinx';\"",
        "systemctl status printagent || echo 'Service not found'",
        "nginx -t"
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print(stdout.read().decode())
        print(stderr.read().decode())
        
    ssh.close()

if __name__ == "__main__":
    check_final()
