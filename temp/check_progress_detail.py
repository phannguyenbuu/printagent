import paramiko

def check_progress():
    hostname = "agentapi.quanlymay.com"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    commands = [
        "ls -d /opt/printagent/venv && echo 'Venv exists' || echo 'Venv missing'",
        "sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw GoPrinx && echo 'DB exists' || echo 'DB missing'",
        "systemctl is-active printagent || echo 'Service not active'",
        "tail -n 50 /var/log/apt/history.log | head -n 20"
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print(stdout.read().decode())
        
    ssh.close()

if __name__ == "__main__":
    check_progress()
