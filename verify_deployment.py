import paramiko

def verify_all():
    hostname = "31.97.76.62"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    commands = [
        "systemctl is-active printagent",
        "systemctl is-active nginx",
        "curl -s http://localhost:8005/health",
        "head -n 20 /opt/printagent/app.py"
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print(stdout.read().decode('utf-8', errors='ignore'))
        
    ssh.close()

if __name__ == "__main__":
    verify_all()
