import paramiko
import sys

def safe_check():
    hostname = "31.97.76.62"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    commands = [
        "systemctl is-active printagent",
        "systemctl status printagent --no-pager",
        "curl -I http://localhost:8005/health"
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        # Use utf-8 explicitly for reading
        print(stdout.read().decode('utf-8', errors='ignore'))
        print(stderr.read().decode('utf-8', errors='ignore'))
        
    ssh.close()

if __name__ == "__main__":
    safe_check()
