import paramiko

def check_vps():
    hostname = "agentapi.quanlymay.com"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    commands = [
        "ps aux | grep apt",
        "systemctl status printagent || echo 'Service not found'",
        "tail -n 20 /var/log/syslog | grep printagent || echo 'No logs yet'",
        "ls -R /opt/printagent || echo 'Dir not ready'"
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print(stdout.read().decode())
        
    ssh.close()

if __name__ == "__main__":
    check_vps()
