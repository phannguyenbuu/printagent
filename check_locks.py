import paramiko

def check_locks():
    hostname = "agentapi.quanlymay.com"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    commands = [
        "ps aux | head -n 50",
        "ps aux | grep -i apt",
        "ps aux | grep -i dpkg",
        "fuser /var/lib/dpkg/lock-frontend || echo 'No lock'",
        "cat /tmp/remote_setup_log.txt || echo 'No log yet'" # I didn't create this log, but maybe it exists?
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print(stdout.read().decode())
        
    ssh.close()

if __name__ == "__main__":
    check_locks()
