import paramiko

def list_accounts():
    hostname = "31.97.76.62"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    cmd = "ls -R /etc/letsencrypt/accounts"
    print(f"Executing: {cmd}")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    
    output = stdout.read().decode('utf-8', errors='ignore')
    print("Output:")
    print(output)
    
    ssh.close()

if __name__ == "__main__":
    list_accounts()
