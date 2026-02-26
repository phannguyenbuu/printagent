import paramiko

def run_setup():
    hostname = "31.97.76.62"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    # Run setup with non-interactive flag
    cmd = "export DEBIAN_FRONTEND=noninteractive; bash /tmp/remote_setup.sh"
    print(f"Executing: {cmd}")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    
    # Use a loop to read output as it comes
    while not stdout.channel.exit_status_ready():
        if stdout.channel.recv_ready():
            print(stdout.channel.recv(1024).decode(), end="")
        if stdout.channel.recv_stderr_ready():
            print(f"[ERR] {stdout.channel.recv_stderr(1024).decode()}", end="")
            
    print(stdout.read().decode())
    print(stderr.read().decode())
    
    ssh.close()

if __name__ == "__main__":
    run_setup()
