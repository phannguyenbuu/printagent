import paramiko

def force_check():
    hostname = "31.97.76.62"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    # Check if we can just start the service manually if setup failed halfway
    commands = [
        "ls -d /opt/printagent/venv || (cd /opt/printagent && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt gunicorn psycopg2-binary)",
        "systemctl daemon-reload",
        "systemctl restart printagent",
        "systemctl status printagent --no-pager"
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print(stdout.read().decode())
        print(stderr.read().decode())
        
    ssh.close()

if __name__ == "__main__":
    force_check()
