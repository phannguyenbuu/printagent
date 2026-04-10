import paramiko

def check_markers():
    hostname = "agentapi.quanlymay.com"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    commands = [
        "ls /etc/nginx/sites-enabled/agentapi.quanlymay.com || echo 'Nginx config missing'",
        "ls /etc/systemd/system/printagent.service || echo 'Service file missing'",
        "cat /etc/systemd/system/printagent.service || echo 'No service content'",
        "sudo -u postgres psql -c \"\\l\" | grep GoPrinx || echo 'DB missing'"
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print(stdout.read().decode())
        
    ssh.close()

if __name__ == "__main__":
    check_markers()
