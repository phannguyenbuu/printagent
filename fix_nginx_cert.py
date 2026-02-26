import paramiko

def fix_nginx_and_install_cert():
    hostname = "31.97.76.62"
    username = "root"
    password = "@baoLong0511"
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    # Rename to .conf
    commands = [
        "mv /etc/nginx/sites-available/agentapi.quanlymay.com /etc/nginx/sites-available/agentapi.quanlymay.com.conf",
        "ln -sf /etc/nginx/sites-available/agentapi.quanlymay.com.conf /etc/nginx/sites-enabled/agentapi.quanlymay.com.conf",
        "rm -f /etc/nginx/sites-enabled/agentapi.quanlymay.com",
        "nginx -t",
        "systemctl reload nginx",
        "certbot install --nginx --cert-name agentapi.quanlymay.com --non-interactive"
    ]
    
    for cmd in commands:
        print(f"--- {cmd} ---")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        print(stdout.read().decode('utf-8', errors='ignore'))
        print(stderr.read().decode('utf-8', errors='ignore'))
        
    ssh.close()

if __name__ == "__main__":
    fix_nginx_and_install_cert()
